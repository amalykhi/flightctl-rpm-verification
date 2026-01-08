#!/bin/bash

################################################################################
# Keycloak OIDC Setup Script for FlightCtl
#
# This script deploys Keycloak and configures it with OIDC realm, client,
# and test users as defined in verification.conf
#
# Usage:
#   ./setup_keycloak_oidc.sh [CONFIG_FILE] [VM_IP]
#
# Examples:
#   ./setup_keycloak_oidc.sh                              # Use default config
#   ./setup_keycloak_oidc.sh verification.conf           # Use specific config
#   ./setup_keycloak_oidc.sh 192.168.122.219             # Legacy: VM IP only
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load configuration
CONFIG_FILE="${1:-${SCRIPT_DIR}/verification.conf}"

# Check for legacy mode (VM_IP as first arg)
if [ $# -eq 1 ] && [[ "${1}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # Legacy mode: first arg is VM_IP
    VM_IP="${1}"
    CONFIG_FILE="${SCRIPT_DIR}/verification.conf"
elif [ $# -eq 2 ]; then
    # Config file + VM IP override
    VM_IP="${2}"
fi

# Load configuration file
if [ ! -f "${CONFIG_FILE}" ]; then
    echo -e "${RED}[ERROR]${NC} Configuration file not found: ${CONFIG_FILE}"
    echo "Please create verification.conf or specify a config file."
    exit 1
fi

echo -e "${BLUE}[INFO]${NC} Loading configuration from: ${CONFIG_FILE}"
source "${CONFIG_FILE}"

# Use config values (can be overridden by command line)
REALM_NAME="${OIDC_REALM}"
CLIENT_ID="${OIDC_CLIENT_ID}"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get VM IP if not already set
if [ -z "${VM_IP}" ]; then
    log_info "Resolving VM IP address for ${VM_NAME}..."
    VM_IP=$(sudo virsh domifaddr "${VM_NAME}" 2>/dev/null | grep ipv4 | awk '{print $4}' | cut -d/ -f1)
    
    if [ -z "${VM_IP}" ]; then
        log_error "Failed to get VM IP address for ${VM_NAME}"
        log_error "Make sure the VM is running: sudo virsh start ${VM_NAME}"
        exit 1
    fi
    log_success "VM IP: ${VM_IP}"
fi

ssh_exec() {
    sshpass -p "${VM_PASSWORD}" ssh -o StrictHostKeyChecking=no "${VM_USER}@${VM_IP}" "$@"
}

ssh_exec_sudo() {
    sshpass -p "${VM_PASSWORD}" ssh -o StrictHostKeyChecking=no "${VM_USER}@${VM_IP}" "echo '${VM_PASSWORD}' | sudo -S $@"
}

log_info "========================================="
log_info "Keycloak OIDC Setup for FlightCtl"
log_info "========================================="
log_info "VM: ${VM_IP}"
log_info "Realm: ${REALM_NAME}"
log_info "Client: ${CLIENT_ID}"
echo ""

# Step 1: Deploy Keycloak container
log_info "Deploying Keycloak container..."
ssh_exec_sudo "podman run -d --name keycloak \
  --restart always \
  -p ${KEYCLOAK_PORT}:8080 \
  -p ${KEYCLOAK_HEALTH_PORT}:9000 \
  -e KEYCLOAK_ADMIN=${KEYCLOAK_ADMIN} \
  -e KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD} \
  -e KC_HEALTH_ENABLED=true \
  quay.io/keycloak/keycloak:latest \
  start-dev" 2>&1 || {
    log_info "Keycloak container may already exist, checking status..."
    if ssh_exec_sudo "podman ps -a | grep keycloak | grep -q Exited"; then
        log_info "Starting existing Keycloak container..."
        ssh_exec_sudo "podman start keycloak"
    elif ssh_exec_sudo "podman ps | grep -q keycloak"; then
        log_info "Keycloak is already running"
    else
        log_error "Failed to start Keycloak"
        exit 1
    fi
}

# Step 2: Open firewall ports for Keycloak and FlightCtl
log_info "Configuring firewall ports..."
if ssh_exec "sudo firewall-cmd --state 2>/dev/null" | grep -q "running"; then
    log_info "Opening ports: 8080 (Keycloak), 443 (UI), 3443 (API)..."
    ssh_exec_sudo "firewall-cmd --permanent --add-port=8080/tcp --add-port=443/tcp --add-port=3443/tcp" > /dev/null 2>&1
    ssh_exec_sudo "firewall-cmd --reload" > /dev/null 2>&1
    log_success "Firewall ports opened"
else
    log_info "Firewall not running, skipping port configuration"
fi

log_info "Waiting for Keycloak to be ready (this may take 30-60 seconds)..."
for i in {1..60}; do
    if ssh_exec "curl -s http://localhost:${KEYCLOAK_HEALTH_PORT}/health/ready 2>/dev/null | grep -q '\"status\":\ \"UP\"'"; then
        log_success "Keycloak is ready!"
        break
    fi
    if [ $i -eq 60 ]; then
        log_error "Keycloak did not become ready in time"
        exit 1
    fi
    sleep 2
    echo -n "."
done
echo ""

# Step 3: Get admin token
log_info "Authenticating with Keycloak admin..."
ADMIN_TOKEN=$(ssh_exec "curl -s -X POST 'http://localhost:${KEYCLOAK_PORT}/realms/master/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=${KEYCLOAK_ADMIN}' \
  -d 'password=${KEYCLOAK_ADMIN_PASSWORD}' \
  -d 'grant_type=password' \
  -d 'client_id=admin-cli' | jq -r '.access_token'")

if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    log_error "Failed to get admin token"
    exit 1
fi
log_success "Admin token obtained"

# Step 4: Create realm
log_info "Creating realm '${REALM_NAME}'..."
REALM_CREATE_RESULT=$(ssh_exec "curl -s -w '%{http_code}' -o /dev/null -X POST 'http://localhost:${KEYCLOAK_PORT}/admin/realms' \
  -H 'Authorization: Bearer ${ADMIN_TOKEN}' \
  -H 'Content-Type: application/json' \
  -d '{
    \"realm\": \"${REALM_NAME}\",
    \"enabled\": true,
    \"sslRequired\": \"none\",
    \"registrationAllowed\": false,
    \"loginWithEmailAllowed\": true,
    \"duplicateEmailsAllowed\": false,
    \"resetPasswordAllowed\": true,
    \"editUsernameAllowed\": false,
    \"bruteForceProtected\": true
  }'")

if [ "$REALM_CREATE_RESULT" = "201" ] || [ "$REALM_CREATE_RESULT" = "409" ]; then
    log_success "Realm '${REALM_NAME}' ready (HTTP ${REALM_CREATE_RESULT})"
else
    log_error "Failed to create realm (HTTP ${REALM_CREATE_RESULT})"
fi

# Step 5: Create client (PKCE disabled - FlightCtl CLI doesn't support PKCE yet)
log_info "Creating client '${CLIENT_ID}'..."
CLIENT_CREATE_RESULT=$(ssh_exec "curl -s -w '%{http_code}' -o /dev/null -X POST 'http://localhost:${KEYCLOAK_PORT}/admin/realms/${REALM_NAME}/clients' \
  -H 'Authorization: Bearer ${ADMIN_TOKEN}' \
  -H 'Content-Type: application/json' \
  -d '{
    \"clientId\": \"${CLIENT_ID}\",
    \"enabled\": true,
    \"publicClient\": true,
    \"redirectUris\": [
      \"https://${VM_IP}:443/callback\",
      \"http://127.0.0.1/*\",
      \"http://localhost/*\"
    ],
    \"webOrigins\": [
      \"http://127.0.0.1\",
      \"https://${VM_IP}:443\",
      \"http://localhost\"
    ],
    \"directAccessGrantsEnabled\": true,
    \"standardFlowEnabled\": true,
    \"implicitFlowEnabled\": false,
    \"protocol\": \"openid-connect\",
    \"attributes\": {}
  }'")

if [ "$CLIENT_CREATE_RESULT" = "201" ] || [ "$CLIENT_CREATE_RESULT" = "409" ]; then
    log_success "Client '${CLIENT_ID}' ready (HTTP ${CLIENT_CREATE_RESULT})"
else
    log_error "Failed to create client (HTTP ${CLIENT_CREATE_RESULT})"
fi

# Step 6: Create test users
log_info "Creating test users..."

# User 1: Test user from config
USER1_CREATE=$(ssh_exec "curl -s -w '%{http_code}' -o /dev/null -X POST 'http://localhost:${KEYCLOAK_PORT}/admin/realms/${REALM_NAME}/users' \
  -H 'Authorization: Bearer ${ADMIN_TOKEN}' \
  -H 'Content-Type: application/json' \
  -d '{
    \"username\": \"${TEST_USER}\",
    \"enabled\": true,
    \"email\": \"${TEST_EMAIL}\",
    \"firstName\": \"Test\",
    \"lastName\": \"User\",
    \"emailVerified\": true
  }'")

if [ "$USER1_CREATE" = "201" ] || [ "$USER1_CREATE" = "409" ]; then
    log_success "User '${TEST_USER}' created (HTTP ${USER1_CREATE})"
    
    # Get user ID and set password
    USER1_ID=$(ssh_exec "curl -s 'http://localhost:${KEYCLOAK_PORT}/admin/realms/${REALM_NAME}/users?username=${TEST_USER}' \
      -H 'Authorization: Bearer ${ADMIN_TOKEN}' | jq -r '.[0].id'")
    
    if [ -n "$USER1_ID" ] && [ "$USER1_ID" != "null" ]; then
        ssh_exec "curl -s -X PUT 'http://localhost:${KEYCLOAK_PORT}/admin/realms/${REALM_NAME}/users/${USER1_ID}/reset-password' \
          -H 'Authorization: Bearer ${ADMIN_TOKEN}' \
          -H 'Content-Type: application/json' \
          -d '{\"type\":\"password\",\"value\":\"${TEST_PASSWORD}\",\"temporary\":false}'" >/dev/null
        log_success "Password set for '${TEST_USER}'"
    fi
fi

# User 2: admin
USER2_CREATE=$(ssh_exec "curl -s -w '%{http_code}' -o /dev/null -X POST 'http://localhost:${KEYCLOAK_PORT}/admin/realms/${REALM_NAME}/users' \
  -H 'Authorization: Bearer ${ADMIN_TOKEN}' \
  -H 'Content-Type: application/json' \
  -d '{
    \"username\": \"admin\",
    \"enabled\": true,
    \"email\": \"admin@example.com\",
    \"firstName\": \"Admin\",
    \"lastName\": \"User\",
    \"emailVerified\": true
  }'")

if [ "$USER2_CREATE" = "201" ] || [ "$USER2_CREATE" = "409" ]; then
    log_success "User 'admin' created (HTTP ${USER2_CREATE})"
    
    USER2_ID=$(ssh_exec "curl -s 'http://localhost:${KEYCLOAK_PORT}/admin/realms/${REALM_NAME}/users?username=admin' \
      -H 'Authorization: Bearer ${ADMIN_TOKEN}' | jq -r '.[0].id'")
    
    if [ -n "$USER2_ID" ] && [ "$USER2_ID" != "null" ]; then
        ssh_exec "curl -s -X PUT 'http://localhost:${KEYCLOAK_PORT}/admin/realms/${REALM_NAME}/users/${USER2_ID}/reset-password' \
          -H 'Authorization: Bearer ${ADMIN_TOKEN}' \
          -H 'Content-Type: application/json' \
          -d '{\"type\":\"password\",\"value\":\"admin123\",\"temporary\":false}'" >/dev/null
        log_success "Password set for 'admin'"
    fi
fi

# Step 7: Verify configuration
log_info "Verifying OIDC configuration..."
OIDC_CONFIG=$(ssh_exec "curl -s 'http://localhost:${KEYCLOAK_PORT}/realms/${REALM_NAME}/.well-known/openid-configuration' | jq -r '.issuer'")

if [ -n "$OIDC_CONFIG" ] && [ "$OIDC_CONFIG" != "null" ]; then
    log_success "OIDC configuration is accessible"
    log_info "Issuer: ${OIDC_CONFIG}"
else
    log_error "OIDC configuration not accessible"
    exit 1
fi

# Step 8: Test user authentication
log_info "Testing user authentication..."
TEST_TOKEN=$(ssh_exec "curl -s -X POST 'http://localhost:${KEYCLOAK_PORT}/realms/${REALM_NAME}/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=${TEST_USER}' \
  -d 'password=${TEST_PASSWORD}' \
  -d 'grant_type=password' \
  -d 'client_id=${CLIENT_ID}' | jq -r '.access_token'")

if [ "$TEST_TOKEN" != "null" ] && [ -n "$TEST_TOKEN" ]; then
    log_success "User authentication test PASSED for ${TEST_USER}"
else
    log_error "User authentication test FAILED for ${TEST_USER}"
fi

echo ""
log_info "========================================="
log_success "Keycloak OIDC Setup Complete!"
log_info "========================================="
echo ""
log_info "Keycloak Access:"
log_info "  Admin Console: http://${VM_IP}:${KEYCLOAK_PORT}/admin"
log_info "  Admin User: ${KEYCLOAK_ADMIN}"
log_info "  Admin Password: ${KEYCLOAK_ADMIN_PASSWORD}"
echo ""
log_info "Realm Configuration:"
log_info "  Realm: ${REALM_NAME}"
log_info "  Client ID: ${CLIENT_ID}"
log_info "  OIDC Endpoint: http://${VM_IP}:${KEYCLOAK_PORT}/realms/${REALM_NAME}"
echo ""
log_info "Test User:"
log_info "  Username: ${TEST_USER}"
log_info "  Password: ${TEST_PASSWORD}"
log_info "  Email: ${TEST_EMAIL}"
echo ""
log_info "Next Steps:"
log_info "  1. Update FlightCtl to use: http://${VM_IP}:${KEYCLOAK_PORT}/realms/${REALM_NAME}"
log_info "  2. Restart FlightCtl services"
log_info "  3. Test login with ${TEST_USER}/${TEST_PASSWORD}"

