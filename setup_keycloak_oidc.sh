#!/bin/bash

################################################################################
# Keycloak OIDC Setup Script for FlightCtl
#
# This script deploys Keycloak and configures it with:
# - Realm: myrealm
# - Client: my_client
# - Test users with passwords
################################################################################

set -e

VM_IP="${1:-192.168.122.219}"
VM_USER="amalykhi"
VM_PASSWORD=" "

# Keycloak configuration
KEYCLOAK_ADMIN="admin"
KEYCLOAK_ADMIN_PASSWORD="admin"
REALM_NAME="myrealm"
CLIENT_ID="my_client"
KEYCLOAK_PORT="8080"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

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
  -e KEYCLOAK_ADMIN=${KEYCLOAK_ADMIN} \
  -e KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD} \
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

log_info "Waiting for Keycloak to be ready (this may take 30-60 seconds)..."
for i in {1..60}; do
    if ssh_exec "curl -s http://localhost:${KEYCLOAK_PORT}/health/ready 2>/dev/null | grep -q '\"status\":\"UP\"'"; then
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

# Step 2: Get admin token
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

# Step 3: Create realm
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

# Step 4: Create client
log_info "Creating client '${CLIENT_ID}'..."
CLIENT_CREATE_RESULT=$(ssh_exec "curl -s -w '%{http_code}' -o /dev/null -X POST 'http://localhost:${KEYCLOAK_PORT}/admin/realms/${REALM_NAME}/clients' \
  -H 'Authorization: Bearer ${ADMIN_TOKEN}' \
  -H 'Content-Type: application/json' \
  -d '{
    \"clientId\": \"${CLIENT_ID}\",
    \"enabled\": true,
    \"publicClient\": true,
    \"redirectUris\": [
      \"https://${VM_IP}:3443/*\",
      \"https://${VM_IP}:443/*\",
      \"https://${VM_IP}/*\",
      \"http://localhost:*\",
      \"urn:ietf:wg:oauth:2.0:oob\"
    ],
    \"webOrigins\": [
      \"https://${VM_IP}:3443\",
      \"https://${VM_IP}:443\",
      \"https://${VM_IP}\",
      \"http://localhost\"
    ],
    \"directAccessGrantsEnabled\": true,
    \"standardFlowEnabled\": true,
    \"implicitFlowEnabled\": false,
    \"protocol\": \"openid-connect\",
    \"attributes\": {
      \"pkce.code.challenge.method\": \"S256\"
    }
  }'")

if [ "$CLIENT_CREATE_RESULT" = "201" ] || [ "$CLIENT_CREATE_RESULT" = "409" ]; then
    log_success "Client '${CLIENT_ID}' ready (HTTP ${CLIENT_CREATE_RESULT})"
else
    log_error "Failed to create client (HTTP ${CLIENT_CREATE_RESULT})"
fi

# Step 5: Create test users
log_info "Creating test users..."

# User 1: testuser
USER1_CREATE=$(ssh_exec "curl -s -w '%{http_code}' -o /dev/null -X POST 'http://localhost:${KEYCLOAK_PORT}/admin/realms/${REALM_NAME}/users' \
  -H 'Authorization: Bearer ${ADMIN_TOKEN}' \
  -H 'Content-Type: application/json' \
  -d '{
    \"username\": \"testuser\",
    \"enabled\": true,
    \"email\": \"testuser@example.com\",
    \"firstName\": \"Test\",
    \"lastName\": \"User\",
    \"emailVerified\": true
  }'")

if [ "$USER1_CREATE" = "201" ] || [ "$USER1_CREATE" = "409" ]; then
    log_success "User 'testuser' created (HTTP ${USER1_CREATE})"
    
    # Get user ID and set password
    USER1_ID=$(ssh_exec "curl -s 'http://localhost:${KEYCLOAK_PORT}/admin/realms/${REALM_NAME}/users?username=testuser' \
      -H 'Authorization: Bearer ${ADMIN_TOKEN}' | jq -r '.[0].id'")
    
    if [ -n "$USER1_ID" ] && [ "$USER1_ID" != "null" ]; then
        ssh_exec "curl -s -X PUT 'http://localhost:${KEYCLOAK_PORT}/admin/realms/${REALM_NAME}/users/${USER1_ID}/reset-password' \
          -H 'Authorization: Bearer ${ADMIN_TOKEN}' \
          -H 'Content-Type: application/json' \
          -d '{\"type\":\"password\",\"value\":\"password\",\"temporary\":false}'" >/dev/null
        log_success "Password set for 'testuser'"
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

# Step 6: Verify configuration
log_info "Verifying OIDC configuration..."
OIDC_CONFIG=$(ssh_exec "curl -s 'http://localhost:${KEYCLOAK_PORT}/realms/${REALM_NAME}/.well-known/openid-configuration' | jq -r '.issuer'")

if [ -n "$OIDC_CONFIG" ] && [ "$OIDC_CONFIG" != "null" ]; then
    log_success "OIDC configuration is accessible"
    log_info "Issuer: ${OIDC_CONFIG}"
else
    log_error "OIDC configuration not accessible"
    exit 1
fi

# Step 7: Test user authentication
log_info "Testing user authentication..."
TEST_TOKEN=$(ssh_exec "curl -s -X POST 'http://localhost:${KEYCLOAK_PORT}/realms/${REALM_NAME}/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=testuser' \
  -d 'password=password' \
  -d 'grant_type=password' \
  -d 'client_id=${CLIENT_ID}' | jq -r '.access_token'")

if [ "$TEST_TOKEN" != "null" ] && [ -n "$TEST_TOKEN" ]; then
    log_success "User authentication test PASSED"
else
    log_error "User authentication test FAILED"
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
log_info "Test Users:"
log_info "  Username: testuser | Password: password"
log_info "  Username: admin    | Password: admin123"
echo ""
log_info "Next Steps:"
log_info "  1. Update FlightCtl to use: http://${VM_IP}:${KEYCLOAK_PORT}/realms/${REALM_NAME}"
log_info "  2. Restart FlightCtl services"
log_info "  3. Test login with testuser/password"

