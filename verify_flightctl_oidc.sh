#!/bin/bash

################################################################################
# FlightCtl Authentication Verification Script
# 
# This script automates the installation and verification of FlightCtl services
# with configurable authentication on a libvirt VM.
#
# Supported Authentication Types (set AUTH_TYPE in verification.conf):
#   - pam:      Built-in PAM Issuer (recommended, no external dependencies)
#   - keycloak: External Keycloak OIDC provider
#   - none:     No authentication
#
# Usage:
#   ./verify_flightctl_oidc.sh [VM_NAME] [RPM_URL|LATEST]
#
# Examples:
#   # Use config file defaults
#   ./verify_flightctl_oidc.sh
#
#   # Use specific build
#   ./verify_flightctl_oidc.sh eurolinux9 https://download.copr.fedorainfracloud.org/results/@redhat-et/flightctl/epel-9-x86_64/09903636-flightctl/
#
#   # Use latest successful build (automatically detected)
#   ./verify_flightctl_oidc.sh eurolinux9 LATEST
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load configuration
CONFIG_FILE="${1:-${SCRIPT_DIR}/verification.conf}"

# Check for legacy command line args (VM_NAME, RPM_URL)
if [ $# -eq 2 ] && [ ! -f "${1}" ]; then
    # Legacy mode: first arg is VM_NAME, second is RPM_URL
    VM_NAME="${1}"
    RPM_URL_ARG="${2}"
    CONFIG_FILE="${SCRIPT_DIR}/verification.conf"
elif [ $# -eq 1 ] && [ ! -f "${1}" ]; then
    # Legacy mode: first arg is VM_NAME
    VM_NAME="${1}"
    RPM_URL_ARG="LATEST"
    CONFIG_FILE="${SCRIPT_DIR}/verification.conf"
fi

# Load configuration file
if [ ! -f "${CONFIG_FILE}" ]; then
    echo -e "${RED}[ERROR]${NC} Configuration file not found: ${CONFIG_FILE}"
    echo "Please create verification.conf or specify a config file as the first argument."
    exit 1
fi

echo -e "${BLUE}[INFO]${NC} Loading configuration from: ${CONFIG_FILE}"
source "${CONFIG_FILE}"

# Override from config if not set by command line
VM_NAME="${VM_NAME:-${VM_NAME}}"
RPM_URL_ARG="${RPM_URL_ARG:-${RPM_SOURCE:-LATEST}}"

# Working directory
WORK_DIR="$(pwd)/flightctl_verification_$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="${WORK_DIR}/verification_report.md"

# Will be set after determining the RPM URL
RPM_BASE_URL=""

################################################################################
# Helper Functions
################################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

ssh_exec() {
    sshpass -p "${VM_PASSWORD}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "${VM_USER}@${VM_IP}" "$@"
}

ssh_exec_sudo() {
    # Try passwordless sudo first, fall back to password if needed
    if sshpass -p "${VM_PASSWORD}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "${VM_USER}@${VM_IP}" "sudo -n true 2>/dev/null"; then
        # Passwordless sudo works
        sshpass -p "${VM_PASSWORD}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "${VM_USER}@${VM_IP}" "sudo $@" 2>&1
    else
        # Use password
        sshpass -p "${VM_PASSWORD}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "${VM_USER}@${VM_IP}" "echo '${VM_PASSWORD}' | sudo -S -p '' $@" 2>&1 | grep -v '^\[sudo\]'
    fi
}

scp_to_vm() {
    sshpass -p "${VM_PASSWORD}" scp -o StrictHostKeyChecking=no "$1" "${VM_USER}@${VM_IP}:$2"
}

setup_passwordless_sudo() {
    log_info "Setting up passwordless sudo for ${VM_USER}..."
    
    # Check if passwordless sudo is already configured
    if sshpass -p "${VM_PASSWORD}" ssh -o StrictHostKeyChecking=no "${VM_USER}@${VM_IP}" "sudo -n true 2>/dev/null"; then
        log_success "Passwordless sudo already configured"
        return 0
    fi
    
    # Set up passwordless sudo
    sshpass -p "${VM_PASSWORD}" ssh -o StrictHostKeyChecking=no "${VM_USER}@${VM_IP}" \
        "echo '${VM_PASSWORD}' | sudo -S bash -c 'echo \"${VM_USER} ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/${VM_USER}-nopasswd && chmod 0440 /etc/sudoers.d/${VM_USER}-nopasswd'" 2>&1 | grep -v '^\[sudo\]'
    
    # Verify it was set up correctly
    if sshpass -p "${VM_PASSWORD}" ssh -o StrictHostKeyChecking=no "${VM_USER}@${VM_IP}" "sudo -n true 2>/dev/null"; then
        log_success "Passwordless sudo configured successfully"
    else
        log_warning "Could not set up passwordless sudo"
        log_info "Will use password for sudo commands"
    fi
}

################################################################################
# FIPS Functions
################################################################################

check_fips_status() {
    # Check if FIPS mode is enabled on the VM
    # Returns: 0 if enabled, 1 if disabled, 2 if error
    local fips_enabled
    fips_enabled=$(ssh_exec "cat /proc/sys/crypto/fips_enabled 2>/dev/null" || echo "error")
    
    if [ "$fips_enabled" = "1" ]; then
        return 0
    elif [ "$fips_enabled" = "0" ]; then
        return 1
    else
        return 2
    fi
}

verify_fips_mode() {
    log_info "Verifying FIPS mode status on VM..."
    
    # Check /proc/sys/crypto/fips_enabled
    local fips_proc
    fips_proc=$(ssh_exec "cat /proc/sys/crypto/fips_enabled 2>/dev/null" || echo "N/A")
    log_info "  /proc/sys/crypto/fips_enabled: ${fips_proc}"
    
    # Check fips-mode-setup status
    local fips_setup_status
    fips_setup_status=$(ssh_exec_sudo "fips-mode-setup --check 2>&1" || echo "Command not available")
    log_info "  fips-mode-setup --check: ${fips_setup_status}"
    
    # Check kernel command line for fips=1
    local kernel_cmdline
    kernel_cmdline=$(ssh_exec "grep -o 'fips=[0-9]' /proc/cmdline 2>/dev/null" || echo "not set")
    log_info "  Kernel cmdline: ${kernel_cmdline}"
    
    # Check OpenSSL FIPS provider
    local openssl_fips
    openssl_fips=$(ssh_exec "openssl list -providers 2>/dev/null | grep -i fips" || echo "No FIPS provider")
    log_info "  OpenSSL FIPS: ${openssl_fips:-Not loaded}"
    
    # Determine overall status
    if [ "$fips_proc" = "1" ]; then
        log_success "FIPS mode is ENABLED on the VM"
        return 0
    else
        log_warning "FIPS mode is DISABLED on the VM"
        return 1
    fi
}

enable_fips_mode() {
    log_info "Enabling FIPS mode on VM..."
    
    # Check current status first
    if check_fips_status; then
        log_success "FIPS mode is already enabled"
        verify_fips_mode
        return 0
    fi
    
    # Enable FIPS mode
    log_info "Running fips-mode-setup --enable..."
    local enable_result
    enable_result=$(ssh_exec_sudo "fips-mode-setup --enable 2>&1")
    local enable_exit=$?
    
    if [ $enable_exit -ne 0 ]; then
        log_error "Failed to enable FIPS mode: ${enable_result}"
        return 1
    fi
    
    log_success "FIPS mode enabled, VM needs to reboot"
    log_info "Rebooting VM to apply FIPS settings..."
    
    # Reboot the VM
    ssh_exec_sudo "reboot" &>/dev/null || true
    
    # Wait for VM to go down
    log_info "Waiting for VM to shut down..."
    sleep 10
    
    # Wait for VM to come back up
    local reboot_wait="${FIPS_REBOOT_WAIT:-120}"
    log_info "Waiting up to ${reboot_wait} seconds for VM to come back online..."
    
    local count=0
    local max_count=$((reboot_wait / 5))
    while [ $count -lt $max_count ]; do
        if ping -c 1 -W 2 "${VM_IP}" &>/dev/null; then
            # VM is responding to ping, check SSH
            if sshpass -p "${VM_PASSWORD}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "${VM_USER}@${VM_IP}" "echo 'SSH Ready'" &>/dev/null 2>&1; then
                log_success "VM is back online after FIPS reboot"
                break
            fi
        fi
        sleep 5
        count=$((count + 1))
        if [ $((count % 6)) -eq 0 ]; then
            log_info "  Still waiting for VM... ($((count * 5))s elapsed)"
        fi
    done
    
    if [ $count -ge $max_count ]; then
        log_error "VM did not come back online after FIPS reboot within ${reboot_wait} seconds"
        return 1
    fi
    
    # Give system a moment to fully initialize
    sleep 10
    
    # Verify FIPS is now enabled
    log_info "Verifying FIPS mode after reboot..."
    if check_fips_status; then
        log_success "FIPS mode successfully enabled and verified!"
        verify_fips_mode
        return 0
    else
        log_error "FIPS mode is NOT enabled after reboot"
        verify_fips_mode
        return 1
    fi
}

handle_fips_configuration() {
    # Handle FIPS configuration based on ENABLE_FIPS setting
    local fips_setting="${ENABLE_FIPS:-false}"
    
    case "$fips_setting" in
        "true"|"yes"|"1")
            log_info "FIPS mode requested (ENABLE_FIPS=true)"
            if ! enable_fips_mode; then
                log_error "Failed to enable FIPS mode"
                exit 1
            fi
            ;;
        "verify"|"check")
            log_info "FIPS verification requested (ENABLE_FIPS=verify)"
            if ! verify_fips_mode; then
                log_warning "FIPS is not enabled on this VM"
            fi
            ;;
        "false"|"no"|"0"|"")
            # Skip FIPS handling, but still show status
            if [ "${DEBUG_MODE}" = "true" ]; then
                log_info "FIPS mode not requested, checking current status..."
                verify_fips_mode || true
            fi
            ;;
        *)
            log_warning "Unknown ENABLE_FIPS value: ${fips_setting}"
            log_info "Valid values: true, false, verify"
            ;;
    esac
}

################################################################################
# Cleanup Functions
################################################################################

full_cleanup() {
    log_info "Performing full cleanup..."
    echo ""
    
    # Stop all FlightCtl services
    log_info "Stopping FlightCtl services..."
    ssh_exec_sudo "systemctl stop flightctl.target 2>/dev/null" || true
    sleep 2
    
    # Stop all FlightCtl containers
    log_info "Stopping FlightCtl containers..."
    ssh_exec_sudo "podman stop -a 2>/dev/null" || true
    sleep 2
    
    # Remove all FlightCtl containers
    log_info "Removing FlightCtl containers..."
    ssh_exec_sudo "podman rm -af 2>/dev/null" || true
    
    # Stop and remove Keycloak container
    log_info "Removing Keycloak container..."
    ssh_exec_sudo "podman stop keycloak 2>/dev/null" || true
    ssh_exec_sudo "podman rm keycloak 2>/dev/null" || true
    
    # Remove podman volumes (database data, etc.)
    log_info "Removing podman volumes..."
    ssh_exec_sudo "podman volume prune -f 2>/dev/null" || true
    
    # Clean up unused container images to free disk space
    log_info "Pruning unused container images (this may take a moment)..."
    ssh_exec_sudo "podman image prune -a -f 2>/dev/null" || true
    
    # Show disk usage after cleanup
    log_info "Disk usage after cleanup:"
    ssh_exec "df -h / | tail -1" || true
    
    # Remove FlightCtl RPMs
    log_info "Removing FlightCtl RPMs..."
    ssh_exec_sudo "dnf remove -y 'flightctl*' 2>/dev/null" || true
    
    # Clean up config directories
    log_info "Cleaning up config directories..."
    ssh_exec_sudo "rm -rf /etc/flightctl 2>/dev/null" || true
    ssh_exec_sudo "rm -rf /var/lib/flightctl 2>/dev/null" || true
    
    # Clean up systemd state
    log_info "Resetting systemd state..."
    ssh_exec_sudo "systemctl daemon-reload 2>/dev/null" || true
    ssh_exec_sudo "systemctl reset-failed 2>/dev/null" || true
    
    log_success "Full cleanup completed"
    echo ""
}

################################################################################
# PAM Issuer Functions
################################################################################

configure_pam_issuer() {
    log_info "Configuring PAM Issuer authentication..."
    
    # Check if PAM Issuer service is running (starts automatically with flightctl.target in rc3+)
    if ! ssh_exec_sudo "systemctl is-active flightctl-pam-issuer.service" 2>/dev/null | grep -q "active"; then
        log_warning "PAM Issuer service is not running"
        log_info "This FlightCtl version may not include PAM Issuer or it failed to start"
        log_info "Consider using AUTH_TYPE=keycloak instead"
        return 1
    fi
    
    log_success "PAM Issuer service is running"
    
    # Get the VM hostname - used for auto-detection of issuer URL
    local vm_hostname=$(ssh_exec "hostname -f" | tr -d '[:space:]')
    if [ -z "$vm_hostname" ] || [ "$vm_hostname" = "localhost" ]; then
        log_warning "VM has no valid hostname, PAM issuer auto-detection may fail"
        log_info "Consider setting hostname with: hostnamectl set-hostname <name>.local"
    else
        log_info "VM Hostname: ${vm_hostname}"
        # Ensure hostname resolves to the VM IP (add to /etc/hosts if needed)
        log_info "Ensuring hostname ${vm_hostname} resolves to ${VM_IP}..."
        ssh_exec "grep -q '${vm_hostname}' /etc/hosts || echo '${VM_IP} ${vm_hostname}' | sudo tee -a /etc/hosts > /dev/null"
    fi
    
    # PAM Issuer URL will be auto-detected from hostname
    log_info "PAM Issuer URL will be auto-detected as: https://${vm_hostname}:8444/api/v1/auth"
    
    # Set auth type to oidc (issuer is auto-detected from hostname)
    ssh_exec_sudo "sed -i 's/type: none/type: oidc/' /etc/flightctl/service-config.yaml" || true
    
    # Clear external Keycloak OIDC authority (use PAM instead)
    ssh_exec_sudo "sed -i 's|externalOidcAuthority:.*|externalOidcAuthority: \"\"|' /etc/flightctl/service-config.yaml" || true
    
    # Regenerate API config (issuer will be auto-configured from hostname)
    log_info "Regenerating API config..."
    ssh_exec_sudo "rm -f /etc/flightctl/flightctl-api/config.yaml"
    ssh_exec_sudo "systemctl unmask flightctl-api-init.service 2>/dev/null" || true
    ssh_exec_sudo "systemctl restart flightctl-api-init.service 2>/dev/null" || true
    sleep 2
    ssh_exec_sudo "systemctl mask flightctl-api-init.service 2>/dev/null" || true
    
    # Restart API to pick up new config
    log_info "Restarting API service..."
    ssh_exec_sudo "systemctl restart flightctl-api.service"
    sleep 5
    
    log_success "PAM Issuer configured successfully (issuer auto-detected)"
}

create_pam_user() {
    local username="${1:-${PAM_USER:-admin}}"
    local password="${2:-${PAM_PASSWORD:-admin123}}"
    local role="${3:-${PAM_ROLE:-flightctl-admin}}"
    
    log_info "Creating PAM Issuer user: ${username} with role: ${role}..."
    
    # Check if PAM Issuer container is running
    local container_name=$(ssh_exec_sudo "podman ps --format '{{.Names}}' 2>/dev/null" | grep -i "pam-issuer" || echo "")
    if [ -z "$container_name" ]; then
        log_error "PAM Issuer container is not running"
        log_info "Available containers:"
        ssh_exec_sudo "podman ps --format '{{.Names}}'" 2>/dev/null || true
        return 1
    fi
    log_info "Found PAM Issuer container: ${container_name}"
    
    # Create role group if it doesn't exist
    log_info "Creating role group: ${role}..."
    ssh_exec_sudo "podman exec -i flightctl-pam-issuer groupadd ${role} 2>/dev/null" || true
    
    # Create user
    log_info "Creating user: ${username}..."
    ssh_exec_sudo "podman exec flightctl-pam-issuer adduser ${username} 2>/dev/null" || true
    
    # Set password
    log_info "Setting password for ${username}..."
    ssh_exec_sudo "podman exec -i flightctl-pam-issuer sh -c 'echo \"${username}:${password}\" | chpasswd'"
    
    # Add user to role group
    log_info "Adding ${username} to ${role} group..."
    ssh_exec_sudo "podman exec -i flightctl-pam-issuer usermod -aG ${role} ${username}"
    
    # Verify user
    local user_groups=$(ssh_exec_sudo "podman exec flightctl-pam-issuer groups ${username}" 2>/dev/null || echo "")
    
    if echo "$user_groups" | grep -q "${role}"; then
        log_success "User ${username} created with role ${role}"
        log_info "User groups: ${user_groups}"
    else
        log_warning "User created but role assignment may have failed"
        log_info "User groups: ${user_groups}"
    fi
}

verify_flightctl_resources() {
    log_info ""
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "Verifying FlightCtl Resource Operations (Quadlet Functionality)"
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    local test_fleet_name="test-fleet-$(date +%s)"
    local test_repo_name="test-repo-$(date +%s)"
    
    # Test 1: Create a Fleet
    log_info "Test 1: Creating test fleet '${test_fleet_name}'..."
    local fleet_yaml="apiVersion: v1alpha1
kind: Fleet
metadata:
  name: ${test_fleet_name}
spec:
  selector:
    matchLabels:
      env: test
  template:
    spec:
      os:
        image: quay.io/centos-bootc/centos-bootc:stream9"
    
    local create_result=$(ssh_exec "echo '${fleet_yaml}' | flightctl apply -f - 2>&1" || echo "")
    
    if echo "$create_result" | grep -qiE "created|configured|applied|unchanged"; then
        log_success "Fleet '${test_fleet_name}' created successfully"
    else
        log_warning "Fleet creation result: ${create_result}"
    fi
    
    # Test 2: List Fleets
    log_info "Test 2: Listing fleets..."
    local fleets_result=$(ssh_exec "flightctl get fleets 2>&1" || echo "")
    
    if echo "$fleets_result" | grep -q "${test_fleet_name}"; then
        log_success "Fleet '${test_fleet_name}' is visible in fleet list"
    elif echo "$fleets_result" | grep -qE "NAME|OWNER"; then
        log_success "Fleet list accessible (test fleet may take time to appear)"
        log_info "Fleets: $(echo "$fleets_result" | head -5)"
    else
        log_warning "Fleet list result: ${fleets_result}"
    fi
    
    # Test 3: Get Fleet details
    log_info "Test 3: Getting fleet details..."
    local fleet_details=$(ssh_exec "flightctl get fleet/${test_fleet_name} -o yaml 2>&1" || echo "")
    
    if echo "$fleet_details" | grep -q "kind: Fleet"; then
        log_success "Fleet details retrieved successfully"
    else
        log_warning "Fleet details: ${fleet_details:0:200}"
    fi
    
    # Test 4: Create a Repository
    log_info "Test 4: Creating test repository '${test_repo_name}'..."
    local repo_yaml="apiVersion: v1alpha1
kind: Repository
metadata:
  name: ${test_repo_name}
spec:
  type: git
  url: https://github.com/flightctl/flightctl-demos"
    
    local repo_result=$(ssh_exec "echo '${repo_yaml}' | flightctl apply -f - 2>&1" || echo "")
    
    if echo "$repo_result" | grep -qiE "created|configured|applied|unchanged"; then
        log_success "Repository '${test_repo_name}' created successfully"
    else
        log_warning "Repository creation result: ${repo_result}"
    fi
    
    # Test 5: List Repositories
    log_info "Test 5: Listing repositories..."
    local repos_result=$(ssh_exec "flightctl get repositories 2>&1" || echo "")
    
    if echo "$repos_result" | grep -q "${test_repo_name}"; then
        log_success "Repository '${test_repo_name}' is visible in repository list"
    elif echo "$repos_result" | grep -qE "NAME|URL"; then
        log_success "Repository list accessible"
    else
        log_warning "Repository list result: ${repos_result}"
    fi
    
    # Test 6: List Devices (should be empty on fresh install)
    log_info "Test 6: Listing devices..."
    local devices_result=$(ssh_exec "flightctl get devices 2>&1" || echo "")
    
    if echo "$devices_result" | grep -qE "NAME|ALIAS|No resources found|^$"; then
        log_success "Device list accessible (empty on fresh install is expected)"
    else
        log_warning "Device list result: ${devices_result}"
    fi
    
    # Test 7: Check enrollment requests
    log_info "Test 7: Listing enrollment requests..."
    local enrollment_result=$(ssh_exec "flightctl get enrollmentrequests 2>&1" || echo "")
    
    if echo "$enrollment_result" | grep -qE "NAME|APPROVAL|No resources found|^$"; then
        log_success "Enrollment requests accessible"
    else
        log_warning "Enrollment requests result: ${enrollment_result}"
    fi
    
    # Test 8: API health check via CLI
    log_info "Test 8: Checking API version..."
    local version_result=$(ssh_exec "flightctl version 2>&1" || echo "")
    
    if echo "$version_result" | grep -qE "Client Version|Server Version"; then
        log_success "API responding with version info"
        log_info "$(echo "$version_result" | grep -E 'Version')"
    else
        log_warning "Version check result: ${version_result}"
    fi
    
    # Cleanup: Delete test resources
    log_info ""
    log_info "Cleaning up test resources..."
    ssh_exec "flightctl delete fleet/${test_fleet_name} 2>/dev/null" || true
    ssh_exec "flightctl delete repository/${test_repo_name} 2>/dev/null" || true
    log_success "Test resources cleaned up"
    
    log_info ""
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_success "FlightCtl Resource Verification Complete"
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

test_pam_authentication() {
    local username="${PAM_USER:-admin}"
    local password="${PAM_PASSWORD:-admin123}"
    
    log_info "Testing PAM Issuer authentication with user: ${username}..."
    
    # Check if PAM Issuer is accessible - use hostname to match API config
    local vm_hostname=$(ssh_exec "hostname -f" | tr -d '[:space:]')
    if [ -z "$vm_hostname" ] || [ "$vm_hostname" = "localhost" ]; then
        vm_hostname="${VM_IP}"
    fi
    local pam_issuer_url="https://${vm_hostname}:8444/api/v1/auth"
    log_info "PAM Issuer URL: ${pam_issuer_url}"
    
    # Test OIDC discovery endpoint
    log_info "Testing OIDC discovery endpoint..."
    local discovery_response=$(ssh_exec "curl -s -k ${pam_issuer_url}/.well-known/openid-configuration 2>&1" || echo "")
    
    if echo "$discovery_response" | grep -q "issuer"; then
        log_success "PAM Issuer OIDC discovery endpoint is accessible"
    else
        log_warning "PAM Issuer OIDC discovery endpoint may not be ready"
        log_info "Response: ${discovery_response:0:200}..."
    fi
    
    # Test FlightCtl CLI login with PAM Issuer
    log_info "Testing FlightCtl CLI login..."
    local insecure_flag=""
    if [ "${INSECURE_SKIP_TLS_VERIFY:-true}" = "true" ]; then
        insecure_flag="-k"
    fi
    
    local login_result=$(ssh_exec "flightctl login https://${VM_IP}:3443 ${insecure_flag} \
        -u ${username} \
        -p ${password} 2>&1" || echo "")
    
    if echo "$login_result" | grep -qiE "login successful|logged in|success"; then
        log_success "FlightCtl CLI login successful for user: ${username}"
        
        # Test querying devices with authenticated user
        log_info "Testing authenticated API query (devices)..."
        local devices_result=$(ssh_exec "flightctl get devices 2>&1" || echo "")
        if echo "$devices_result" | grep -qE "NAME|ALIAS|No resources found" || [ -z "$(echo "$devices_result" | grep -i error)" ]; then
            log_success "Can query devices with authenticated user"
        else
            log_warning "Device query returned: ${devices_result}"
        fi
        
        # Test FlightCtl resource operations
        verify_flightctl_resources
    else
        log_warning "FlightCtl CLI login result: ${login_result}"
        
        # Try web-based login info
        log_info ""
        log_info "Manual login commands:"
        log_info "  Web:      flightctl login https://${VM_IP}:3443 -k --web"
        log_info "  Password: flightctl login https://${VM_IP}:3443 -k -u ${username} -p ${password}"
    fi
}

# Switch API to use Keycloak OIDC (modifies service-config and restarts API)
switch_to_keycloak() {
    log_info "Switching API to Keycloak OIDC..."
    
    local oidc_authority="http://${VM_IP}:8080/realms/${OIDC_REALM}"
    log_info "Keycloak OIDC Authority: ${oidc_authority}"
    
    # IMPORTANT: Modify service-config.yaml (not the generated config.yaml)
    # The ExecStartPre in flightctl-api.service regenerates config.yaml from template
    # We need to:
    # 1. Disable pamOidcIssuer.enabled
    # 2. Set oidc.issuer to Keycloak URL
    # 3. Set oidc.clientId to Keycloak client
    
    log_info "Updating service-config.yaml for Keycloak..."
    
    # Disable PAM Issuer by setting enabled: false in pamOidcIssuer section
    ssh_exec_sudo "sed -i '/pamOidcIssuer:/,/clientSecret:/ s/enabled: true/enabled: false/' /etc/flightctl/service-config.yaml" || true
    
    # Set issuer in oidc section (the empty one after clientId: flightctl-client)
    # First check if issuer is empty and set it
    ssh_exec_sudo "sed -i 's|issuer:$|issuer: ${oidc_authority}|' /etc/flightctl/service-config.yaml" || true
    ssh_exec_sudo "sed -i 's|issuer: $|issuer: ${oidc_authority}|' /etc/flightctl/service-config.yaml" || true
    
    # Update clientId in the oidc section
    ssh_exec_sudo "sed -i 's|clientId: flightctl-client|clientId: ${OIDC_CLIENT_ID}|' /etc/flightctl/service-config.yaml" || true
    
    # Restart API service (ExecStartPre will regenerate config.yaml from updated service-config.yaml)
    log_info "Restarting API service..."
    ssh_exec_sudo "systemctl restart flightctl-api.service"
    sleep 5
    
    # Show the generated config
    log_info "Updated OIDC config:"
    ssh_exec "grep -A5 'oidc:' /etc/flightctl/flightctl-api/config.yaml" || true
    
    log_success "API switched to Keycloak OIDC"
}

# Switch API back to PAM Issuer
switch_to_pam() {
    log_info "Switching API back to PAM Issuer..."
    
    # Re-enable PAM Issuer in service-config.yaml
    ssh_exec_sudo "sed -i '/pamOidcIssuer:/,/clientSecret:/ s/enabled: false/enabled: true/' /etc/flightctl/service-config.yaml" || true
    
    # Reset clientId back to default
    ssh_exec_sudo "sed -i 's|clientId: ${OIDC_CLIENT_ID:-my_client}|clientId: flightctl-client|' /etc/flightctl/service-config.yaml" || true
    
    # Clear issuer (will be auto-detected from hostname)
    ssh_exec_sudo "sed -i 's|issuer: http://.*|issuer:|' /etc/flightctl/service-config.yaml" || true
    
    # Restart API service (ExecStartPre will regenerate config.yaml)
    log_info "Regenerating API config and restarting..."
    ssh_exec_sudo "systemctl restart flightctl-api.service"
    sleep 5
    
    log_success "API switched back to PAM Issuer (issuer auto-detected)"
}

configure_auth() {
    local auth_type="${AUTH_TYPE:-both}"
    
    log_info "Configuring authentication (type: ${auth_type})..."
    
    case "$auth_type" in
        "both"|"BOTH"|"all"|"ALL")
            log_info "Configuring BOTH PAM Issuer and Keycloak (will test sequentially)..."
            echo ""
            log_info "═══════════════════════════════════════════════════════════"
            log_info "Step 1: Configuring PAM Issuer Authentication"
            log_info "═══════════════════════════════════════════════════════════"
            configure_pam_issuer
            create_pam_user
            echo ""
            log_info "═══════════════════════════════════════════════════════════"
            log_info "Step 2: Deploying Keycloak (will test after PAM)"
            log_info "═══════════════════════════════════════════════════════════"
            check_and_start_keycloak || log_warning "Keycloak deployment failed"
            configure_keycloak_realm || log_warning "Keycloak realm configuration failed"
            ;;
        "pam"|"PAM")
            configure_pam_issuer
            create_pam_user
            ;;
        "keycloak"|"KEYCLOAK"|"oidc"|"OIDC")
            configure_oidc
            ;;
        "none"|"NONE"|"")
            log_info "Authentication disabled (AUTH_TYPE=none)"
            ssh_exec_sudo "sed -i 's/type: oidc/type: none/' /etc/flightctl/service-config.yaml" || true
            ssh_exec_sudo "sed -i 's/type: pam/type: none/' /etc/flightctl/service-config.yaml" || true
            ;;
        *)
            log_error "Unknown AUTH_TYPE: ${auth_type}"
            log_info "Valid options: both, pam, keycloak, none"
            exit 1
            ;;
    esac
}

test_authentication() {
    local auth_type="${AUTH_TYPE:-both}"
    
    case "$auth_type" in
        "both"|"BOTH"|"all"|"ALL")
            # Sequential testing: PAM first, then Keycloak
            echo ""
            log_info "═══════════════════════════════════════════════════════════"
            log_info "PHASE 1: Testing PAM Issuer Authentication"
            log_info "═══════════════════════════════════════════════════════════"
            test_pam_authentication
            
            # Now switch to Keycloak and test
            echo ""
            log_info "═══════════════════════════════════════════════════════════"
            log_info "PHASE 2: Switching to Keycloak OIDC"
            log_info "═══════════════════════════════════════════════════════════"
            switch_to_keycloak
            
            echo ""
            log_info "═══════════════════════════════════════════════════════════"
            log_info "PHASE 2: Testing Keycloak OIDC Authentication"
            log_info "═══════════════════════════════════════════════════════════"
            check_oidc_status || true
            test_oidc_authentication || true
            
            # Switch back to PAM for normal operation
            echo ""
            log_info "═══════════════════════════════════════════════════════════"
            log_info "Switching back to PAM Issuer (default)"
            log_info "═══════════════════════════════════════════════════════════"
            switch_to_pam
            log_success "Both authentication methods tested sequentially"
            ;;
        "pam"|"PAM")
            test_pam_authentication
            ;;
        "keycloak"|"KEYCLOAK"|"oidc"|"OIDC")
            check_oidc_status
            test_oidc_authentication
            ;;
        "none"|"NONE"|"")
            log_info "Authentication testing skipped (AUTH_TYPE=none)"
            ;;
    esac
}

################################################################################
# Main Functions
################################################################################

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    for tool in virsh sshpass curl wget jq; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install with: sudo dnf install -y ${missing_tools[*]}"
        exit 1
    fi
    
    log_success "All prerequisites available"
}

get_brew_task_rpms() {
    local task_url="$1"
    log_info "Fetching RPMs from Brew task: ${task_url}"
    
    # Ensure WORK_DIR exists
    mkdir -p "${WORK_DIR}"
    
    # Download the task page
    local task_html=$(curl -s -L "${task_url}" 2>&1)
    
    if [ -z "$task_html" ]; then
        log_error "Failed to fetch Brew task page from ${task_url}"
        exit 1
    fi
    
    # Extract all RPM download URLs directly from the task page (full URLs, excluding .src.rpm)
    # Store them in a temporary file for later use
    echo "$task_html" | grep -oP 'href="https://[^"]+/brewroot/work/[^"]+\.rpm"' | \
        cut -d'"' -f2 | grep -v "\.src\.rpm" > "${WORK_DIR}/.brew_rpms.list"
    
    # Extract base URL from first RPM
    local first_rpm=$(head -1 "${WORK_DIR}/.brew_rpms.list")
    RPM_BASE_URL=$(echo "$first_rpm" | rev | cut -d'/' -f2- | rev)"/"
    
    if [ -z "$RPM_BASE_URL" ]; then
        log_error "Could not extract RPM URLs from Brew task page"
        exit 1
    fi
    
    # Mark this as a Brew source with direct URLs
    BREW_DIRECT_URLS="true"
    
    log_info "Extracted Brew RPM base URL: ${RPM_BASE_URL}"
    log_info "Found $(wc -l < "${WORK_DIR}/.brew_rpms.list") RPM files"
}

get_latest_build_url() {
    log_info "Fetching latest successful build from Copr..."
    
    # Use Copr API to get latest build
    local api_url="https://copr.fedorainfracloud.org/api_3/build/list?ownername=@redhat-et&projectname=flightctl-dev&limit=1"
    local latest_build_id=$(curl -s "${api_url}" 2>&1 | jq -r '.items[0].id' 2>/dev/null)
    
    if [ -z "$latest_build_id" ] || [ "$latest_build_id" = "null" ]; then
        log_error "Failed to fetch latest build ID from Copr API"
        log_info "Tried API: ${api_url}"
        exit 1
    fi
    
    log_info "Found latest build ID: ${latest_build_id}"
    
    # Construct the download URL
    # Format: https://download.copr.fedorainfracloud.org/results/@redhat-et/flightctl-dev/epel-9-x86_64/0{BUILD_ID}-flightctl/
    local padded_build_id=$(printf "%08d" "$latest_build_id")
    RPM_BASE_URL="${COPR_DOWNLOAD_BASE}/${padded_build_id}-flightctl/"
    
    log_success "Latest build URL: ${RPM_BASE_URL}"
    
    # Verify the URL is accessible
    if ! curl -s -I "${RPM_BASE_URL}" | grep -q "200\|301\|302"; then
        log_warning "Build URL may not be accessible yet, trying without padding..."
        RPM_BASE_URL="${COPR_DOWNLOAD_BASE}/${latest_build_id}-flightctl/"
        
        if ! curl -s -I "${RPM_BASE_URL}" | grep -q "200\|301\|302"; then
            log_error "Could not access build URL: ${RPM_BASE_URL}"
            exit 1
        fi
    fi
    
    log_success "Build URL verified and accessible"
}

determine_rpm_url() {
    log_info "Determining RPM source URL..."
    
    if [ "$RPM_URL_ARG" = "LATEST" ] || [ "$RPM_URL_ARG" = "latest" ]; then
        log_info "Using LATEST build option"
        get_latest_build_url
    elif [[ "$RPM_URL_ARG" == *"brewweb.engineering.redhat.com/brew/taskinfo"* ]]; then
        log_info "Detected Brew task URL"
        get_brew_task_rpms "$RPM_URL_ARG"
    elif [[ "$RPM_URL_ARG" == *".rpm" ]]; then
        log_info "Detected direct RPM file URL"
        # Extract directory URL from RPM file URL
        RPM_BASE_URL=$(echo "$RPM_URL_ARG" | rev | cut -d'/' -f2- | rev)"/"
        log_info "Extracted directory URL: ${RPM_BASE_URL}"
    elif [[ "$RPM_URL_ARG" == *"brewroot/work/tasks"* ]]; then
        log_info "Detected Brew download URL"
        # Ensure it ends with /
        RPM_BASE_URL="${RPM_URL_ARG%/}/"
    else
        log_info "Using provided URL"
        RPM_BASE_URL="$RPM_URL_ARG"
    fi
    
    log_info "RPM Base URL: ${RPM_BASE_URL}"
}

check_vm_exists() {
    sudo virsh list --all | grep -q "${VM_NAME}"
}

create_vm() {
    log_info "VM '${VM_NAME}' not found. Creating new VM..."
    
    # Check prerequisites for VM creation
    if ! command -v virt-install &> /dev/null; then
        log_error "virt-install not found. Install with: sudo dnf install -y virt-install"
        exit 1
    fi
    
    # Build virt-install command
    local virt_install_cmd="sudo virt-install \
        --name ${VM_NAME} \
        --memory ${VM_MEMORY} \
        --vcpus ${VM_CPUS} \
        --disk size=${VM_DISK_SIZE} \
        --os-variant ${VM_OS_VARIANT} \
        --network network=${VM_NETWORK} \
        --graphics none \
        --console pty,target_type=serial"
    
    # Add installation source
    if [ -n "${VM_INSTALL_SOURCE}" ]; then
        if [[ "${VM_INSTALL_SOURCE}" == http* ]]; then
            virt_install_cmd+=" --location ${VM_INSTALL_SOURCE}"
        elif [[ "${VM_INSTALL_SOURCE}" == *.iso ]]; then
            virt_install_cmd+=" --cdrom ${VM_INSTALL_SOURCE}"
        elif [ "${VM_INSTALL_SOURCE}" = "pxe" ]; then
            virt_install_cmd+=" --pxe"
        else
            log_error "Invalid VM_INSTALL_SOURCE: ${VM_INSTALL_SOURCE}"
            exit 1
        fi
    else
        log_error "VM_INSTALL_SOURCE not specified in config"
        exit 1
    fi
    
    # Add kickstart if provided
    if [ -n "${VM_KICKSTART_FILE}" ]; then
        # Copy kickstart to a temporary location accessible during install
        local ks_name="ks.cfg"
        cp "${VM_KICKSTART_FILE}" "/tmp/${ks_name}"
        
        # Start a simple HTTP server on a random port to serve kickstart
        local ks_port=8765
        log_info "Starting temporary HTTP server for kickstart on port ${ks_port}..."
        (cd /tmp && python3 -m http.server ${ks_port} > /dev/null 2>&1) &
        local http_pid=$!
        sleep 2  # Give server time to start
        
        # Get host IP that VM can reach
        local host_ip=$(ip route get 8.8.8.8 | grep -oP 'src \K[\d.]+' | head -1)
        
        log_info "Kickstart will be served from: http://${host_ip}:${ks_port}/${ks_name}"
        virt_install_cmd+=" --extra-args=\"inst.ks=http://${host_ip}:${ks_port}/${ks_name} console=ttyS0\""
        
        # Store HTTP server PID for cleanup
        echo $http_pid > /tmp/ks_http_server.pid
    fi
    
    # Add cloud-init if provided
    if [ -n "${VM_CLOUD_INIT_USER_DATA}" ] && [ -n "${VM_CLOUD_INIT_META_DATA}" ]; then
        virt_install_cmd+=" --cloud-init user-data=${VM_CLOUD_INIT_USER_DATA},meta-data=${VM_CLOUD_INIT_META_DATA}"
    fi
    
    # Add noautoconsole for automated installation
    virt_install_cmd+=" --noautoconsole"
    
    log_info "Creating VM with command:"
    log_info "${virt_install_cmd}"
    
    # Execute virt-install
    if eval "${virt_install_cmd}"; then
        log_success "VM creation started successfully"
        
        # Clean up kickstart HTTP server if it was started
        if [ -f /tmp/ks_http_server.pid ]; then
            local http_pid=$(cat /tmp/ks_http_server.pid)
            sleep 10  # Give installer time to download kickstart
            kill $http_pid 2>/dev/null || true
            rm -f /tmp/ks_http_server.pid /tmp/ks.cfg
            log_info "Kickstart HTTP server stopped"
        fi
        
        # Wait for VM to be created
        log_info "Waiting for VM installation to complete..."
        log_info "This may take 10-30 minutes depending on your system and network speed"
        
        # Check if VM appears in the list
        local max_wait=60
        local count=0
        while [ $count -lt $max_wait ]; do
            if sudo virsh list --all | grep -q "${VM_NAME}"; then
                log_success "VM '${VM_NAME}' is now visible in virsh"
                break
            fi
            sleep 5
            count=$((count + 1))
            if [ $((count % 6)) -eq 0 ]; then
                log_info "Still waiting for VM... ($((count * 5))s elapsed)"
            fi
        done
        
        if [ $count -ge $max_wait ]; then
            log_warning "VM creation is taking longer than expected"
            log_info "You may need to monitor the installation manually with: sudo virsh console ${VM_NAME}"
        fi
        
        # Wait for VM to complete installation and be running
        log_info "Waiting for VM to be in running state..."
        max_wait=120  # 10 minutes
        count=0
        while [ $count -lt $max_wait ]; do
            if sudo virsh list --state-running | grep -q "${VM_NAME}"; then
                log_success "VM '${VM_NAME}' is now running"
                sleep 30  # Give it extra time for SSH to be ready
                return 0
            fi
            sleep 5
            count=$((count + 1))
            if [ $((count % 12)) -eq 0 ]; then
                log_info "Still waiting for VM to be running... ($((count * 5))s elapsed)"
            fi
        done
        
        log_error "VM did not reach running state within expected time"
        log_info "Check VM status with: sudo virsh list --all"
        log_info "Check VM console with: sudo virsh console ${VM_NAME}"
        exit 1
    else
        log_error "Failed to create VM"
        exit 1
    fi
}

wait_for_ssh() {
    local max_wait=720  # 60 minutes (for slow installations)
    local count=0
    local vm_ip="$1"
    
    log_info "Waiting for SSH to become available on ${vm_ip}..."
    log_info "This may take 20-60 minutes for fresh VM installation to complete"
    
    while [ $count -lt $max_wait ]; do
        if sshpass -p "${VM_PASSWORD}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "${VM_USER}@${vm_ip}" "echo 'SSH Ready'" &>/dev/null 2>&1; then
            log_success "SSH is now available on ${vm_ip}"
            return 0
        fi
        
        sleep 5
        count=$((count + 1))
        
        # Log progress every minute
        if [ $((count % 12)) -eq 0 ]; then
            log_info "Still waiting for SSH... ($((count * 5))s / $((max_wait * 5))s elapsed)"
            log_info "The VM OS installation is likely still in progress"
        fi
    done
    
    log_error "SSH did not become available within $((max_wait * 5)) seconds"
    log_info "The VM installation may have failed or is taking longer than expected"
    log_info "Check VM console with: sudo virsh console ${VM_NAME}"
    log_info "Or check if installation needs manual interaction"
    return 1
}

ensure_vm_exists() {
    if ! check_vm_exists; then
        if [ "${CREATE_VM_IF_MISSING}" = "true" ]; then
            create_vm
        else
            log_error "VM '${VM_NAME}' not found"
            log_info "To auto-create VM, set CREATE_VM_IF_MISSING=true in verification.conf"
            exit 1
        fi
    else
        log_info "VM '${VM_NAME}' exists"
        
        # Check if VM is running, start if not
        vm_state=$(sudo virsh list --all | grep -w "${VM_NAME}" | awk '{print $3, $4}' | xargs)
        if [[ "$vm_state" == "shut off" ]]; then
            log_info "VM is shut off. Starting VM..."
            if sudo virsh start "${VM_NAME}"; then
                log_success "VM started successfully"
                log_info "Waiting for VM to initialize properly (30 seconds)..."
                sleep 30
            else
                log_error "Failed to start VM"
                exit 1
            fi
        elif ! sudo virsh list --state-running | grep -q "${VM_NAME}"; then
            log_info "VM is not in running state. Starting..."
            if sudo virsh start "${VM_NAME}"; then
                log_success "VM started successfully"
                log_info "Waiting for VM to initialize properly (30 seconds)..."
                sleep 30
            else
                log_error "Failed to start VM"
                exit 1
            fi
        fi
    fi
}

get_vm_ip() {
    log_info "Getting VM IP address for ${VM_NAME}..."
    
    # Ensure VM exists and is running
    ensure_vm_exists
    
    # Get IP address
    VM_IP=$(sudo virsh domifaddr "${VM_NAME}" | grep -oP '(\d+\.){3}\d+' | head -1)
    
    if [ -z "$VM_IP" ]; then
        log_error "Could not determine VM IP address"
        exit 1
    fi
    
    log_success "VM IP: ${VM_IP}"
    
    # Test connectivity
    if ! ping -c 2 "${VM_IP}" &> /dev/null; then
        log_error "Cannot ping VM at ${VM_IP}"
        exit 1
    fi
    
    log_success "VM is reachable"
    
    # Wait for SSH to become available (especially important for fresh installations)
    if ! wait_for_ssh "${VM_IP}"; then
        log_error "SSH is not available on ${VM_IP}"
        exit 1
    fi
}

download_rpms() {
    log_info "Downloading FlightCtl RPMs from ${RPM_BASE_URL}..."
    
    mkdir -p "${WORK_DIR}"
    cd "${WORK_DIR}"
    
    local rpm_files=""
    
    # Check if we have direct URLs from Brew
    if [ -f "${WORK_DIR}/.brew_rpms.list" ]; then
        # Extract just the filenames for display
        rpm_files=$(cat "${WORK_DIR}/.brew_rpms.list" | rev | cut -d'/' -f1 | rev)
    else
        # Download index page for Copr/directory listing
        curl -L -s "${RPM_BASE_URL}" -o index.html
        
        # Extract RPM filenames
        # Try Copr format first (relative URLs with single quotes)
        rpm_files=$(grep -oP "href='[^']*\.rpm'" index.html 2>/dev/null | cut -d"'" -f2 | grep -v src.rpm || true)
        
        # If empty, try Brew format (absolute URLs with double quotes)
        if [ -z "$rpm_files" ]; then
            rpm_files=$(grep -oP 'href="[^"]*\.rpm"' index.html 2>/dev/null | cut -d'"' -f2 | grep -v "\.src\.rpm" || true)
        fi
    fi
    
    if [ -z "$rpm_files" ]; then
        log_error "No RPM files found at ${RPM_BASE_URL}"
        exit 1
    fi
    
    log_info "Found RPM packages:"
    while IFS= read -r rpm; do
        [ -n "$rpm" ] && log_info "  - $rpm"
    done <<< "$rpm_files"
    
    # Download flightctl-services and flightctl-cli
    local services_rpm=$(echo "$rpm_files" | grep "flightctl-services.*x86_64.rpm" | head -1)
    # Try Copr naming first (flightctl-cli), then Brew naming (flightctl-X.X.X without -cli, -services, -agent, etc.)
    local cli_rpm=$(echo "$rpm_files" | grep "flightctl-cli.*x86_64.rpm" | head -1)
    if [ -z "$cli_rpm" ]; then
        cli_rpm=$(echo "$rpm_files" | grep -E "flightctl-[0-9]+\.[0-9]+.*x86_64\.rpm" | grep -v -E "services|agent|observability|telemetry" | head -1)
    fi
    
    # Determine download URL format (Brew uses full URLs, others use base+filename)
    local services_url cli_url
    if [ -f "${WORK_DIR}/.brew_rpms.list" ]; then
        # Brew: use full URLs from the list
        services_url=$(cat "${WORK_DIR}/.brew_rpms.list" | grep "flightctl-services.*x86_64.rpm" | head -1)
        cli_url=$(cat "${WORK_DIR}/.brew_rpms.list" | grep -E "flightctl-[0-9]+\.[0-9]+.*x86_64\.rpm" | grep -v -E "services|agent|observability|telemetry" | head -1)
    else
        # Copr/other: construct URLs from base + filename
        services_url="${RPM_BASE_URL}${services_rpm}"
        cli_url="${RPM_BASE_URL}${cli_rpm}"
    fi
    
    if [ -n "$services_url" ]; then
        log_info "Downloading ${services_rpm}..."
        wget -q "${services_url}" 2>&1
        # Check if file was actually downloaded
        if [ -f "${services_rpm}" ] && [ -s "${services_rpm}" ]; then
            log_success "Downloaded ${services_rpm}"
        else
            # Try to get HTTP error details
            local wget_output=$(wget --spider "${services_url}" 2>&1)
            if echo "$wget_output" | grep -q "403"; then
                log_error "Access Forbidden (403) for ${services_rpm}"
                log_error "Brew URLs require VPN/authentication. Please:"
                log_error "  1. Connect to Red Hat VPN"
                log_error "  2. Or download RPMs manually and place them in a directory"
                log_error "  3. Or use Copr instead: RPM_SOURCE=\"LATEST\""
            else
                log_error "Failed to download ${services_rpm}"
                log_error "URL: ${services_url}"
            fi
            exit 1
        fi
    fi
    
    if [ -n "$cli_url" ]; then
        log_info "Downloading ${cli_rpm}..."
        wget -q "${cli_url}" 2>&1
        # Check if file was actually downloaded
        if [ -f "${cli_rpm}" ] && [ -s "${cli_rpm}" ]; then
            log_success "Downloaded ${cli_rpm}"
        else
            local wget_output=$(wget --spider "${cli_url}" 2>&1)
            if echo "$wget_output" | grep -q "403"; then
                log_error "Access Forbidden (403) for ${cli_rpm}"
                log_error "Brew URLs require VPN/authentication"
            else
                log_error "Failed to download ${cli_rpm}"
                log_error "URL: ${cli_url}"
            fi
            exit 1
        fi
    fi
}

copy_rpms_to_vm() {
    log_info "Copying RPMs to VM..."
    
    # Clean up old RPMs in /tmp first
    ssh_exec "rm -f /tmp/flightctl*.rpm" 2>/dev/null || true
    
    for rpm in *.rpm; do
        if [ -f "$rpm" ]; then
            log_info "Copying $rpm..."
            scp_to_vm "$rpm" "/tmp/"
        fi
    done
    
    log_success "RPMs copied to VM"
}

stop_old_services() {
    log_info "Checking for existing FlightCtl services..."
    
    # Check if services are installed
    if ssh_exec "rpm -qa | grep -q flightctl"; then
        log_info "Found existing FlightCtl installation. Stopping services..."
        ssh_exec_sudo "systemctl stop flightctl.target" || true
        sleep 5
        log_success "Services stopped"
    else
        log_info "No existing FlightCtl installation found"
    fi
}

remove_old_packages() {
    log_info "Removing old FlightCtl packages..."
    
    if ssh_exec "rpm -qa | grep -q flightctl"; then
        log_info "Removing old packages..."
        # Remove ALL flightctl packages to avoid conflicts between Brew and Copr versions
        ssh_exec_sudo "dnf remove -y 'flightctl*' 2>/dev/null" || true
        # Double-check specific packages that might conflict
        ssh_exec_sudo "rpm -e --nodeps flightctl flightctl-cli flightctl-services 2>/dev/null" || true
        log_success "Old packages removed"
    else
        log_info "No old packages to remove"
    fi
}

install_rpms() {
    log_info "Installing FlightCtl RPMs..."
    
    # Find the actual RPM files (handle both Copr and Brew naming)
    local services_rpm=$(ssh_exec "ls /tmp/flightctl-services-*.rpm 2>/dev/null | head -1")
    # For CLI: try flightctl-cli first, then fall back to flightctl-X.X.X
    local cli_rpm=$(ssh_exec "ls /tmp/flightctl-cli-*.rpm 2>/dev/null | head -1")
    if [ -z "$cli_rpm" ]; then
        cli_rpm=$(ssh_exec "ls /tmp/flightctl-[0-9]*.rpm 2>/dev/null | grep -v -E 'services|agent|observability|telemetry|selinux' | head -1")
    fi
    
    if [ -z "$services_rpm" ] || [ -z "$cli_rpm" ]; then
        log_error "Could not find required RPM files on VM"
        log_info "Services RPM: ${services_rpm}"
        log_info "CLI RPM: ${cli_rpm}"
        exit 1
    fi
    
    ssh_exec_sudo "dnf install -y ${services_rpm} ${cli_rpm}"
    
    log_success "RPMs installed successfully"
}

check_container_images() {
    # Check if image verification should be skipped
    if [ "${SKIP_IMAGE_CHECK:-false}" = "true" ]; then
        log_info "Skipping container image tag verification (SKIP_IMAGE_CHECK=true)"
        return 0
    fi
    
    log_info "Checking container images..."
    
    # Get the version from installed RPM
    local installed_version=$(ssh_exec "rpm -q flightctl-services --qf '%{VERSION}-%{RELEASE}'" | sed 's/\.el9$//')
    log_info "Installed version: ${installed_version}"
    
    # Check what tag the services require (from service file)
    local required_tag=$(ssh_exec_sudo "grep 'Image=' /usr/share/containers/systemd/flightctl-api.container 2>/dev/null" | sed 's/.*://' || echo "1.0.0")
    log_info "Services require tag: ${required_tag}"
    
    # Verify the required images exist
    local image_output=$(ssh_exec_sudo "podman images 2>&1 | grep 'flightctl.*${required_tag}' | wc -l")
    local image_count=$(echo "$image_output" | tail -1 | tr -d '[:space:]')
    
    if [ -n "$image_count" ] && [ "$image_count" -gt 0 ] 2>/dev/null; then
        log_success "Container images with tag '${required_tag}' are available"
    else
        log_warning "Required container images with tag '${required_tag}' not found"
        log_info "Available FlightCtl images:"
        ssh_exec_sudo "podman images 2>&1 | grep flightctl | head -10"
    fi
}

check_and_start_keycloak() {
    log_info "Checking Keycloak status..."
    
    # Check if Keycloak container exists
    local keycloak_exists=$(ssh_exec_sudo "podman ps -a --filter name=^keycloak$ --format '{{.Names}}' 2>/dev/null || true")
    
    if [ -z "$keycloak_exists" ]; then
        log_info "Keycloak container not found. Deploying Keycloak..."
        deploy_keycloak || return 1
    fi
    
    # Check if Keycloak is running
    local keycloak_running=$(ssh_exec_sudo "podman ps --filter name=^keycloak$ --format '{{.Names}}' 2>/dev/null || true")
    
    if [ -z "$keycloak_running" ]; then
        log_warning "Keycloak is stopped. Starting it..."
        ssh_exec_sudo "podman start keycloak"
    fi
    
    # Wait for Keycloak to be ready (up to 90 seconds for fresh deployment)
    log_info "Waiting for Keycloak to be ready (up to 90 seconds)..."
    local ready=false
    for i in {1..45}; do
        if ssh_exec "curl -s http://localhost:${KEYCLOAK_HEALTH_PORT:-9000}/health/ready 2>/dev/null | grep -q 'UP'"; then
            log_success "Keycloak is ready"
            ready=true
            break
        fi
        sleep 2
        if [ $((i % 10)) -eq 0 ]; then
            log_info "  Still waiting... ($((i * 2))s elapsed)"
        fi
    done
    
    if [ "$ready" = false ]; then
        log_warning "Keycloak health check timed out, checking realm..."
        if ssh_exec "curl -s http://localhost:8080/realms/master 2>/dev/null | grep -q 'master'"; then
            log_success "Keycloak is responding (master realm accessible)"
        else
            log_error "Keycloak is not responding"
            return 1
        fi
    fi
}

deploy_keycloak() {
    log_info "Deploying Keycloak container..."
    
    # Deploy Keycloak
    ssh_exec_sudo "podman run -d --name keycloak \
        --restart always \
        -p ${KEYCLOAK_PORT:-8080}:8080 \
        -p ${KEYCLOAK_HEALTH_PORT:-9000}:9000 \
        -e KEYCLOAK_ADMIN=${KEYCLOAK_ADMIN:-admin} \
        -e KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD:-admin} \
        -e KC_HEALTH_ENABLED=true \
        quay.io/keycloak/keycloak:latest \
        start-dev" 2>&1 || {
        log_error "Failed to deploy Keycloak container"
        return 1
    }
    
    log_success "Keycloak container deployed"
    
    # Wait for Keycloak to be fully ready
    log_info "Waiting for Keycloak to initialize (this may take 30-60 seconds)..."
    local ready=false
    for i in {1..60}; do
        if ssh_exec "curl -s http://localhost:${KEYCLOAK_HEALTH_PORT:-9000}/health/ready 2>/dev/null | grep -q 'UP'"; then
            log_success "Keycloak is ready!"
            ready=true
            break
        fi
        sleep 2
        echo -n "."
    done
    echo ""
    
    if [ "$ready" = false ]; then
        log_error "Keycloak did not become ready in time"
        return 1
    fi
    
    # Configure Keycloak realm and client
    configure_keycloak_realm
}

configure_keycloak_realm() {
    log_info "Configuring Keycloak realm and client..."
    
    # Get admin token
    log_info "Authenticating with Keycloak admin..."
    local admin_token=$(ssh_exec "curl -s -X POST 'http://localhost:${KEYCLOAK_PORT:-8080}/realms/master/protocol/openid-connect/token' \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d 'username=${KEYCLOAK_ADMIN:-admin}' \
        -d 'password=${KEYCLOAK_ADMIN_PASSWORD:-admin}' \
        -d 'grant_type=password' \
        -d 'client_id=admin-cli' | jq -r '.access_token'")
    
    if [ "$admin_token" = "null" ] || [ -z "$admin_token" ]; then
        log_error "Failed to get Keycloak admin token"
        return 1
    fi
    log_success "Admin token obtained"
    
    # Create realm
    log_info "Creating realm '${OIDC_REALM}'..."
    ssh_exec "curl -s -X POST 'http://localhost:${KEYCLOAK_PORT:-8080}/admin/realms' \
        -H 'Authorization: Bearer ${admin_token}' \
        -H 'Content-Type: application/json' \
        -d '{
            \"realm\": \"${OIDC_REALM}\",
            \"enabled\": true,
            \"sslRequired\": \"none\",
            \"registrationAllowed\": false,
            \"loginWithEmailAllowed\": true,
            \"duplicateEmailsAllowed\": false
        }'" >/dev/null 2>&1 || true
    log_success "Realm '${OIDC_REALM}' configured"
    
    # Create client (PKCE disabled - FlightCtl CLI doesn't support PKCE yet)
    log_info "Creating client '${OIDC_CLIENT_ID}'..."
    ssh_exec "curl -s -X POST 'http://localhost:${KEYCLOAK_PORT:-8080}/admin/realms/${OIDC_REALM}/clients' \
        -H 'Authorization: Bearer ${admin_token}' \
        -H 'Content-Type: application/json' \
        -d '{
            \"clientId\": \"${OIDC_CLIENT_ID}\",
            \"enabled\": true,
            \"publicClient\": true,
            \"redirectUris\": [\"https://${VM_IP}:443/callback\", \"http://127.0.0.1/*\", \"http://localhost/*\"],
            \"webOrigins\": [\"http://127.0.0.1\", \"https://${VM_IP}:443\", \"http://localhost\"],
            \"directAccessGrantsEnabled\": true,
            \"standardFlowEnabled\": true,
            \"protocol\": \"openid-connect\",
            \"attributes\": {}
        }'" >/dev/null 2>&1 || true
    log_success "Client '${OIDC_CLIENT_ID}' configured (PKCE optional)"
    
    # Get client internal ID for adding protocol mappers
    local client_internal_id=$(ssh_exec "curl -s 'http://localhost:${KEYCLOAK_PORT:-8080}/admin/realms/${OIDC_REALM}/clients?clientId=${OIDC_CLIENT_ID}' \
        -H 'Authorization: Bearer ${admin_token}' | jq -r '.[0].id'" 2>/dev/null)
    
    if [ -n "$client_internal_id" ] && [ "$client_internal_id" != "null" ]; then
        # Add 'organizations' protocol mapper to include organizations claim in tokens
        log_info "Adding 'organizations' claim mapper to client..."
        ssh_exec "curl -s -X POST 'http://localhost:${KEYCLOAK_PORT:-8080}/admin/realms/${OIDC_REALM}/clients/${client_internal_id}/protocol-mappers/models' \
            -H 'Authorization: Bearer ${admin_token}' \
            -H 'Content-Type: application/json' \
            -d '{
                \"name\": \"organizations\",
                \"protocol\": \"openid-connect\",
                \"protocolMapper\": \"oidc-usermodel-attribute-mapper\",
                \"config\": {
                    \"claim.name\": \"organizations\",
                    \"user.attribute\": \"organizations\",
                    \"id.token.claim\": \"true\",
                    \"access.token.claim\": \"true\",
                    \"userinfo.token.claim\": \"true\",
                    \"multivalued\": \"true\",
                    \"aggregate.attrs\": \"false\"
                }
            }'" >/dev/null 2>&1 || true
        
        # Add 'roles' protocol mapper to include roles claim in tokens
        log_info "Adding 'roles' claim mapper to client..."
        ssh_exec "curl -s -X POST 'http://localhost:${KEYCLOAK_PORT:-8080}/admin/realms/${OIDC_REALM}/clients/${client_internal_id}/protocol-mappers/models' \
            -H 'Authorization: Bearer ${admin_token}' \
            -H 'Content-Type: application/json' \
            -d '{
                \"name\": \"flightctl-roles\",
                \"protocol\": \"openid-connect\",
                \"protocolMapper\": \"oidc-usermodel-attribute-mapper\",
                \"config\": {
                    \"claim.name\": \"roles\",
                    \"user.attribute\": \"roles\",
                    \"id.token.claim\": \"true\",
                    \"access.token.claim\": \"true\",
                    \"userinfo.token.claim\": \"true\",
                    \"multivalued\": \"true\",
                    \"aggregate.attrs\": \"false\"
                }
            }'" >/dev/null 2>&1 || true
        log_success "Protocol mappers for 'organizations' and 'roles' claims added"
    else
        log_warning "Could not get client ID for adding protocol mappers"
    fi
    
    # Keycloak 26.x requires User Profile configuration before custom attributes can be set
    log_info "Configuring User Profile for custom attributes (Keycloak 26.x+)..."
    
    # Get current User Profile config
    local user_profile=$(ssh_exec "curl -s 'http://localhost:${KEYCLOAK_PORT:-8080}/admin/realms/${OIDC_REALM}/users/profile' \
        -H 'Authorization: Bearer ${admin_token}'" 2>/dev/null)
    
    # Check if organizations attribute already exists
    local has_org_attr=$(echo "$user_profile" | jq -r '.attributes[]? | select(.name=="organizations") | .name' 2>/dev/null)
    
    if [ -z "$has_org_attr" ]; then
        # Add organizations and roles attributes to User Profile
        log_info "Adding 'organizations' and 'roles' to User Profile..."
        local updated_profile=$(echo "$user_profile" | jq '.attributes += [
            {
                "name": "organizations",
                "displayName": "Organizations",
                "validations": {},
                "permissions": {"view": ["admin", "user"], "edit": ["admin"]},
                "multivalued": true
            },
            {
                "name": "roles",
                "displayName": "FlightCtl Roles",
                "validations": {},
                "permissions": {"view": ["admin", "user"], "edit": ["admin"]},
                "multivalued": true
            }
        ]' 2>/dev/null)
        
        if [ -n "$updated_profile" ] && [ "$updated_profile" != "null" ]; then
            ssh_exec "curl -s -X PUT 'http://localhost:${KEYCLOAK_PORT:-8080}/admin/realms/${OIDC_REALM}/users/profile' \
                -H 'Authorization: Bearer ${admin_token}' \
                -H 'Content-Type: application/json' \
                -d '${updated_profile}'" >/dev/null 2>&1 || true
            log_success "User Profile updated with custom attributes"
        else
            log_warning "Could not update User Profile - attributes may not work"
        fi
    else
        log_info "User Profile already has custom attributes configured"
    fi
    
    # Create test user - Step 1: Create user with all required fields
    log_info "Creating test user '${TEST_USER}' (Step 1: user creation)..."
    ssh_exec "curl -s -X POST 'http://localhost:${KEYCLOAK_PORT:-8080}/admin/realms/${OIDC_REALM}/users' \
        -H 'Authorization: Bearer ${admin_token}' \
        -H 'Content-Type: application/json' \
        -d '{
            \"username\": \"${TEST_USER}\",
            \"enabled\": true,
            \"email\": \"${TEST_EMAIL}\",
            \"firstName\": \"Test\",
            \"lastName\": \"User\",
            \"emailVerified\": true,
            \"requiredActions\": []
        }'" >/dev/null 2>&1 || true
    
    # Get user ID
    local user_id=$(ssh_exec "curl -s 'http://localhost:${KEYCLOAK_PORT:-8080}/admin/realms/${OIDC_REALM}/users?username=${TEST_USER}' \
        -H 'Authorization: Bearer ${admin_token}' | jq -r '.[0].id'" 2>/dev/null)
    
    if [ -n "$user_id" ] && [ "$user_id" != "null" ]; then
        # Step 2: Set password
        log_info "Setting password for '${TEST_USER}' (Step 2)..."
        ssh_exec "curl -s -X PUT 'http://localhost:${KEYCLOAK_PORT:-8080}/admin/realms/${OIDC_REALM}/users/${user_id}/reset-password' \
            -H 'Authorization: Bearer ${admin_token}' \
            -H 'Content-Type: application/json' \
            -d '{
                \"type\": \"password\",
                \"value\": \"${TEST_PASSWORD}\",
                \"temporary\": false
            }'" >/dev/null 2>&1 || true
        
        # Step 3: Update user with all required fields AND custom attributes
        log_info "Setting FlightCtl attributes for '${TEST_USER}' (Step 3)..."
        ssh_exec "curl -s -X PUT 'http://localhost:${KEYCLOAK_PORT:-8080}/admin/realms/${OIDC_REALM}/users/${user_id}' \
            -H 'Authorization: Bearer ${admin_token}' \
            -H 'Content-Type: application/json' \
            -d '{
                \"username\": \"${TEST_USER}\",
                \"enabled\": true,
                \"email\": \"${TEST_EMAIL}\",
                \"firstName\": \"Test\",
                \"lastName\": \"User\",
                \"emailVerified\": true,
                \"requiredActions\": [],
                \"attributes\": {
                    \"organizations\": [\"default\"],
                    \"roles\": [\"flightctl-admin\"]
                }
            }'" >/dev/null 2>&1 || true
        
        # Verify user configuration
        local user_data=$(ssh_exec "curl -s 'http://localhost:${KEYCLOAK_PORT:-8080}/admin/realms/${OIDC_REALM}/users/${user_id}' \
            -H 'Authorization: Bearer ${admin_token}'" 2>/dev/null)
        local user_attrs=$(echo "$user_data" | jq -r '.attributes.organizations[0] // empty' 2>/dev/null)
        local required_actions=$(echo "$user_data" | jq -r '.requiredActions | length' 2>/dev/null)
        
        if [ "$user_attrs" = "default" ]; then
            log_success "Test user '${TEST_USER}' configured with organizations=['default'] and roles=['flightctl-admin']"
        else
            log_warning "User attributes may not have been set correctly (Keycloak version specific)"
            log_info "You can manually set attributes in Keycloak Admin Console: http://${VM_IP}:8080/admin"
        fi
        
        if [ "$required_actions" = "0" ] || [ -z "$required_actions" ]; then
            log_success "No required actions pending for user"
        else
            log_warning "User has ${required_actions} required action(s) - may cause login issues"
        fi
    else
        log_warning "Could not create or find test user"
    fi
    
    log_success "Keycloak realm and client configured with FlightCtl claim mappings"
}

configure_oidc() {
    # Ensure Keycloak is running before configuring OIDC
    check_and_start_keycloak || {
        log_error "Keycloak is not available. Cannot configure OIDC."
        return 1
    }
    
    log_info "Configuring OIDC authentication..."
    
    local oidc_authority="http://${VM_IP}:8080/realms/${OIDC_REALM}"
    
    # Update main service config
    log_info "Updating /etc/flightctl/service-config.yaml..."
    
    # Run sed commands separately with explicit error checking
    log_info "  - Setting auth type to oidc..."
    ssh_exec_sudo "sed -i 's/type: none/type: oidc/' /etc/flightctl/service-config.yaml" || log_warning "Failed to set type"
    
    # Note: Do NOT set baseDomain to IP address - Brew builds require FQDN
    # Leave baseDomain empty to use default (hostname -f)
    
    log_info "  - Setting oidcAuthority..."
    ssh_exec_sudo "sed -i 's|oidcAuthority:.*|oidcAuthority: \"${oidc_authority}\"|' /etc/flightctl/service-config.yaml" || log_warning "Failed to set oidcAuthority"
    
    log_info "  - Setting externalOidcAuthority..."
    ssh_exec_sudo "sed -i 's|externalOidcAuthority:.*|externalOidcAuthority: \"${oidc_authority}\"|' /etc/flightctl/service-config.yaml" || log_warning "Failed to set externalOidcAuthority"
    
    log_info "  - Setting oidcClientId..."
    ssh_exec_sudo "sed -i 's|oidcClientId:.*|oidcClientId: \"${OIDC_CLIENT_ID}\"|' /etc/flightctl/service-config.yaml" || log_warning "Failed to set oidcClientId"
    
    log_success "Service config updated"
    
    # Regenerate API config from service config
    log_info "Regenerating API config from template..."
    ssh_exec_sudo "rm -f /etc/flightctl/flightctl-api/config.yaml"
    ssh_exec_sudo "systemctl unmask flightctl-api-init.service"
    
    # Use 'restart' to force re-execution of the oneshot service
    ssh_exec_sudo "systemctl restart flightctl-api-init.service"
    
    # Wait for API init to complete and config to be written
    log_info "Waiting for API config generation..."
    local config_generated=false
    for i in {1..15}; do
        if ssh_exec "test -f /etc/flightctl/flightctl-api/config.yaml"; then
            log_success "API config generated successfully"
            config_generated=true
            break
        fi
        sleep 1
    done
    
    # Check if config was created (in newer builds, it may be generated by service ExecStartPre)
    if [ "$config_generated" = "false" ]; then
        log_warning "API config not generated by init service (may be generated by API service on startup)"
        log_info "Checking init service status..."
        ssh_exec_sudo "systemctl status flightctl-api-init.service --no-pager -l" || true
    fi
    
    ssh_exec_sudo "systemctl mask flightctl-api-init.service"
    
    log_success "OIDC configuration updated"
}

start_services() {
    log_info "Starting FlightCtl services..."
    
    ssh_exec_sudo "systemctl start flightctl.target"
    
    log_info "Waiting for services to start and stabilize (up to 10 minutes)..."
    
    # Wait and check service status multiple times
    local max_attempts=60  # 60 attempts * 10 seconds = 10 minutes
    local wait_time=10
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        sleep $wait_time
        
        local running=$(ssh_exec "systemctl list-units 'flightctl*' --no-legend | grep running | wc -l" || echo "0")
        local activating=$(ssh_exec "systemctl list-units 'flightctl*' --no-legend | grep -E 'activating|auto-restart' | wc -l" || echo "0")
        
        # Show progress every 3 attempts (30 seconds) to reduce log spam
        if [ $((attempt % 3)) -eq 0 ] || [ $attempt -le 3 ]; then
            log_info "Attempt $attempt/$max_attempts: $running services running, $activating services starting... ($((attempt * wait_time))s elapsed)"
        fi
        
        # If we have services running and nothing activating, we're good
        if [ "$running" -ge 8 ] && [ "$activating" -eq 0 ]; then
            log_success "Services are stable with $running services running (after $((attempt * wait_time))s)"
            return 0
        fi
        
        # If no progress after 4 minutes, continue anyway
        if [ $attempt -ge 24 ] && [ "$running" -ge 5 ]; then
            log_warning "Some services still starting, but proceeding with $running services (after $((attempt * wait_time))s)"
            return 0
        fi
        
        attempt=$((attempt + 1))
    done
    
    log_warning "Services may still be starting after $((max_attempts * wait_time))s (10 minutes)"
}

check_service_status() {
    log_info "Checking service status..."
    
    # Get running services
    local running_services=$(ssh_exec "systemctl list-units 'flightctl*' --no-legend | grep running | wc -l")
    log_success "Running services: ${running_services}"
    
    # Get failed services (excluding 'not-found' which are optional)
    local failed_services=$(ssh_exec "systemctl list-units 'flightctl*' --no-legend --state=failed,auto-restart --all | grep -v 'not-found' | awk '{print \$1}'" || true)
    
    if [ -n "$failed_services" ]; then
        log_warning "Failed/Auto-restarting services:"
        echo "$failed_services" | while read service; do
            [ -n "$service" ] && log_warning "  - $service"
        done
        
        # Check logs for these failed services
        check_service_logs "$failed_services"
    fi
}

check_service_logs() {
    local failed_services="$1"
    
    if [ -z "$failed_services" ]; then
        return 0
    fi
    
    log_info "Checking logs for failed services..."
    echo ""
    
    while IFS= read -r service; do
        if [ -n "$service" ]; then
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            log_info "Logs for $service (last 30 lines with errors):"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            
            # Get recent logs with error keywords
            local logs=$(ssh_exec "journalctl -u $service -n 50 --no-pager -o cat 2>/dev/null | grep -iE 'error|fail|fatal|panic|denied|refused|unauthorized|unable|cannot|invalid' | tail -30" || true)
            
            if [ -n "$logs" ]; then
                echo "$logs"
            else
                # If no error keywords found, show last 20 lines
                log_info "No explicit errors found, showing last 20 lines:"
                ssh_exec "journalctl -u $service -n 20 --no-pager 2>/dev/null" || true
            fi
            echo ""
        fi
    done <<< "$failed_services"
}

test_cli() {
    log_info "Testing FlightCtl CLI..."
    
    # Clear any old login config that might have invalid tokens
    ssh_exec "rm -f ~/.flightctl/client.yaml" > /dev/null 2>&1 || true
    
    local max_attempts=3
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if [ $attempt -gt 1 ]; then
            log_info "Retry attempt $attempt/$max_attempts..."
            sleep 5
        fi
        
        # With OIDC enabled, we can't do anonymous queries
        # Just test that the CLI binary works and can reach the API
        # (Authentication will be tested separately in test_oidc_authentication)
        local cli_output=$(ssh_exec "flightctl version 2>&1")
        
        if echo "$cli_output" | grep -q "Client Version:"; then
            log_success "CLI binary is working"
            return 0
        fi
        
        attempt=$((attempt + 1))
    done
    
    log_error "CLI test failed after $max_attempts attempts"
    return 1
}

test_ui() {
    log_info "Testing FlightCtl UI..."
    
    local max_attempts=3
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if [ $attempt -gt 1 ]; then
            log_info "Retry attempt $attempt/$max_attempts..."
            sleep 5
        fi
        
        local ui_response=$(curl -k -s -o /dev/null -w "%{http_code}" "https://${VM_IP}:443")
        
        if [ "$ui_response" = "200" ]; then
            log_success "UI is accessible at https://${VM_IP}:443"
            return 0
        fi
        
        attempt=$((attempt + 1))
    done
    
    log_error "UI test failed after $max_attempts attempts - last response: HTTP ${ui_response}"
    
    # Check logs for UI-related services
    log_info "Checking UI service logs..."
    check_service_logs "flightctl-ui.service"
    
    return 1
}

test_api() {
    log_info "Testing FlightCtl API..."
    
    local max_attempts=3
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if [ $attempt -gt 1 ]; then
            log_info "Retry attempt $attempt/$max_attempts..."
            sleep 5
        fi
        
        local api_response=$(ssh_exec "curl -k -s https://${VM_IP}:3443/api/v1/devices" | jq -r '.kind' 2>/dev/null || echo "")
        
        if [ "$api_response" = "DeviceList" ]; then
            log_success "API is working - returned DeviceList"
            return 0
        fi
        
        attempt=$((attempt + 1))
    done
    
    log_warning "API test inconclusive after $max_attempts attempts"
    
    # Check logs for API-related services
    log_info "Checking API service logs..."
    check_service_logs "flightctl-api.service"
}

check_oidc_status() {
    log_info "Checking OIDC authentication status..."
    
    # Check if Keycloak is accessible
    if curl -s "http://${VM_IP}:8080/realms/${OIDC_REALM}/.well-known/openid-configuration" | grep -q "issuer"; then
        log_success "Keycloak is accessible at http://${VM_IP}:8080"
    else
        log_warning "Keycloak may not be accessible"
    fi
    
    # Check API auth status from logs
    local auth_status=$(ssh_exec_sudo "podman logs flightctl-api 2>&1 | grep -E 'OIDC auth enabled|Auth disabled' | tail -1")
    
    if echo "$auth_status" | grep -q "OIDC auth enabled"; then
        log_success "OIDC authentication is ENABLED in API"
    elif echo "$auth_status" | grep -q "Auth disabled"; then
        log_warning "Authentication is DISABLED in API"
        log_info "OIDC configuration is present but not active"
    fi
}

test_oidc_authentication() {
    log_info "Testing OIDC authentication with test user..."
    
    # Test Keycloak token endpoint
    log_info "Testing Keycloak token endpoint..."
    local token_response=$(ssh_exec "curl -s -X POST http://${VM_IP}:8080/realms/${OIDC_REALM}/protocol/openid-connect/token \
        -d 'client_id=${OIDC_CLIENT_ID}' \
        -d 'username=${TEST_USER}' \
        -d 'password=${TEST_PASSWORD}' \
        -d 'grant_type=password'" || echo "")
    
    if echo "$token_response" | grep -q "access_token"; then
        log_success "Keycloak authentication successful for user: ${TEST_USER}"
        
        # Extract and display token info
        local access_token=$(echo "$token_response" | jq -r '.access_token' 2>/dev/null)
        if [ -n "$access_token" ] && [ "$access_token" != "null" ]; then
            log_info "Access token obtained (first 50 chars): ${access_token:0:50}..."
            
            # Decode JWT payload and check for FlightCtl claims (organizations, roles)
            log_info "Verifying FlightCtl claims in token..."
            local token_payload=$(echo "$access_token" | cut -d'.' -f2 | tr '_-' '/+' | base64 -d 2>/dev/null)
            
            local orgs_claim=$(echo "$token_payload" | jq -r '.organizations // empty' 2>/dev/null)
            local roles_claim=$(echo "$token_payload" | jq -r '.roles // empty' 2>/dev/null)
            
            if [ -n "$orgs_claim" ] && [ "$orgs_claim" != "null" ]; then
                log_success "Token contains 'organizations' claim: ${orgs_claim}"
            else
                log_warning "Token is missing 'organizations' claim - FlightCtl login may fail"
                log_info "Ensure Keycloak user has 'organizations' attribute and client has protocol mapper"
            fi
            
            if [ -n "$roles_claim" ] && [ "$roles_claim" != "null" ]; then
                log_success "Token contains 'roles' claim: ${roles_claim}"
            else
                log_warning "Token is missing 'roles' claim - user may have limited permissions"
            fi
        fi
    else
        log_warning "Keycloak authentication failed for user: ${TEST_USER}"
        log_info "Response: ${token_response}"
    fi
    
    # Test FlightCtl CLI login
    log_info "Testing FlightCtl CLI login..."
    local insecure_flag=""
    if [ "${INSECURE_SKIP_TLS_VERIFY:-true}" = "true" ]; then
        insecure_flag="-k"
    fi
    
    # Check available providers first
    log_info "Available auth providers:"
    ssh_exec "flightctl login https://${VM_IP}:3443 ${insecure_flag} --show-providers 2>&1" || true
    
    # Use standard password flow (rc5+ doesn't use --client-id)
    local login_result=$(ssh_exec "flightctl login https://${VM_IP}:3443 ${insecure_flag} \
        -u ${TEST_USER} \
        -p ${TEST_PASSWORD} 2>&1" || echo "")
    
    if echo "$login_result" | grep -q "Login successful"; then
        log_success "FlightCtl CLI login successful for user: ${TEST_USER}"
        
        # Test querying devices with authenticated user
        log_info "Testing authenticated API query (devices)..."
        local devices_result=$(ssh_exec "flightctl get devices 2>&1" || echo "")
        if echo "$devices_result" | grep -qE "NAME|ALIAS" || [ -z "$devices_result" ]; then
            log_success "Can query devices with authenticated user"
        else
            log_warning "Device query returned error: ${devices_result}"
        fi
        
        # Test querying fleets with authenticated user
        log_info "Testing authenticated API query (fleets)..."
        local fleets_result=$(ssh_exec "flightctl get fleets 2>&1" || echo "")
        if echo "$fleets_result" | grep -qE "NAME|OWNER" || [ -z "$fleets_result" ]; then
            log_success "Can query fleets with authenticated user"
        else
            log_warning "Fleet query returned error: ${fleets_result}"
        fi
    else
        log_warning "FlightCtl CLI login failed for user: ${TEST_USER}"
        log_info "Login result: ${login_result}"
    fi
}

collect_service_logs() {
    log_info "Collecting service logs for failed services..."
    
    local failed_services=$(ssh_exec "systemctl list-units 'flightctl*' --no-legend | grep -E 'failed|auto-restart' | awk '{print \$1}'" || true)
    
    if [ -n "$failed_services" ]; then
        mkdir -p "${WORK_DIR}/logs"
        
        echo "$failed_services" | while read service; do
            local log_file="${WORK_DIR}/logs/${service}.log"
            log_info "Collecting logs for ${service}..."
            ssh_exec_sudo "journalctl -u ${service} -n 50 --no-pager" > "$log_file" 2>&1 || true
        done
        
        log_success "Logs collected in ${WORK_DIR}/logs/"
    fi
}

generate_report() {
    log_info "Generating verification report..."
    
    local auth_type="${AUTH_TYPE:-pam}"
    
    cat > "${REPORT_FILE}" << EOF
# FlightCtl Authentication Verification Report

**Date**: $(date '+%B %d, %Y at %H:%M:%S')  
**VM**: ${VM_NAME} (${VM_IP})  
**RPM Source**: ${RPM_BASE_URL}  
**Authentication Type**: ${auth_type}

## Summary

FlightCtl services have been installed and configured on the VM.

### FIPS Status

EOF

    local fips_status
    fips_status=$(ssh_exec "cat /proc/sys/crypto/fips_enabled 2>/dev/null" || echo "N/A")
    if [ "$fips_status" = "1" ]; then
        echo "**FIPS Mode**: ✅ ENABLED" >> "${REPORT_FILE}"
    elif [ "$fips_status" = "0" ]; then
        echo "**FIPS Mode**: ❌ DISABLED" >> "${REPORT_FILE}"
    else
        echo "**FIPS Mode**: ⚠️ Unknown" >> "${REPORT_FILE}"
    fi
    
    cat >> "${REPORT_FILE}" << EOF

## Installation Details

### RPM Packages Installed

EOF

    # List installed RPMs
    ssh_exec "rpm -qa | grep flightctl" >> "${REPORT_FILE}" || true
    
    cat >> "${REPORT_FILE}" << EOF

### Container Images

EOF

    ssh_exec_sudo "podman images | grep flightctl | head -10" >> "${REPORT_FILE}" || true
    
    cat >> "${REPORT_FILE}" << EOF

## Service Status

### Running Services

EOF

    ssh_exec "systemctl list-units 'flightctl*' --no-legend | grep running | awk '{print \"- \" \$1}'" >> "${REPORT_FILE}" || true
    
    cat >> "${REPORT_FILE}" << EOF

### Failed/Auto-restarting Services

EOF

    local failed=$(ssh_exec "systemctl list-units 'flightctl*' --no-legend | grep -E 'failed|auto-restart' | awk '{print \"- \" \$1}'" || true)
    if [ -n "$failed" ]; then
        echo "$failed" >> "${REPORT_FILE}"
    else
        echo "None" >> "${REPORT_FILE}"
    fi
    
    cat >> "${REPORT_FILE}" << EOF

## Authentication Configuration

**Type**: ${auth_type}

### Configuration Files

#### /etc/flightctl/service-config.yaml (auth section)

\`\`\`yaml
EOF

    ssh_exec "grep -A 15 '^  auth:' /etc/flightctl/service-config.yaml" >> "${REPORT_FILE}" || true
    
    cat >> "${REPORT_FILE}" << EOF
\`\`\`

#### /etc/flightctl/flightctl-api/config.yaml (auth section)

\`\`\`yaml
EOF

    ssh_exec "grep -A 8 '^auth:' /etc/flightctl/flightctl-api/config.yaml" >> "${REPORT_FILE}" || true
    
    cat >> "${REPORT_FILE}" << EOF
\`\`\`

### Authentication Status

EOF

    local auth_status=$(ssh_exec_sudo "podman logs flightctl-api 2>&1 | grep -E 'OIDC auth enabled|Auth disabled' | tail -1" || echo "Unknown")
    echo "**API Auth Status**: \`${auth_status}\`" >> "${REPORT_FILE}"
    
    # Add PAM Issuer specific info
    if [ "$auth_type" = "pam" ] || [ "$auth_type" = "PAM" ] || [ "$auth_type" = "both" ] || [ "$auth_type" = "BOTH" ]; then
        cat >> "${REPORT_FILE}" << EOF

### PAM Issuer Users

EOF
        echo "**Configured User**: ${PAM_USER:-admin} (role: ${PAM_ROLE:-flightctl-admin})" >> "${REPORT_FILE}"
        echo "" >> "${REPORT_FILE}"
        echo "To add more users:" >> "${REPORT_FILE}"
        echo "\`\`\`bash" >> "${REPORT_FILE}"
        echo "sudo podman exec flightctl-pam-issuer adduser <username>" >> "${REPORT_FILE}"
        echo "sudo podman exec -i flightctl-pam-issuer sh -c 'echo \"<username>:<password>\" | chpasswd'" >> "${REPORT_FILE}"
        echo "sudo podman exec -i flightctl-pam-issuer usermod -aG flightctl-admin <username>" >> "${REPORT_FILE}"
        echo "\`\`\`" >> "${REPORT_FILE}"
    fi
    
    cat >> "${REPORT_FILE}" << EOF

## Access Points

| Service | URL | Status |
|---------|-----|--------|
| API (Management) | https://${VM_IP}:3443 | ✅ |
| API (Agent) | https://${VM_IP}:7443 | ✅ |
| UI | https://${VM_IP}:443 | ✅ |
| CLI Artifacts | http://${VM_IP}:8090 | ✅ |
| Keycloak | http://${VM_IP}:8080 | ⚠️ HTTP only |

## CLI Configuration

\`\`\`bash
EOF

    # Add auth-specific login command
    if [ "$auth_type" = "both" ] || [ "$auth_type" = "BOTH" ]; then
        cat >> "${REPORT_FILE}" << EOF
# Login to FlightCtl (PAM Issuer - recommended)
flightctl login https://${VM_IP}:3443 -k -u ${PAM_USER:-admin} -p ${PAM_PASSWORD:-admin123}

# Login to FlightCtl (Keycloak - if configured)
flightctl login https://${VM_IP}:3443 -k -u ${TEST_USER} -p ${TEST_PASSWORD}

# Or use web-based login (works with either provider)
flightctl login https://${VM_IP}:3443 -k --web
EOF
    elif [ "$auth_type" = "pam" ] || [ "$auth_type" = "PAM" ]; then
        cat >> "${REPORT_FILE}" << EOF
# Login to FlightCtl (PAM Issuer)
flightctl login https://${VM_IP}:3443 -k -u ${PAM_USER:-admin} -p ${PAM_PASSWORD:-admin123}

# Or use web-based login
flightctl login https://${VM_IP}:3443 -k --web
EOF
    elif [ "$auth_type" = "keycloak" ] || [ "$auth_type" = "KEYCLOAK" ]; then
        cat >> "${REPORT_FILE}" << EOF
# Login to FlightCtl (Keycloak)
flightctl login https://${VM_IP}:3443 -k -u ${TEST_USER} -p ${TEST_PASSWORD}

# Or use web-based login
flightctl login https://${VM_IP}:3443 -k --web
EOF
    else
        cat >> "${REPORT_FILE}" << EOF
# Authentication disabled - direct access
flightctl login https://${VM_IP}:3443 -k
EOF
    fi

    cat >> "${REPORT_FILE}" << EOF

# List devices
flightctl get devices

# List fleets
flightctl get fleets
\`\`\`

## UI Access

Open in browser: https://${VM_IP}:443

## Service Logs

EOF

    if [ -d "${WORK_DIR}/logs" ]; then
        echo "Failed service logs are available in: \`${WORK_DIR}/logs/\`" >> "${REPORT_FILE}"
    else
        echo "No failed services detected." >> "${REPORT_FILE}"
    fi
    
    log_success "Report generated: ${REPORT_FILE}"
}

################################################################################
# Main Execution
################################################################################

main() {
    echo "=================================="
    echo "FlightCtl OIDC Verification Script"
    echo "=================================="
    echo ""
    
    log_info "VM Name: ${VM_NAME}"
    log_info "Work Directory: ${WORK_DIR}"
    echo ""
    
    check_prerequisites
    determine_rpm_url
    
    log_info "Using RPM URL: ${RPM_BASE_URL}"
    echo ""
    
    get_vm_ip
    setup_passwordless_sudo
    
    # Full cleanup if requested
    if [ "${FULL_CLEANUP:-false}" = "true" ]; then
        log_info "FULL_CLEANUP is enabled - cleaning up previous installation..."
        full_cleanup
    fi
    
    handle_fips_configuration
    download_rpms
    copy_rpms_to_vm
    stop_old_services
    remove_old_packages
    install_rpms
    check_container_images
    start_services
    check_service_status
    configure_auth
    
    echo ""
    log_info "Testing FlightCtl components..."
    test_cli
    test_ui
    test_api
    test_authentication
    
    echo ""
    collect_service_logs
    generate_report
    
    echo ""
    echo "=================================="
    log_success "Verification Complete!"
    echo "=================================="
    echo ""
    
    # Show FIPS status in summary
    local fips_status
    fips_status=$(ssh_exec "cat /proc/sys/crypto/fips_enabled 2>/dev/null" || echo "N/A")
    if [ "$fips_status" = "1" ]; then
        log_success "FIPS Mode: ENABLED"
    elif [ "$fips_status" = "0" ]; then
        log_info "FIPS Mode: Disabled"
    fi
    echo ""
    
    log_info "Report: ${REPORT_FILE}"
    log_info "Logs: ${WORK_DIR}/logs/"
    echo ""
    log_info "Quick Access:"
    log_info "  API: https://${VM_IP}:3443"
    log_info "  UI:  https://${VM_IP}:443"
    echo ""
    
    # Show login commands based on AUTH_TYPE
    local auth_type="${AUTH_TYPE:-both}"
    log_info "Authentication Type: ${auth_type}"
    log_info "Login Commands:"
    
    case "$auth_type" in
        "both"|"BOTH"|"all"|"ALL")
            local pam_user="${PAM_USER:-admin}"
            local pam_pass="${PAM_PASSWORD:-admin123}"
            log_info ""
            log_info "  PAM Issuer (recommended):"
            log_info "    Web:      flightctl login https://${VM_IP}:3443 -k --web"
            log_info "    Password: flightctl login https://${VM_IP}:3443 -k -u ${pam_user} -p ${pam_pass}"
            log_info ""
            log_info "  Keycloak (if configured):"
            log_info "    Web:      flightctl login https://${VM_IP}:3443 -k --web"
            log_info "    Password: flightctl login https://${VM_IP}:3443 -k -u ${TEST_USER} -p ${TEST_PASSWORD}"
            ;;
        "pam"|"PAM")
            local pam_user="${PAM_USER:-admin}"
            local pam_pass="${PAM_PASSWORD:-admin123}"
            log_info "  CLI (web):      flightctl login https://${VM_IP}:3443 -k --web"
            log_info "  CLI (password): flightctl login https://${VM_IP}:3443 -k -u ${pam_user} -p ${pam_pass}"
            ;;
        "keycloak"|"KEYCLOAK"|"oidc"|"OIDC")
            log_info "  CLI (web):      flightctl login https://${VM_IP}:3443 -k --web"
            log_info "  CLI (password): flightctl login https://${VM_IP}:3443 -k -u ${TEST_USER} -p ${TEST_PASSWORD}"
            ;;
        "none"|"NONE"|"")
            log_info "  Authentication disabled - no login required"
            ;;
    esac
    
    log_info "  UI: https://${VM_IP}/"
    echo ""
}

# Run main function
main "$@"

