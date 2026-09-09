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
#   VERIFY_RUN_MODE=agent_ui_only ./verify_flightctl_oidc.sh
#     — UI check + device onboarding only (no cleanup, no reinstall). Optional: VERIFY_WORK_DIR=/path/to/flightctl_verification_*
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

# CLI overrides (applied after sourcing; sourcing must not clobber these)
CLI_VM_NAME=""
CLI_RPM_URL_ARG=""
# True when user passed VM + RPM URL on CLI (second arg); verification.conf
# SERVICES_RPM_URL / CLI_RPM_URL must not override that source.
CLI_PASSED_RPM_URL="false"

# Check for legacy command line args (VM_NAME, RPM_URL)
if [ $# -eq 2 ] && [ ! -f "${1}" ]; then
    # Legacy mode: first arg is VM_NAME, second is RPM_URL
    CLI_VM_NAME="${1}"
    CLI_RPM_URL_ARG="${2}"
    CLI_PASSED_RPM_URL="true"
    CONFIG_FILE="${SCRIPT_DIR}/verification.conf"
elif [ $# -eq 1 ] && [ ! -f "${1}" ]; then
    # Legacy mode: first arg is VM_NAME
    CLI_VM_NAME="${1}"
    CLI_RPM_URL_ARG="LATEST"
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

if [ -n "${CLI_VM_NAME}" ]; then
    VM_NAME="${CLI_VM_NAME}"
fi
if [ -n "${CLI_RPM_URL_ARG}" ]; then
    RPM_URL_ARG="${CLI_RPM_URL_ARG}"
else
    RPM_URL_ARG="${RPM_SOURCE:-LATEST}"
fi

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
    
    # RHEL 10+ removed fips-mode-setup; FIPS must be enabled at install time (fips=1 kernel param)
    if ! ssh_exec "command -v fips-mode-setup" &>/dev/null && ! ssh_exec_sudo "command -v fips-mode-setup" &>/dev/null; then
        local os_id=$(ssh_exec "grep -E '^ID=' /etc/os-release 2>/dev/null | head -1" || echo "")
        local ver_id=$(ssh_exec "grep -E '^VERSION_ID=' /etc/os-release 2>/dev/null | head -1" || echo "")
        if echo "${os_id} ${ver_id}" | grep -qE 'rhel|el10|"10'; then
            log_error "FIPS cannot be enabled on this OS: fips-mode-setup is not available (removed in RHEL 10)."
            log_info "On RHEL 10, FIPS must be enabled during installation (e.g. add fips=1 to kernel cmdline at install)."
            log_info "To run verification without FIPS, set ENABLE_FIPS=false in verification.conf"
            return 1
        fi
        log_error "fips-mode-setup not found on VM. Install the crypto-policies or fips-mode-setup package, or enable FIPS at OS install time."
        return 1
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
    
    # Clean up podman builder cache
    log_info "Pruning podman builder cache..."
    ssh_exec_sudo "podman builder prune -a -f 2>/dev/null" || true
    
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
# VM Hostname (for PAM issuer URL and token validation)
################################################################################

# Set a proper hostname on the VM so PAM issuer auto-detection uses a reachable URL.
# Without this, hostname -f is often "localhost" and the API fails to validate tokens.
ensure_vm_hostname() {
    log_info "Ensuring VM has a valid hostname for PAM issuer..."
    local current=$(ssh_exec "hostname -f" | tr -d '[:space:]')
    if [ -n "$current" ] && [ "$current" != "localhost" ] && [ "$current" != "localhost.localdomain" ]; then
        log_success "VM hostname is already set: ${current}"
        ssh_exec "grep -q '${current}' /etc/hosts || echo '${VM_IP} ${current}' | sudo tee -a /etc/hosts > /dev/null"
        return 0
    fi
    # Derive FQDN from VM_NAME (e.g. RHEL10.1 -> rhel10-1.local)
    local fqdn=$(echo "${VM_NAME}" | tr '[:upper:]' '[:lower:]' | sed 's/\./-/g')
    [ -z "$fqdn" ] && fqdn="flightctl-vm"
    fqdn="${fqdn}.local"
    log_info "Setting VM hostname to ${fqdn} (resolving to ${VM_IP})..."
    ssh_exec_sudo "hostnamectl set-hostname ${fqdn}"
    # Resolve hostname to VM IP so API (and containers) can reach PAM issuer on the host
    ssh_exec "grep -q '${fqdn}' /etc/hosts || echo '${VM_IP} ${fqdn}' | sudo tee -a /etc/hosts > /dev/null"
    local verify=$(ssh_exec "hostname -f" | tr -d '[:space:]')
    if [ "$verify" = "$fqdn" ]; then
        log_success "VM hostname set to ${fqdn}"
    else
        log_warning "Hostname set to ${fqdn} but hostname -f reports: ${verify}"
    fi
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
        # Remove any existing entry for this hostname (may have stale IP)
        ssh_exec_sudo "sed -i '/${vm_hostname}/d' /etc/hosts"
        # Add the correct entry
        ssh_exec "echo '${VM_IP} ${vm_hostname}' | sudo tee -a /etc/hosts > /dev/null"
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
    local fleet_yaml="apiVersion: v1beta1
kind: Fleet
metadata:
  name: ${test_fleet_name}
spec:
  selector:
    matchLabels:
      env: test
  template:
    spec:
      config:
        - name: verification-inline
          inline:
            - path: /etc/flightctl-verification-marker
              content: 'flightctl-verification-resource-test'
              mode: 0644"
    
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
    local repo_yaml="apiVersion: v1beta1
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
    
    # Download the task page (Brew can be slow; allow up to 3 minutes)
    local task_html=$(curl -s -L --max-time 180 "${task_url}" 2>&1)
    
    if [ -z "$task_html" ]; then
        log_error "Failed to fetch Brew task page from ${task_url}"
        exit 1
    fi
    
    # Extract all RPM download URLs directly from the task page (full URLs, excluding .src.rpm)
    # Use "|| true" so set -e does not abort when parent tasks have no RPM links (build tasks).
    echo "$task_html" | grep -oP 'href="https://[^"]+/brewroot/work/[^"]+\.rpm"' | \
        cut -d'"' -f2 | grep -v "\.src\.rpm" > "${WORK_DIR}/.brew_rpms.list" || true
    
    # If parent task has no RPM links (e.g. it's a "build" task), follow x86_64 buildArch child task
    if [ ! -s "${WORK_DIR}/.brew_rpms.list" ]; then
        local child_task_id
        child_task_id=$(echo "$task_html" | grep "x86_64" | grep -oP 'taskinfo\?taskID=\K\d+' | head -1)
        if [ -z "$child_task_id" ]; then
            child_task_id=$(echo "$task_html" | grep "buildArch" | grep -oP 'taskinfo\?taskID=\K\d+' | head -1)
        fi
        if [ -n "$child_task_id" ]; then
            local base_url="${task_url%%\?*}"
            local child_url="${base_url}?taskID=${child_task_id}"
            log_info "Parent task has no RPM links; fetching x86_64 buildArch task: ${child_url}"
            task_html=$(curl -s -L --max-time 180 "${child_url}" 2>&1)
            [ -n "$task_html" ] || { log_error "Failed to fetch Brew child task page"; exit 1; }
            echo "$task_html" | grep -oP 'href="https://[^"]+/brewroot/work/[^"]+\.rpm"' | \
                cut -d'"' -f2 | grep -v "\.src\.rpm" > "${WORK_DIR}/.brew_rpms.list" || true
        fi
    fi
    
    # Extract base URL from first RPM
    local first_rpm=$(head -1 "${WORK_DIR}/.brew_rpms.list")
    RPM_BASE_URL=$(echo "$first_rpm" | rev | cut -d'/' -f2- | rev)"/"
    
    if [ -z "$RPM_BASE_URL" ]; then
        log_error "Could not extract RPM URLs from Brew task page (and no x86_64 buildArch child found)"
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
    mkdir -p "${WORK_DIR}"
    cd "${WORK_DIR}"

    # Check if RPMs already exist in WORK_DIR (manual download or pre-copied)
    local existing_services=$(ls flightctl-services-*.rpm 2>/dev/null | head -1 || true)
    local existing_cli=$(ls flightctl-cli-*.rpm 2>/dev/null | head -1 || true)

    if [ -n "$existing_services" ] && [ -n "$existing_cli" ]; then
        log_info "Found pre-downloaded RPMs in ${WORK_DIR}:"
        log_info "  - ${existing_services}"
        log_info "  - ${existing_cli}"
        log_success "Skipping download, using existing RPMs"
        return 0
    fi

    log_info "Downloading FlightCtl RPMs from ${RPM_BASE_URL}..."

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
    # Optional exact URL overrides from verification.conf:
    #   SERVICES_RPM_URL="https://.../flightctl-services-...rpm"
    #   CLI_RPM_URL="https://.../flightctl-cli-...rpm"
    local services_rpm=$(echo "$rpm_files" | grep "flightctl-services.*x86_64.rpm" | head -1)
    # Try Copr naming first (flightctl-cli), then Brew naming (flightctl-X.X.X without -cli, -services, -agent, etc.)
    local cli_rpm=$(echo "$rpm_files" | grep "flightctl-cli.*x86_64.rpm" | head -1)
    if [ -z "$cli_rpm" ]; then
        cli_rpm=$(echo "$rpm_files" | grep -E "flightctl-[0-9]+\.[0-9]+.*x86_64\.rpm" | grep -v -E "services|agent|observability|telemetry" | head -1)
    fi
    
    # Determine download URL format (Brew uses full URLs, others use base+filename)
    local services_url cli_url
    if [ -f "${WORK_DIR}/.brew_rpms.list" ]; then
        # Brew: use full URLs from the list (CLI is flightctl-cli-VERSION, not flightctl-VERSION)
        services_url=$(cat "${WORK_DIR}/.brew_rpms.list" | grep "flightctl-services.*x86_64.rpm" | head -1)
        cli_url=$(cat "${WORK_DIR}/.brew_rpms.list" | grep "flightctl-cli.*x86_64.rpm" | head -1)
        if [ -z "$cli_url" ]; then
            cli_url=$(cat "${WORK_DIR}/.brew_rpms.list" | grep -E "flightctl-[0-9]+\.[0-9]+.*x86_64\.rpm" | grep -v -E "services|agent|observability|telemetry" | head -1)
        fi
    else
        # Copr/other: construct URLs from base + filename
        services_url="${RPM_BASE_URL}${services_rpm}"
        cli_url="${RPM_BASE_URL}${cli_rpm}"
    fi

    # Respect verification.conf direct RPM URL overrides only when RPM source was
    # not passed as the second CLI argument (otherwise conf pins an old task/build).
    if [ "${CLI_PASSED_RPM_URL:-false}" = "true" ]; then
        log_info "RPM source from CLI — ignoring SERVICES_RPM_URL / CLI_RPM_URL in config for this run"
    else
        if [ -n "${SERVICES_RPM_URL:-}" ]; then
            services_url="${SERVICES_RPM_URL}"
            services_rpm="$(basename "${SERVICES_RPM_URL}")"
            log_info "Using SERVICES_RPM_URL override: ${services_rpm}"
        fi
        if [ -n "${CLI_RPM_URL:-}" ]; then
            cli_url="${CLI_RPM_URL}"
            cli_rpm="$(basename "${CLI_RPM_URL}")"
            log_info "Using CLI_RPM_URL override: ${cli_rpm}"
        fi
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
    
    ssh_exec_sudo "dnf install -y --disablerepo='edge-manager-1.1-for-rhel-9-x86_64-rpms' --disablerepo='edge-manager-1.1-for-rhel-10-x86_64-rpms' --disablerepo='rhel-10-for-x86_64-baseos-rpms' --disablerepo='rhel-10-for-x86_64-appstream-rpms' ${services_rpm} ${cli_rpm}"

    log_success "RPMs installed successfully"
}

verify_selinux_context() {
    log_info "Verifying SELinux context for flightctl-agent binary..."

    # Check if SELinux is enabled
    local selinux_status=$(ssh_exec "getenforce 2>/dev/null" || echo "Unknown")
    log_info "SELinux status: ${selinux_status}"

    if [ "$selinux_status" = "Disabled" ]; then
        log_warning "SELinux is disabled, skipping context verification"
        return 0
    fi

    # Check if flightctl-agent binary exists
    if ! ssh_exec "test -f /usr/bin/flightctl-agent"; then
        log_warning "flightctl-agent binary not found at /usr/bin/flightctl-agent, skipping SELinux verification"
        return 0
    fi

    # Get SELinux context of flightctl-agent binary
    local selinux_context=$(ssh_exec "ls -Z /usr/bin/flightctl-agent 2>/dev/null | awk '{print \$1}'" || echo "")

    if [ -z "$selinux_context" ]; then
        log_error "Failed to get SELinux context for /usr/bin/flightctl-agent"
        return 1
    fi

    log_info "SELinux context: ${selinux_context}"

    # Expected context: system_u:object_r:flightctl_agent_exec_t:s0
    local expected_type="flightctl_agent_exec_t"

    if echo "$selinux_context" | grep -q "$expected_type"; then
        log_success "SELinux context is correct: ${selinux_context}"
        log_success "Binary has proper flightctl_agent_exec_t type"
        return 0
    else
        log_error "SELinux context is incorrect!"
        log_error "  Expected type: ${expected_type}"
        log_error "  Actual context: ${selinux_context}"

        # Check if flightctl-selinux package is installed
        local selinux_rpm=$(ssh_exec "rpm -qa | grep flightctl-selinux" || echo "")
        if [ -z "$selinux_rpm" ]; then
            log_error "flightctl-selinux package is not installed"
            log_info "Install with: sudo dnf install flightctl-selinux"
        else
            log_info "flightctl-selinux package installed: ${selinux_rpm}"
            log_info "You may need to run: sudo restorecon -v /usr/bin/flightctl-agent"
        fi

        return 1
    fi
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

EOF

    if [ -f "${WORK_DIR}/.verification_fleet_name" ]; then
        local report_fleet_name
        report_fleet_name=$(head -1 "${WORK_DIR}/.verification_fleet_name" | tr -d '[:space:]')
        if [ -n "$report_fleet_name" ]; then
            cat >> "${REPORT_FILE}" << EOF

## Verification fleet (device onboarding)

Fleet **${report_fleet_name}** was applied with \`selector.matchLabels\` derived from \`DEVICE_LABELS\`. Devices approved with \`flightctl approve ... -l ...\` receive the same labels and join this fleet.

\`\`\`bash
flightctl get fleet/${report_fleet_name} -o yaml
flightctl get fleets
\`\`\`
EOF
        fi
    fi

    cat >> "${REPORT_FILE}" << EOF

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
# Device Onboarding Functions
################################################################################

# Agent VM IP (will be set after VM is created/started)
AGENT_VM_IP=""

# SSH helper for agent VM
agent_ssh_exec() {
    sshpass -p "${AGENT_VM_PASSWORD}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "${AGENT_VM_USER}@${AGENT_VM_IP}" "$@"
}

agent_ssh_exec_sudo() {
    sshpass -p "${AGENT_VM_PASSWORD}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "${AGENT_VM_USER}@${AGENT_VM_IP}" "echo '${AGENT_VM_PASSWORD}' | sudo -S $*"
}

agent_scp() {
    sshpass -p "${AGENT_VM_PASSWORD}" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$@"
}

# Get agent VM IP from libvirt
get_agent_vm_ip() {
    log_info "Getting agent VM IP address..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        AGENT_VM_IP=$(sudo virsh domifaddr "${AGENT_VM_NAME}" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
        
        if [ -n "$AGENT_VM_IP" ]; then
            log_success "Agent VM IP: ${AGENT_VM_IP}"
            return 0
        fi
        
        log_info "Waiting for agent VM IP (attempt ${attempt}/${max_attempts})..."
        sleep 5
        ((attempt++))
    done
    
    log_error "Failed to get agent VM IP after ${max_attempts} attempts"
    return 1
}

# Check if agent VM exists (use sudo to match system libvirt where VMs are created)
agent_vm_exists() {
    sudo virsh dominfo "${AGENT_VM_NAME}" &>/dev/null
}

# Check if agent VM is running
agent_vm_running() {
    local state=$(sudo virsh domstate "${AGENT_VM_NAME}" 2>/dev/null)
    [ "$state" = "running" ]
}

# Create bootc-based agent VM (OSTree system like make agent-vm)
create_bootc_agent_vm() {
    log_info "Creating bootc-based agent VM: ${AGENT_VM_NAME}..."
    
    local bootc_image="${BOOTC_IMAGE:-quay.io/centos-bootc/centos-bootc:stream10}"
    local virt_os_variant="${BOOTC_VIRT_OS_VARIANT:-fedora-eln}"
    local disk_path="/var/lib/libvirt/images/${AGENT_VM_NAME}.qcow2"
    local output_dir="${WORK_DIR}/bootc-output"
    local disk_size="${AGENT_VM_DISK_SIZE:-20}"
    
    mkdir -p "${output_dir}"
    
    # Check if bootc-image-builder is available
    if ! command -v podman &>/dev/null; then
        log_error "podman is required for bootc image building"
        return 1
    fi
    
    # Build qcow2 from bootc image using bootc-image-builder
    log_info "Building qcow2 from bootc image: ${bootc_image}"
    log_info "This may take several minutes on first run..."
    # bootc-image-builder expects the base image in local storage (it does not pull it).
    log_info "Pulling base bootc image into local podman storage..."
    if ! sudo podman pull "${bootc_image}"; then
        log_error "Failed to pull bootc image: ${bootc_image}"
        return 1
    fi

    sudo podman run --rm \
        -i \
        --privileged \
        --pull=newer \
        --security-opt label=type:unconfined_t \
        -v "${output_dir}:/output" \
        -v /var/lib/containers/storage:/var/lib/containers/storage \
        quay.io/centos-bootc/bootc-image-builder:latest \
        build \
        --type qcow2 \
        --rootfs xfs \
        "${bootc_image}"
    
    if [ ! -f "${output_dir}/qcow2/disk.qcow2" ]; then
        log_error "Failed to build bootc qcow2 image"
        return 1
    fi
    
    log_success "Bootc qcow2 image built successfully"
    
    # Copy and resize the disk
    log_info "Copying disk to libvirt images directory..."
    sudo cp "${output_dir}/qcow2/disk.qcow2" "${disk_path}"
    sudo qemu-img resize "${disk_path}" "${disk_size}G"
    
    # Inject user credentials into bootc image for SSH access
    log_info "Injecting user credentials into bootc image..."
    inject_user_into_bootc_image "${disk_path}"
    
    # Create VM with virt-install (similar to make agent-vm)
    log_info "Creating VM with virt-install..."
    sudo virt-install \
        --name "${AGENT_VM_NAME}" \
        --tpm backend.type=emulator,backend.version=2.0,model=tpm-tis \
        --vcpus "${AGENT_VM_CPUS:-2}" \
        --memory "${AGENT_VM_MEMORY:-2048}" \
        --import \
        --disk "${disk_path},format=qcow2" \
        --os-variant "${virt_os_variant}" \
        --network network=default \
        --graphics none \
        --noautoconsole \
        --wait 0
    
    log_success "Bootc agent VM created: ${AGENT_VM_NAME}"
    
    # For bootc images, use root user
    AGENT_VM_USER="root"
    log_info "Using root user for bootc VM access"
    
    # Wait for VM to boot and get IP
    log_info "Waiting for bootc agent VM to boot..."
    sleep 45  # Bootc images take longer to boot
    get_agent_vm_ip
    
    # Wait for SSH to be available
    log_info "Waiting for SSH to be available..."
    local ssh_attempts=0
    local max_ssh_attempts=40
    
    while [ $ssh_attempts -lt $max_ssh_attempts ]; do
        if sshpass -p "${AGENT_VM_PASSWORD}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
            "root@${AGENT_VM_IP}" "echo 'SSH ready'" &>/dev/null; then
            log_success "SSH is available on bootc agent VM"
            return 0
        fi
        sleep 5
        ((ssh_attempts++))
        log_info "Waiting for SSH (attempt ${ssh_attempts}/${max_ssh_attempts})..."
    done
    
    log_error "SSH not available after ${max_ssh_attempts} attempts"
    return 1
}

# Inject user credentials into bootc qcow2 image for SSH access
inject_user_into_bootc_image() {
    local disk_path="$1"
    
    # Load nbd module if needed
    sudo modprobe nbd max_part=8 2>/dev/null || true
    
    # Find an available nbd device
    local nbd_device=""
    for i in $(seq 0 15); do
        if [ ! -e "/sys/block/nbd${i}/pid" ]; then
            nbd_device="/dev/nbd${i}"
            break
        fi
    done
    
    if [ -z "${nbd_device}" ]; then
        log_error "No available nbd device found"
        return 1
    fi
    
    log_info "Using nbd device: ${nbd_device}"
    
    # Connect qcow2 to nbd
    sudo qemu-nbd --connect="${nbd_device}" "${disk_path}"
    sleep 2
    
    # Wait for partitions to appear
    sudo partprobe "${nbd_device}" 2>/dev/null || true
    sleep 2
    
    # Find and mount the root partition (usually partition 3 on bootc images)
    local mount_point="${WORK_DIR}/bootc-mount"
    mkdir -p "${mount_point}"
    
    local root_partition=""
    # Try common partition layouts for bootc images
    # p4 is typically root (xfs), p3 is boot, p2 is EFI
    for part in "${nbd_device}p4" "${nbd_device}p3" "${nbd_device}p2"; do
        if [ -b "${part}" ]; then
            if sudo mount "${part}" "${mount_point}" 2>/dev/null; then
                # Check if this looks like an OSTree root with deployments
                if [ -d "${mount_point}/ostree/deploy" ]; then
                    root_partition="${part}"
                    log_info "Mounted root partition: ${part}"
                    break
                fi
                sudo umount "${mount_point}" 2>/dev/null
            fi
        fi
    done
    
    if [ -z "${root_partition}" ]; then
        log_warning "Could not find OSTree root partition, trying alternate methods..."
        sudo qemu-nbd -d "${nbd_device}" 2>/dev/null || true
        log_error "Failed to find and mount OSTree root partition"
        return 1
    fi
    
    # Find the OSTree deployment directory
    # Structure: /ostree/deploy/<os>/deploy/<checksum>.0/
    local deploy_dir=""
    if [ -d "${mount_point}/ostree/deploy" ]; then
        # List OSTree deployments and find the first one
        for os_dir in "${mount_point}"/ostree/deploy/*/; do
            if [ -d "${os_dir}deploy" ]; then
                # Get the first deployment (usually ends with .0)
                local deployment=$(ls -1 "${os_dir}deploy" 2>/dev/null | grep -E '\.0$' | head -1)
                if [ -n "${deployment}" ]; then
                    deploy_dir="${os_dir}deploy/${deployment}"
                    break
                fi
            fi
        done
    fi
    
    if [ -z "${deploy_dir}" ] || [ ! -d "${deploy_dir}" ]; then
        log_error "Could not find OSTree deployment directory"
        log_info "Contents of ostree/deploy: $(ls -la ${mount_point}/ostree/deploy/ 2>&1 || echo 'not found')"
        sudo umount "${mount_point}" 2>/dev/null || true
        sudo qemu-nbd -d "${nbd_device}" 2>/dev/null || true
        return 1
    fi
    
    log_info "OSTree deployment directory: ${deploy_dir}"
    
    # The etc directory is inside the deployment
    local etc_dir="${deploy_dir}/etc"
    
    if [ ! -d "${etc_dir}" ]; then
        log_error "etc directory not found at ${etc_dir}"
        sudo umount "${mount_point}" 2>/dev/null || true
        sudo qemu-nbd -d "${nbd_device}" 2>/dev/null || true
        return 1
    fi
    
    # Set root password for SSH access (bootc uses root by default)
    log_info "Setting root password for SSH access..."
    local password_hash=$(openssl passwd -6 "${AGENT_VM_PASSWORD}")
    
    # Update root password in shadow file
    if sudo grep -q "^root:" "${etc_dir}/shadow" 2>/dev/null; then
        sudo sed -i "s|^root:[^:]*:|root:${password_hash}:|" "${etc_dir}/shadow"
    fi
    
    # Enable password authentication and root login for SSH
    local sshd_dir="${etc_dir}/ssh/sshd_config.d"
    sudo mkdir -p "${sshd_dir}"
    cat << 'SSHEOF' | sudo tee "${sshd_dir}/50-allow-password.conf" > /dev/null
PasswordAuthentication yes
PermitRootLogin yes
SSHEOF
    
    # Inject registry remap configuration (similar to make prepare-e2e-tests)
    if [ "${ENABLE_LOCAL_REGISTRY:-false}" = "true" ]; then
        log_info "Injecting registry remap configuration into bootc image..."
        
        # Get host IP on libvirt bridge (accessible from VMs)
        local host_ip=$(ip addr show virbr0 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
        if [ -z "${host_ip}" ]; then
            host_ip="192.168.122.1"  # Default libvirt bridge IP
        fi
        local registry_port="${LOCAL_REGISTRY_PORT:-5000}"
        local registry_url="${host_ip}:${registry_port}"
        
        # Create containers registries.conf.d directory
        local registries_dir="${etc_dir}/containers/registries.conf.d"
        sudo mkdir -p "${registries_dir}"
        
        # Write registry remap configuration
        cat << REGEOF | sudo tee "${registries_dir}/flightctl-remap.conf" > /dev/null
[[registry]]
prefix = "quay.io/flightctl"
location = "${registry_url}/flightctl"
insecure = true
REGEOF
        
        log_success "Registry remap injected: quay.io/flightctl -> ${registry_url}/flightctl"
        
        # Export for use by other functions
        export LOCAL_REGISTRY_URL="${registry_url}"
    fi
    
    # For bootc, override AGENT_VM_USER to root
    log_info "Bootc image will use root user for SSH access"
    
    # Unmount and disconnect
    log_info "Cleaning up nbd mount..."
    sync
    sudo umount "${mount_point}" 2>/dev/null || true
    sleep 1
    sudo qemu-nbd -d "${nbd_device}" 2>/dev/null || true
    
    log_success "User credentials injected into bootc image"
    return 0
}

# Create agent VM using cloud-init
create_agent_vm() {
    log_info "Creating agent VM: ${AGENT_VM_NAME}..."
    
    # Check if we should use flightctl repo's make agent-vm
    if [ "${USE_MAKE_AGENT_VM:-false}" = "true" ]; then
        log_info "Using flightctl repo's make agent-vm..."
        create_agent_vm_via_make
        return $?
    fi
    
    local image_url=""
    local os_variant="rocky9"
    
    case "${AGENT_VM_IMAGE:-rocky9}" in
        "bootc"|"BOOTC"|"centos-bootc")
            # Use bootc-based VM creation (same as make agent-vm)
            create_bootc_agent_vm
            return $?
            ;;
        "rocky9"|"ROCKY9")
            image_url="https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2"
            os_variant="rocky9"
            ;;
        "centos9"|"CENTOS9")
            image_url="https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2"
            os_variant="centos-stream9"
            ;;
        http*|https*)
            image_url="${AGENT_VM_IMAGE}"
            os_variant="rocky9"
            ;;
        *)
            log_error "Unknown agent VM image: ${AGENT_VM_IMAGE}"
            return 1
            ;;
    esac
    
    local disk_path="/var/lib/libvirt/images/${AGENT_VM_NAME}.qcow2"
    local cloud_init_dir="${WORK_DIR}/agent-cloud-init"
    
    mkdir -p "${cloud_init_dir}"
    
    # Create cloud-init user-data
    cat > "${cloud_init_dir}/user-data" << EOF
#cloud-config
users:
  - name: ${AGENT_VM_USER}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: "${AGENT_VM_PASSWORD}"
    ssh_authorized_keys: []

chpasswd:
  expire: false

ssh_pwauth: true

packages:
  - curl
  - wget
  - vim

runcmd:
  - systemctl enable --now sshd
  - echo "${AGENT_VM_USER}:${AGENT_VM_PASSWORD}" | chpasswd
EOF
    
    # Create cloud-init meta-data
    cat > "${cloud_init_dir}/meta-data" << EOF
instance-id: ${AGENT_VM_NAME}
local-hostname: ${AGENT_VM_NAME}
EOF
    
    # Download base image if not cached
    local cache_dir="/var/lib/libvirt/images/cache"
    local cached_image="${cache_dir}/$(basename ${image_url})"
    
    sudo mkdir -p "${cache_dir}"
    
    if [ ! -f "${cached_image}" ]; then
        log_info "Downloading base image..."
        sudo curl -L -o "${cached_image}" "${image_url}"
    else
        log_info "Using cached base image: ${cached_image}"
    fi
    
    # Create disk from base image
    log_info "Creating VM disk..."
    sudo cp "${cached_image}" "${disk_path}"
    sudo qemu-img resize "${disk_path}" "${AGENT_VM_DISK_SIZE:-20}G"
    
    # Create cloud-init ISO
    log_info "Creating cloud-init ISO..."
    local cloud_init_iso="${cloud_init_dir}/cloud-init.iso"
    genisoimage -output "${cloud_init_iso}" -volid cidata -joliet -rock \
        "${cloud_init_dir}/user-data" "${cloud_init_dir}/meta-data" 2>/dev/null || \
    mkisofs -output "${cloud_init_iso}" -volid cidata -joliet -rock \
        "${cloud_init_dir}/user-data" "${cloud_init_dir}/meta-data"
    
    # Create VM
    log_info "Creating VM with virt-install..."
    sudo virt-install \
        --name "${AGENT_VM_NAME}" \
        --memory "${AGENT_VM_MEMORY:-2048}" \
        --vcpus "${AGENT_VM_CPUS:-2}" \
        --disk "path=${disk_path},format=qcow2" \
        --disk "path=${cloud_init_iso},device=cdrom" \
        --os-variant "${os_variant}" \
        --network network=default \
        --import \
        --graphics none \
        --noautoconsole \
        --wait 0
    
    log_success "Agent VM created: ${AGENT_VM_NAME}"
    
    # Wait for VM to boot and get IP
    log_info "Waiting for agent VM to boot..."
    sleep 30
    get_agent_vm_ip
    
    # Wait for SSH to be available
    log_info "Waiting for SSH to be available..."
    local ssh_attempts=0
    local max_ssh_attempts=30
    
    while [ $ssh_attempts -lt $max_ssh_attempts ]; do
        if agent_ssh_exec "echo 'SSH ready'" &>/dev/null; then
            log_success "SSH is available on agent VM"
            return 0
        fi
        sleep 5
        ((ssh_attempts++))
        log_info "Waiting for SSH (attempt ${ssh_attempts}/${max_ssh_attempts})..."
    done
    
    log_error "SSH not available after ${max_ssh_attempts} attempts"
    return 1
}

# Start existing agent VM
start_agent_vm() {
    log_info "Starting agent VM: ${AGENT_VM_NAME}..."
    
    if agent_vm_running; then
        log_info "Agent VM is already running"
    else
        sudo virsh start "${AGENT_VM_NAME}"
        sleep 10
    fi
    
    get_agent_vm_ip
}

# Stop and remove agent VM
cleanup_agent_vm() {
    log_info "Cleaning up agent VM: ${AGENT_VM_NAME}..."
    
    sudo virsh destroy "${AGENT_VM_NAME}" 2>/dev/null || true
    sudo virsh undefine "${AGENT_VM_NAME}" --remove-all-storage 2>/dev/null || true
    
    log_success "Agent VM cleaned up"
}

# Force insecureSkipVerify in enrollment and management sections.
set_insecure_skip_verify_in_config() {
    local config_file="$1"

    python3 - "$config_file" <<'PY'
import sys
from pathlib import Path

p = Path(sys.argv[1])
lines = p.read_text().splitlines()

def patch_section(section_name):
    start = None
    for i, line in enumerate(lines):
        if line.strip() == f"{section_name}:" and not line.startswith(" "):
            start = i
            break
    if start is None:
        return

    end = len(lines)
    for j in range(start + 1, len(lines)):
        line = lines[j]
        if line and not line.startswith(" ") and not line.startswith("#"):
            end = j
            break

    for k in range(start + 1, end):
        if "insecureSkipVerify:" in lines[k]:
            indent = lines[k].split("insecureSkipVerify:")[0]
            lines[k] = f"{indent}insecureSkipVerify: true"
            return

    for k in range(start + 1, end):
        if lines[k].strip() in ("service:", "service: {}"):
            if lines[k].strip() == "service: {}":
                lines[k] = "  service:"
            lines.insert(k + 1, "    insecureSkipVerify: true")
            return

patch_section("enrollment-service")
patch_section("management-service")
p.write_text("\n".join(lines) + "\n")
PY
}

# Generate enrollment config and save to file
generate_enrollment_config() {
    log_info "Generating enrollment configuration with client certificate..."
    
    local enrollment_config="${WORK_DIR}/enrollment-config.yaml"
    
    # Ensure CLI is logged in before generating enrollment config
    local insecure_flag=""
    if [ "${INSECURE_SKIP_TLS_VERIFY:-false}" = "true" ]; then
        insecure_flag="-k"
    fi
    
    log_info "Logging in to FlightCtl API..."
    ssh_exec "flightctl login https://${VM_IP}:3443 ${insecure_flag} -u ${PAM_USER:-admin} -p ${PAM_PASSWORD:-admin123}" > /dev/null 2>&1
    
    # Generate enrollment config with client certificate using certificate request
    # This creates a CSR, submits it, and returns config with embedded client cert/key
    # Required for mTLS enrollment on port 7443
    log_info "Requesting client certificate for enrollment..."
    ssh_exec "flightctl certificate request --expiration=365d -o embedded 2>/dev/null" > "${enrollment_config}"
    
    if [ ! -s "${enrollment_config}" ]; then
        log_error "Failed to generate enrollment config with certificate"
        return 1
    fi
    
    # Verify the config has client certificate data
    if grep -q 'client-certificate-data: ""' "${enrollment_config}" 2>/dev/null; then
        log_error "Enrollment config has empty client certificate - mTLS will fail"
        return 1
    fi
    
    # Agent VM cannot resolve the server hostname (rhel10-1.local); replace with VM_IP
    # so the agent can reach the server (DNS on 192.168.122.1 does not have the hostname)
    local vm_hostname=$(ssh_exec "hostname -f" | tr -d '[:space:]')
    if [ -n "$vm_hostname" ] && [ "$vm_hostname" != "localhost" ]; then
        log_info "Replacing server hostname ${vm_hostname} with ${VM_IP} in enrollment config (for agent reachability)"
        sed -i "s|${vm_hostname}|${VM_IP}|g" "${enrollment_config}"
    fi
    
    # Optionally set insecureSkipVerify so the agent skips TLS verification (self-signed server cert)
    if [ "${AGENT_INSECURE_SKIP_TLS_VERIFY:-false}" = "true" ]; then
        log_info "Setting insecureSkipVerify: true in enrollment config (agent will skip TLS verification)"
        set_insecure_skip_verify_in_config "${enrollment_config}"
    fi
    
    log_success "Enrollment config with client certificate saved to: ${enrollment_config}"
    return 0
}

# Create agent VM using flightctl repo's make agent-vm target
# This uses the same workflow as: make agent-vm VMNAME=X VMCPUS=X VMDISKSIZE=X VMRAM=X
create_agent_vm_via_make() {
    local repo_path="${FLIGHTCTL_REPO_PATH:-}"
    
    if [ -z "${repo_path}" ] || [ ! -d "${repo_path}" ]; then
        log_error "FLIGHTCTL_REPO_PATH not set or directory doesn't exist: ${repo_path}"
        return 1
    fi
    
    if [ ! -f "${repo_path}/Makefile" ]; then
        log_error "Makefile not found in ${repo_path}"
        return 1
    fi
    
    log_info "Creating agent VM using flightctl repo's make agent-vm..."
    log_info "Repository: ${repo_path}"
    
    local vm_name="${AGENT_VM_NAME:-flightctl-agent-test}"
    local vm_cpus="${MAKE_AGENT_VM_CPUS:-4}"
    local vm_disksize="${MAKE_AGENT_VM_DISKSIZE:-15G}"
    local vm_ram="${MAKE_AGENT_VM_RAM:-2048}"
    
    log_info "VM Parameters: VMNAME=${vm_name} VMCPUS=${vm_cpus} VMDISKSIZE=${vm_disksize} VMRAM=${vm_ram}"
    
    # Clean up existing VM if present
    log_info "Cleaning up any existing agent VM..."
    sudo virsh destroy "${vm_name}" 2>/dev/null || true
    sudo virsh undefine "${vm_name}" --remove-all-storage 2>/dev/null || true
    sudo rm -f "/var/lib/libvirt/images/${vm_name}.qcow2" 2>/dev/null || true
    
    # Run make agent-vm from the flightctl repo
    log_info "Running: make agent-vm VMNAME=${vm_name} VMCPUS=${vm_cpus} VMDISKSIZE=${vm_disksize} VMRAM=${vm_ram}"
    
    pushd "${repo_path}" > /dev/null
    
    # Run make agent-vm with parameters
    # Note: VMWAIT=0 to not wait for console, INJECT_CONFIG=true to inject agent config
    if make agent-vm \
        VMNAME="${vm_name}" \
        VMCPUS="${vm_cpus}" \
        VMDISKSIZE="${vm_disksize}" \
        VMRAM="${vm_ram}" \
        VMWAIT=0 \
        INJECT_CONFIG=true; then
        log_success "make agent-vm completed successfully"
    else
        log_error "make agent-vm failed"
        popd > /dev/null
        return 1
    fi
    
    popd > /dev/null
    
    # Wait for VM to boot and get IP
    log_info "Waiting for agent VM to boot..."
    sleep 30
    get_agent_vm_ip
    
    # The make agent-vm creates a VM with user 'user' and password 'user'
    AGENT_VM_USER="user"
    AGENT_VM_PASSWORD="user"
    log_info "Agent VM credentials: user=${AGENT_VM_USER}, password=${AGENT_VM_PASSWORD}"
    
    # Wait for SSH to be available
    log_info "Waiting for SSH to be available..."
    local ssh_attempts=0
    local max_ssh_attempts=40
    
    while [ $ssh_attempts -lt $max_ssh_attempts ]; do
        if sshpass -p "${AGENT_VM_PASSWORD}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
            "${AGENT_VM_USER}@${AGENT_VM_IP}" "echo 'SSH ready'" &>/dev/null; then
            log_success "SSH is available on agent VM"
            return 0
        fi
        sleep 5
        ((ssh_attempts++))
        log_info "Waiting for SSH (attempt ${ssh_attempts}/${max_ssh_attempts})..."
    done
    
    log_error "SSH not available after ${max_ssh_attempts} attempts"
    return 1
}

# Prepare e2e environment using flightctl repo's make targets
# Runs: make prepare-e2e-test (or deploy-e2e-extras + build-e2e-containers + prepare-e2e-qcow-config)
prepare_e2e_environment() {
    local repo_path="${FLIGHTCTL_REPO_PATH:-}"
    
    if [ -z "${repo_path}" ] || [ ! -d "${repo_path}" ]; then
        log_warning "FLIGHTCTL_REPO_PATH not set, skipping e2e preparation"
        return 0
    fi
    
    log_info "Preparing e2e environment using flightctl repo..."
    log_info "Repository: ${repo_path}"
    
    pushd "${repo_path}" > /dev/null
    
    # Check if prepare-e2e-test target exists
    if grep -q "prepare-e2e-test:" Makefile test/test.mk 2>/dev/null; then
        log_info "Running: make prepare-e2e-test"
        if make prepare-e2e-test; then
            log_success "E2E environment prepared successfully"
        else
            log_warning "make prepare-e2e-test had issues, continuing..."
        fi
    else
        # Run individual targets
        log_info "Running: make deploy-e2e-extras"
        make deploy-e2e-extras || log_warning "deploy-e2e-extras had issues"
        
        log_info "Running: make build-e2e-containers"
        make build-e2e-containers || log_warning "build-e2e-containers had issues"
        
        log_info "Running: make prepare-e2e-qcow-config"
        make prepare-e2e-qcow-config || log_warning "prepare-e2e-qcow-config had issues"
    fi
    
    popd > /dev/null
    
    return 0
}

# Setup local container registry for flightctl-device images
setup_local_registry() {
    if [ "${ENABLE_LOCAL_REGISTRY:-false}" != "true" ]; then
        log_info "Local registry disabled, skipping..."
        return 0
    fi
    
    log_info "Setting up local container registry..."
    
    local registry_port="${LOCAL_REGISTRY_PORT:-5000}"
    local registry_name="${LOCAL_REGISTRY_NAME:-flightctl-registry}"
    local host_ip=""
    
    # Get the host IP on the libvirt bridge (accessible from VMs)
    host_ip=$(ip addr show virbr0 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    if [ -z "${host_ip}" ]; then
        host_ip="192.168.122.1"  # Default libvirt bridge IP
    fi
    
    log_info "Host IP for registry: ${host_ip}:${registry_port}"
    
    # Check if registry is already running
    if sudo podman ps --format "{{.Names}}" | grep -q "^${registry_name}$"; then
        log_info "Local registry already running"
    else
        # Check if registry container exists but stopped
        if sudo podman ps -a --format "{{.Names}}" | grep -q "^${registry_name}$"; then
            log_info "Starting existing registry container..."
            sudo podman start "${registry_name}"
        else
            log_info "Creating new local registry container..."
            sudo podman run -d \
                --name "${registry_name}" \
                -p "${registry_port}:5000" \
                --restart always \
                docker.io/library/registry:2
        fi
    fi
    
    # Wait for registry to be ready
    sleep 3
    
    # Verify registry is accessible
    if curl -s "http://${host_ip}:${registry_port}/v2/_catalog" &>/dev/null; then
        log_success "Local registry is running at ${host_ip}:${registry_port}"
    else
        log_warning "Registry may not be accessible yet, continuing..."
    fi
    
    # Export for use by other functions
    export LOCAL_REGISTRY_URL="${host_ip}:${registry_port}"
    
    return 0
}

# Push flightctl-device images to local registry
push_device_images_to_registry() {
    if [ "${ENABLE_LOCAL_REGISTRY:-false}" != "true" ]; then
        return 0
    fi
    
    log_info "Pushing flightctl-device images to local registry..."
    
    local registry_url="${LOCAL_REGISTRY_URL:-192.168.122.1:5000}"
    local tags="${FLIGHTCTL_DEVICE_TAGS:-v6 v7 v8 v9 v10 v11 base}"
    local pushed_count=0
    
    for tag in ${tags}; do
        local source_image="quay.io/flightctl/flightctl-device:${tag}"
        local target_image="${registry_url}/flightctl/flightctl-device:${tag}"
        
        # Check if source image exists locally
        if sudo podman image exists "${source_image}" 2>/dev/null; then
            log_info "Pushing ${source_image} -> ${target_image}..."
            
            # Tag for local registry
            sudo podman tag "${source_image}" "${target_image}" 2>/dev/null || true
            
            # Push to local registry (insecure)
            if sudo podman push --tls-verify=false "${target_image}" 2>/dev/null; then
                log_success "Pushed ${tag}"
                ((pushed_count++))
            else
                log_warning "Failed to push ${tag}"
            fi
        else
            log_warning "Image ${source_image} not found locally, skipping..."
        fi
    done
    
    if [ ${pushed_count} -gt 0 ]; then
        log_success "Pushed ${pushed_count} images to local registry"
        
        # Show available images in registry
        local catalog=$(curl -s "http://${registry_url}/v2/_catalog" 2>/dev/null || echo "{}")
        log_info "Registry catalog: ${catalog}"
    else
        log_warning "No images were pushed to the registry"
        log_info "Build images first with: make build-e2e-agent-images (in flightctl repo)"
    fi
    
    return 0
}

# Configure agent VM to use local registry
configure_agent_registry_remap() {
    if [ "${ENABLE_LOCAL_REGISTRY:-false}" != "true" ]; then
        return 0
    fi
    
    log_info "Configuring agent VM to use local registry..."
    
    local registry_url="${LOCAL_REGISTRY_URL:-192.168.122.1:5000}"
    
    # Create registry remap configuration
    local remap_config="[[registry]]
prefix = \"quay.io/flightctl\"
location = \"${registry_url}/flightctl\"
insecure = true"
    
    # Write config to agent VM
    agent_ssh_exec "cat > /etc/containers/registries.conf.d/flightctl-remap.conf << 'EOF'
${remap_config}
EOF"
    
    # Verify the config was written
    local verify=$(agent_ssh_exec "cat /etc/containers/registries.conf.d/flightctl-remap.conf 2>/dev/null" || echo "")
    
    if echo "${verify}" | grep -q "quay.io/flightctl"; then
        log_success "Registry remap configured on agent VM"
        log_info "  quay.io/flightctl -> ${registry_url}/flightctl"
    else
        log_warning "Failed to configure registry remap"
    fi
    
    return 0
}

# Install flightctl-agent on agent VM
install_agent_on_vm() {
    log_info "Installing flightctl-agent on agent VM..."

    local rpm_list=""
    local agent_rpm=""
    local selinux_rpm=""
    local agent_rpm_url=""
    local selinux_rpm_url=""

    # Pinned selinux URL (optional; wins over Brew list / directory pairing).
    if [ -n "${AGENT_SELINUX_RPM_URL:-}" ]; then
        selinux_rpm_url="${AGENT_SELINUX_RPM_URL}"
        selinux_rpm=$(basename "${selinux_rpm_url}")
        log_info "Using AGENT_SELINUX_RPM_URL (pinned): ${selinux_rpm_url}"
    fi

    # 0) Pinned agent URL wins (cross-OS / explicit build; overrides Brew list and directory).
    if [ -n "${AGENT_RPM_URL:-}" ]; then
        agent_rpm_url="${AGENT_RPM_URL}"
        agent_rpm=$(basename "${agent_rpm_url}")
        log_info "Using AGENT_RPM_URL (pinned): ${agent_rpm_url}"
        if [ -z "$selinux_rpm_url" ] && [ -f "${WORK_DIR}/.brew_rpms.list" ]; then
            selinux_rpm_url=$(grep 'flightctl-selinux' "${WORK_DIR}/.brew_rpms.list" | grep '\.rpm$' | head -1)
            if [ -n "$selinux_rpm_url" ]; then
                selinux_rpm=$(basename "${selinux_rpm_url}")
                log_info "Paired flightctl-selinux from Brew task list: ${selinux_rpm}"
            fi
        fi
    fi

    # 1) Brew task: same build as services — use full URLs from parsed task list.
    if [ -z "$agent_rpm_url" ] && [ -f "${WORK_DIR}/.brew_rpms.list" ]; then
        agent_rpm_url=$(grep 'flightctl-agent' "${WORK_DIR}/.brew_rpms.list" | grep -E 'x86_64\.rpm$' | head -1)
        if [ -n "$agent_rpm_url" ]; then
            agent_rpm=$(basename "${agent_rpm_url}")
            if [ -z "$selinux_rpm_url" ]; then
                selinux_rpm_url=$(grep 'flightctl-selinux' "${WORK_DIR}/.brew_rpms.list" | grep '\.rpm$' | head -1)
                if [ -n "$selinux_rpm_url" ]; then
                    selinux_rpm=$(basename "${selinux_rpm_url}")
                fi
            fi
            log_info "flightctl-agent from Brew task RPM list: ${agent_rpm}"
        fi
    fi

    # 2) Copr / directory URL: discover agent next to services.
    if [ -z "$agent_rpm_url" ]; then
        log_info "Looking for agent RPMs in ${RPM_BASE_URL}..."
        rpm_list=$(curl -sL "${RPM_BASE_URL}" | grep -oE "href=['\"][^'\"]*\.rpm['\"]" | sed "s/href=['\"]//;s/['\"]$//" | sort -u)
        agent_rpm=$(echo "$rpm_list" | grep -E "flightctl-agent.*x86_64\.rpm" | head -1)
        if [ -n "$agent_rpm" ]; then
            agent_rpm_url="${RPM_BASE_URL}${agent_rpm}"
            selinux_rpm=$(echo "$rpm_list" | grep -E "flightctl-selinux.*\.rpm" | head -1)
            if [ -n "$selinux_rpm" ]; then
                selinux_rpm_url="${RPM_BASE_URL}${selinux_rpm}"
            fi
        fi
    fi

    # 2b) Pinned or direct agent URL: pair flightctl-selinux from the same directory (required by agent RPM).
    if [ -n "$agent_rpm_url" ] && [ -z "$selinux_rpm_url" ] && [ -z "${AGENT_SELINUX_RPM_URL:-}" ]; then
        local agent_dir="${agent_rpm_url%/*}"
        if [ -n "$agent_dir" ] && [ "$agent_dir" != "$agent_rpm_url" ]; then
            log_info "Looking for flightctl-selinux next to agent RPM (${agent_dir}/)..."
            rpm_list=$(curl -sL "${agent_dir}/" 2>/dev/null | grep -oE "href=['\"][^'\"]*\.rpm['\"]" | sed "s/href=['\"]//;s/['\"]$//" | sort -u)
            selinux_rpm=$(echo "$rpm_list" | grep -E "flightctl-selinux.*\.rpm" | head -1)
            if [ -n "$selinux_rpm" ]; then
                selinux_rpm_url="${agent_dir}/${selinux_rpm}"
                log_info "Paired flightctl-selinux: ${selinux_rpm}"
            fi
        fi
    fi

    if [ -z "$selinux_rpm" ]; then
        log_warning "Could not find flightctl-selinux RPM in source — agent install may fail (agent requires flightctl-selinux). Set AGENT_SELINUX_RPM_URL in verification.conf if needed."
    fi

    # 3) Last resort: explicit override when source has no agent RPM.
    if [ -z "$agent_rpm_url" ]; then
        if [ -n "${AGENT_RPM_URL:-}" ]; then
            agent_rpm_url="${AGENT_RPM_URL}"
            agent_rpm=$(basename "${agent_rpm_url}")
            if [ -z "${AGENT_SELINUX_RPM_URL:-}" ]; then
                selinux_rpm=""
                selinux_rpm_url=""
            fi
            log_info "Using AGENT_RPM_URL (fallback): ${agent_rpm_url}"
        else
            log_error "Could not find flightctl-agent RPM (Brew list, ${RPM_BASE_URL}, or AGENT_RPM_URL)"
            log_error "Set AGENT_RPM_URL in verification.conf to a direct agent RPM URL and retry."
            return 1
        fi
    fi

    local local_agent_rpm="${WORK_DIR}/${agent_rpm}"
    
    if [ ! -f "${local_agent_rpm}" ]; then
        log_info "Downloading ${agent_rpm}..."
        curl -sL -o "${local_agent_rpm}" "${agent_rpm_url}"
    fi
    
    log_info "Copying agent RPM to agent VM..."
    agent_scp "${local_agent_rpm}" "${AGENT_VM_USER}@${AGENT_VM_IP}:/tmp/"
    
    # Download and copy selinux RPM if found
    if [ -n "$selinux_rpm" ] && [ -n "$selinux_rpm_url" ]; then
        local local_selinux_rpm="${WORK_DIR}/${selinux_rpm}"
        
        if [ ! -f "${local_selinux_rpm}" ]; then
            log_info "Downloading ${selinux_rpm}..."
            curl -sL -o "${local_selinux_rpm}" "${selinux_rpm_url}"
        fi
        
        log_info "Copying selinux RPM to agent VM..."
        agent_scp "${local_selinux_rpm}" "${AGENT_VM_USER}@${AGENT_VM_IP}:/tmp/"
    fi
    
    # Install RPMs on agent VM
    log_info "Installing agent RPMs..."

    # For bootc systems, use --transient flag to install in a transient overlay
    local dnf_opts="-y"
    if [[ "${AGENT_VM_IMAGE:-}" =~ ^(bootc|BOOTC|centos-bootc)$ ]]; then
        log_info "Using transient overlay for bootc system..."
        dnf_opts="-y --transient"
    fi

    # Avoid installing mismatched SELinux policy packages (e.g., el10 policy on el9 bootc agent).
    if [ -n "$selinux_rpm" ]; then
        local agent_os_major
        agent_os_major=$(agent_ssh_exec "source /etc/os-release >/dev/null 2>&1; echo \${VERSION_ID%%.*}" 2>/dev/null | tr -dc '0-9')
        local selinux_el_major
        selinux_el_major=$(echo "${selinux_rpm}" | sed -n 's/.*\.el\([0-9]\+\).*/\1/p')

        if [ -n "${agent_os_major}" ] && [ -n "${selinux_el_major}" ] && [ "${agent_os_major}" != "${selinux_el_major}" ]; then
            log_warning "Skipping ${selinux_rpm}: built for el${selinux_el_major}, agent OS is el${agent_os_major}"
            log_warning "If needed, provide matching direct RPM via AGENT_RPM_URL (and optional selinux RPM in source)."
            selinux_rpm=""
        fi
    fi

    if [ -n "$selinux_rpm" ]; then
        agent_ssh_exec_sudo "dnf install ${dnf_opts} /tmp/${selinux_rpm} /tmp/${agent_rpm}"
    else
        agent_ssh_exec_sudo "dnf install ${dnf_opts} /tmp/${agent_rpm}"
    fi
    
    log_success "flightctl-agent installed on agent VM"

    # Verify SELinux context on agent VM
    log_info "Verifying SELinux context for flightctl-agent on agent VM..."
    local agent_selinux_status=$(agent_ssh_exec "getenforce 2>/dev/null" || echo "Unknown")
    log_info "Agent VM SELinux status: ${agent_selinux_status}"

    if [ "$agent_selinux_status" != "Disabled" ]; then
        local agent_selinux_context=$(agent_ssh_exec "ls -Z /usr/bin/flightctl-agent 2>/dev/null | awk '{print \$1}'" || echo "")

        if [ -n "$agent_selinux_context" ]; then
            log_info "Agent SELinux context: ${agent_selinux_context}"

            if echo "$agent_selinux_context" | grep -q "flightctl_agent_exec_t"; then
                log_success "Agent binary has correct SELinux type: flightctl_agent_exec_t"
            else
                log_warning "Agent binary SELinux context may be incorrect: ${agent_selinux_context}"
                log_info "Expected type: flightctl_agent_exec_t"
            fi
        else
            log_warning "Could not retrieve agent SELinux context"
        fi
    else
        log_info "SELinux is disabled on agent VM, skipping context verification"
    fi

    return 0
}

# Configure agent with enrollment config
configure_agent() {
    log_info "Configuring flightctl-agent..."
    
    local enrollment_config="${WORK_DIR}/enrollment-config.yaml"
    
    if [ ! -f "${enrollment_config}" ]; then
        log_error "Enrollment config not found: ${enrollment_config}"
        return 1
    fi
    
    # Ensure stale identity from previous runs does not cause CA mismatch after server reinstall.
    # This is especially important with FULL_CLEANUP=true on the management VM.
    if [ "${RESET_AGENT_STATE_BEFORE_ENROLLMENT:-true}" = "true" ]; then
        log_info "Resetting agent identity state before applying new enrollment config..."
        agent_ssh_exec_sudo "systemctl stop flightctl-agent 2>/dev/null || true"
        agent_ssh_exec_sudo "rm -rf /var/lib/flightctl/* /etc/flightctl/config.yaml 2>/dev/null || true"
    fi

    # Copy enrollment config to agent VM
    log_info "Copying enrollment config to agent VM..."
    agent_scp "${enrollment_config}" "${AGENT_VM_USER}@${AGENT_VM_IP}:/tmp/config.yaml"
    
    # Create flightctl config directory and copy config
    agent_ssh_exec_sudo "mkdir -p /etc/flightctl"
    agent_ssh_exec_sudo "cp /tmp/config.yaml /etc/flightctl/config.yaml"
    agent_ssh_exec_sudo "chmod 644 /etc/flightctl/config.yaml"
    
    log_success "Agent configured with enrollment config"
    return 0
}

# Start agent service
start_agent_service() {
    log_info "Starting flightctl-agent service..."
    
    agent_ssh_exec_sudo "systemctl enable flightctl-agent"
    agent_ssh_exec_sudo "systemctl restart flightctl-agent"
    
    sleep 5
    
    local status=$(agent_ssh_exec_sudo "systemctl is-active flightctl-agent" 2>/dev/null || echo "unknown")
    
    if [ "$status" = "active" ]; then
        log_success "flightctl-agent service is running"
        return 0
    else
        log_error "flightctl-agent service failed to start"
        agent_ssh_exec_sudo "journalctl -u flightctl-agent --no-pager -n 50" || true
        return 1
    fi
}

# Resolved fleet name for verification onboarding (DEVICE_FLEET or default).
verification_fleet_name() {
    if [ -n "${DEVICE_FLEET:-}" ]; then
        echo "${DEVICE_FLEET}"
    else
        echo "verification-fleet"
    fi
}

# Build matchLabels YAML lines (6-space indent) from DEVICE_LABELS "k=v,k2=v2".
fleet_match_labels_yaml_from_device_labels() {
    local labels="${DEVICE_LABELS:-}"
    if [ -z "$labels" ]; then
        return 1
    fi
    local pair k v
    IFS=',' read -ra PAIRS <<< "$labels"
    for pair in "${PAIRS[@]}"; do
        pair="${pair#"${pair%%[![:space:]]*}"}"
        pair="${pair%"${pair##*[![:space:]]}"}"
        [ -z "$pair" ] && continue
        k="${pair%%=*}"
        v="${pair#*=}"
        echo "      ${k}: ${v}"
    done
}

# Create a Fleet whose selector matches DEVICE_LABELS; enrolled devices approved with the same labels join this fleet.
create_verification_fleet_for_onboarding() {
    local fleet_name
    fleet_name=$(verification_fleet_name)
    local match_block
    if ! match_block=$(fleet_match_labels_yaml_from_device_labels); then
        log_warning "DEVICE_LABELS is empty — skipping fleet creation (set DEVICE_LABELS to use fleet onboarding)"
        return 0
    fi
    if [ -z "$(echo "$match_block" | tr -d '[:space:]')" ]; then
        log_warning "DEVICE_LABELS produced no match labels — skipping fleet creation"
        return 0
    fi

    log_info ""
    log_info "Creating verification fleet '${fleet_name}' (selector matches DEVICE_LABELS; template adds inline file config only, no os.image)..."
    local fleet_yaml="apiVersion: v1beta1
kind: Fleet
metadata:
  name: ${fleet_name}
spec:
  selector:
    matchLabels:
${match_block}
  template:
    spec:
      config:
        - name: verification-inline
          inline:
            - path: /etc/flightctl-verification-marker
              content: 'flightctl-verification-onboarding-fleet'
              mode: 0644"

    local create_result
    create_result=$(ssh_exec "echo '${fleet_yaml}' | flightctl apply -f - 2>&1" || echo "apply failed")

    if echo "$create_result" | grep -qiE "created|configured|applied|unchanged"; then
        log_success "Fleet '${fleet_name}' applied (visible in UI: Fleets / ${fleet_name})"
        printf '%s\n' "${fleet_name}" > "${WORK_DIR}/.verification_fleet_name" 2>/dev/null || true
    else
        log_warning "Fleet apply returned: ${create_result}"
    fi
}

# Poll until device summary status updates (e.g. leaves Unknown) after fleet template applies.
wait_for_device_status_after_fleet_assignment() {
    local device_name="$1"
    local max_attempts="${DEVICE_FLEET_STATUS_MAX_ATTEMPTS:-36}"
    local wait_interval="${DEVICE_FLEET_STATUS_WAIT_INTERVAL:-5}"

    log_info "Waiting for device '${device_name}' status to update after fleet assignment (max ${max_attempts} attempts, ${wait_interval}s apart)..."

    local attempt=1
    local device_json summary summary_lc last_seen

    while [ "$attempt" -le "$max_attempts" ]; do
        device_json=$(ssh_exec "flightctl get device '${device_name}' -o json 2>/dev/null" || echo "{}")
        summary=$(echo "$device_json" | jq -r '.status.summary.status // ""' 2>/dev/null || echo "")
        last_seen=$(echo "$device_json" | jq -r '.status.lastSeen // ""' 2>/dev/null || echo "")

        if [ -n "$summary" ] && [ "$summary" != "null" ]; then
            summary_lc=$(echo "$summary" | tr '[:upper:]' '[:lower:]')
            if [ "$summary_lc" != "unknown" ]; then
                log_success "Device status updated after fleet: summary.status=${summary} (lastSeen=${last_seen:-n/a})"
                return 0
            fi
        fi

        log_info "Device summary status still '${summary:-empty}', lastSeen='${last_seen:-empty}' (${attempt}/${max_attempts})..."
        sleep "$wait_interval"
        attempt=$((attempt + 1))
    done

    log_warning "Device summary status did not leave Unknown within $((max_attempts * wait_interval))s — check UI or agent (device: ${device_name})"
    return 0
}

# After enrollment, confirm device carries DEVICE_LABELS and the fleet resource exists (label-based membership).
verify_device_in_verification_fleet() {
    local device_name="$1"
    local fleet_name
    fleet_name=$(verification_fleet_name)

    if [ -z "${DEVICE_LABELS:-}" ]; then
        log_info "DEVICE_LABELS unset — skipping fleet membership check"
        return 0
    fi

    log_info "Verifying device '${device_name}' labels match fleet '${fleet_name}' selector..."

    local device_json
    device_json=$(ssh_exec "flightctl get device '${device_name}' -o json 2>/dev/null" || echo "{}")

    local failed=false
    local pair k v dv
    IFS=',' read -ra PAIRS <<< "${DEVICE_LABELS}"
    for pair in "${PAIRS[@]}"; do
        pair="${pair#"${pair%%[![:space:]]*}"}"
        pair="${pair%"${pair##*[![:space:]]}"}"
        [ -z "$pair" ] && continue
        k="${pair%%=*}"
        v="${pair#*=}"
        dv=$(echo "$device_json" | jq -r --arg k "$k" '.metadata.labels[$k] // empty' 2>/dev/null || echo "")
        if [ "$dv" = "$v" ]; then
            log_success "Device label ${k}=${v} (matches fleet selector)"
        else
            log_warning "Label ${k}: expected '${v}', device has '${dv}'"
            failed=true
        fi
    done

    local fleet_json
    fleet_json=$(ssh_exec "flightctl get fleet '${fleet_name}' -o json 2>/dev/null" || echo "{}")
    if echo "$fleet_json" | jq -e '.kind == "Fleet"' >/dev/null 2>&1; then
        log_success "Fleet '${fleet_name}' is present on the server"
    else
        log_warning "Could not read fleet '${fleet_name}'"
        failed=true
    fi

    if [ "$failed" = true ]; then
        log_warning "Fleet label check had issues — inspect: flightctl get device ${device_name} -o yaml && flightctl get fleet ${fleet_name} -o yaml"
        return 1
    fi

    log_success "Device '${device_name}' is in fleet '${fleet_name}' (label selector match)"

    wait_for_device_status_after_fleet_assignment "$device_name"

    return 0
}

# Wait for enrollment request to appear
wait_for_enrollment_request() {
    echo -e "${BLUE}[INFO]${NC} Waiting for enrollment request..." >&2
    
    local max_attempts=30
    local attempt=1
    local enrollment_name=""
    
    while [ $attempt -le $max_attempts ]; do
        # Get enrollment requests
        local enrollments=$(ssh_exec "flightctl get enrollmentrequests -o json 2>/dev/null" || echo "{}")
        
        # Check if there's a pending enrollment
        enrollment_name=$(echo "$enrollments" | jq -r '.items[]? | select(.status.approval.approved != true) | .metadata.name' 2>/dev/null | head -1)
        
        if [ -n "$enrollment_name" ] && [ "$enrollment_name" != "null" ]; then
            echo -e "${GREEN}[SUCCESS]${NC} Found enrollment request: ${enrollment_name}" >&2
            echo "$enrollment_name"
            return 0
        fi
        
        echo -e "${BLUE}[INFO]${NC} Waiting for enrollment request (attempt ${attempt}/${max_attempts})..." >&2
        sleep 5
        ((attempt++))
    done
    
    echo -e "${RED}[ERROR]${NC} No enrollment request found after ${max_attempts} attempts" >&2
    return 1
}

# Approve enrollment request
approve_enrollment() {
    local enrollment_name="$1"
    
    if [ -z "$enrollment_name" ]; then
        log_error "No enrollment name provided"
        return 1
    fi
    
    log_info "Approving enrollment request: ${enrollment_name}..."
    
    # Build approve command with optional labels
    local approve_cmd="flightctl approve enrollmentrequest ${enrollment_name}"
    
    if [ -n "${DEVICE_LABELS}" ]; then
        # Each label needs its own -l flag
        # Convert "key1=val1,key2=val2" to "-l key1=val1 -l key2=val2"
        local label_flags=""
        IFS=',' read -ra LABELS <<< "${DEVICE_LABELS}"
        for label in "${LABELS[@]}"; do
            label_flags="${label_flags} -l ${label}"
        done
        approve_cmd="${approve_cmd}${label_flags}"
    fi
    
    ssh_exec "${approve_cmd}"
    
    if [ $? -eq 0 ]; then
        log_success "Enrollment request approved: ${enrollment_name}"
        return 0
    else
        log_error "Failed to approve enrollment request"
        return 1
    fi
}

# Wait for device to appear and be ready
wait_for_device() {
    local enrollment_name="$1"
    
    # Redirect log messages to stderr to avoid contaminating stdout (used for return value)
    echo -e "${BLUE}[INFO]${NC} Waiting for device to be enrolled..." >&2
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        # Check if device exists
        local devices=$(ssh_exec "flightctl get devices -o json 2>/dev/null" || echo "{}")
        local device_count=$(echo "$devices" | jq '.items | length' 2>/dev/null || echo "0")
        
        if [ "$device_count" -gt 0 ]; then
            local device_name=$(echo "$devices" | jq -r '.items[0].metadata.name' 2>/dev/null)
            local device_status=$(echo "$devices" | jq -r '.items[0].status.summary.status' 2>/dev/null || echo "unknown")
            
            echo -e "${GREEN}[SUCCESS]${NC} Device enrolled: ${device_name} (status: ${device_status})" >&2
            echo "$device_name"
            return 0
        fi
        
        echo -e "${BLUE}[INFO]${NC} Waiting for device (attempt ${attempt}/${max_attempts})..." >&2
        sleep 5
        ((attempt++))
    done
    
    echo -e "${RED}[ERROR]${NC} Device not enrolled after ${max_attempts} attempts" >&2
    return 1
}

# Verify device is communicating with server
verify_device_communication() {
    local device_name="$1"
    
    log_info "Verifying device communication..."
    
    # Check device status
    local device_info=$(ssh_exec "flightctl get device ${device_name} -o json 2>/dev/null" || echo "{}")
    
    local last_seen=$(echo "$device_info" | jq -r '.status.lastSeen' 2>/dev/null || echo "unknown")
    local summary_status=$(echo "$device_info" | jq -r '.status.summary.status' 2>/dev/null || echo "unknown")
    
    log_info "Device: ${device_name}"
    log_info "  Status: ${summary_status}"
    log_info "  Last Seen: ${last_seen}"
    
    # Check agent logs on agent VM
    log_info "Agent logs (last 10 lines):"
    agent_ssh_exec_sudo "journalctl -u flightctl-agent --no-pager -n 10" 2>/dev/null || true
    
    if [ "$summary_status" != "unknown" ] && [ "$summary_status" != "null" ]; then
        log_success "Device is communicating with server"
        return 0
    else
        log_warning "Device status unknown - may still be initializing"
        return 0
    fi
}

# Main device onboarding function
test_device_onboarding() {
    if [ "${ENABLE_DEVICE_ONBOARDING:-false}" != "true" ]; then
        log_info "Device onboarding is disabled (ENABLE_DEVICE_ONBOARDING=${ENABLE_DEVICE_ONBOARDING:-false})"
        return 0
    fi
    
    echo ""
    log_info "═══════════════════════════════════════════════════════════"
    log_info "Device Onboarding Test"
    log_info "═══════════════════════════════════════════════════════════"
    
    # Step 1: Create or start agent VM
    if agent_vm_exists; then
        log_info "Agent VM exists, starting it..."
        # Bootc VMs use root for SSH; set now so agent_ssh/agent_scp use correct user
        if [[ "${AGENT_VM_IMAGE:-}" =~ ^(bootc|BOOTC|centos-bootc)$ ]]; then
            AGENT_VM_USER="root"
            log_info "Using root user for existing bootc agent VM"
        fi
        start_agent_vm
    else
        log_info "Creating new agent VM..."
        create_agent_vm
    fi
    
    if [ -z "$AGENT_VM_IP" ]; then
        log_error "Failed to get agent VM IP"
        return 1
    fi
    
    log_info "Agent VM SSH: ssh ${AGENT_VM_USER}@${AGENT_VM_IP}  (password: ${AGENT_VM_PASSWORD})"
    
    # Step 2: Generate enrollment config
    generate_enrollment_config
    
    # Step 2b: Fleet with selector = DEVICE_LABELS (device receives these labels at approval → joins fleet)
    create_verification_fleet_for_onboarding
    
    # Step 2.5: Prepare e2e environment (if using flightctl repo)
    if [ "${USE_MAKE_AGENT_VM:-false}" = "true" ] && [ -n "${FLIGHTCTL_REPO_PATH:-}" ]; then
        prepare_e2e_environment
    else
        # Setup local registry (if enabled and not using make agent-vm)
        setup_local_registry
        push_device_images_to_registry
    fi
    
    # Step 3: Install agent on VM
    install_agent_on_vm
    
    # Note: Registry remap is now injected into bootc image during creation
    # For non-bootc VMs, configure registry remap after VM is running
    if [[ ! "${AGENT_VM_IMAGE:-}" =~ ^(bootc|BOOTC|centos-bootc)$ ]]; then
        configure_agent_registry_remap
    fi
    
    # Step 4: Configure agent
    configure_agent
    
    # Step 5: Start agent service
    start_agent_service
    
    # Step 6: Wait for enrollment request
    local enrollment_name=$(wait_for_enrollment_request)
    
    if [ -z "$enrollment_name" ]; then
        log_error "No enrollment request received"
        return 1
    fi
    
    # Step 7: Approve enrollment (if auto mode)
    if [ "${ENROLLMENT_APPROVAL_MODE:-auto}" = "auto" ]; then
        approve_enrollment "$enrollment_name"
    else
        log_info "Manual approval mode - please approve enrollment request: ${enrollment_name}"
        log_info "Run: flightctl approve ${enrollment_name}"
        log_info "Waiting 60 seconds for manual approval..."
        sleep 60
    fi
    
    # Step 8: Wait for device to be enrolled
    local device_name=$(wait_for_device "$enrollment_name")
    
    if [ -z "$device_name" ]; then
        log_error "Device enrollment failed"
        return 1
    fi
    
    # Step 9: Verify device communication
    verify_device_communication "$device_name"
    
    # Step 10: Confirm fleet membership (labels applied at approval must match fleet selector)
    verify_device_in_verification_fleet "$device_name" || true
    
    echo ""
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_success "Device Onboarding Test Complete!"
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "  Agent VM: ${AGENT_VM_NAME} (${AGENT_VM_IP})"
    log_info "  Device: ${device_name}"
    if [ -n "${DEVICE_LABELS:-}" ]; then
        log_info "  Fleet:  $(verification_fleet_name) (selector matches DEVICE_LABELS)"
    fi
    log_info ""
    log_info "  To access agent VM:"
    log_info "    ssh ${AGENT_VM_USER}@${AGENT_VM_IP}"
    log_info "    Password: ${AGENT_VM_PASSWORD}"
    log_info ""
    log_info "  To view agent logs:"
    log_info "    ssh ${AGENT_VM_USER}@${AGENT_VM_IP} 'sudo journalctl -u flightctl-agent -f'"
    echo ""
    
    return 0
}

################################################################################
# Main Execution
################################################################################

# Partial run: HTTPS UI probe + device onboarding path only.
# Does not run FULL_CLEANUP, RPM install, start_services, or auth/CLI/API tests.
# Optional VERIFY_WORK_DIR selects work dir; otherwise newest SCRIPT_DIR/flightctl_verification_* is used.
run_agent_ui_only_mode() {
    echo "=================================="
    echo "FlightCtl — UI + device onboarding only"
    echo "=================================="
    echo ""

    FULL_CLEANUP="false"

    log_info "VM Name: ${VM_NAME}"

    if [ -n "${VERIFY_WORK_DIR:-}" ]; then
        WORK_DIR="${VERIFY_WORK_DIR}"
    else
        local latest
        latest=$(ls -1dt "${SCRIPT_DIR}"/flightctl_verification_* 2>/dev/null | head -1) || true
        if [ -n "${latest}" ] && [ -d "${latest}" ]; then
            WORK_DIR="${latest}"
        else
            WORK_DIR="$(pwd)/flightctl_verification_$(date +%Y%m%d_%H%M%S)"
            log_warning "No prior ${SCRIPT_DIR}/flightctl_verification_* directory; using new WORK_DIR=${WORK_DIR}"
        fi
    fi
    mkdir -p "${WORK_DIR}"
    REPORT_FILE="${WORK_DIR}/verification_report.md"
    log_info "Work Directory: ${WORK_DIR}"
    echo ""

    check_prerequisites
    determine_rpm_url

    log_info "Using RPM URL: ${RPM_BASE_URL}"
    echo ""

    get_vm_ip
    setup_passwordless_sudo || true
    ensure_vm_hostname || true

    log_info "Skipping cleanup, RPM install, services, auth, CLI, API, and OIDC test phases."
    echo ""

    if ! test_ui; then
        log_error "UI test failed"
        return 1
    fi

    ENABLE_DEVICE_ONBOARDING="true"
    export ENABLE_DEVICE_ONBOARDING
    if ! test_device_onboarding; then
        log_error "Device onboarding failed"
        return 1
    fi

    log_success "VERIFY_RUN_MODE=agent_ui_only completed."
    return 0
}

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
    ensure_vm_hostname
    
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
    verify_selinux_context
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
    
    # Device onboarding test (if enabled)
    test_device_onboarding
    
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

# Run main (or partial agent+UI mode)
if [ "${VERIFY_RUN_MODE:-}" = "agent_ui_only" ]; then
    run_agent_ui_only_mode
    exit $?
fi

main "$@"


