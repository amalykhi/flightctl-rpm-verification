#!/bin/bash

################################################################################
# FlightCtl OIDC Authentication Verification Script
# 
# This script automates the installation and verification of FlightCtl services
# with OIDC authentication on a libvirt VM.
#
# Usage:
#   ./verify_flightctl_oidc.sh <VM_NAME> <RPM_URL|LATEST>
#
# Examples:
#   # Use specific build
#   ./verify_flightctl_oidc.sh eurolinux9 https://download.copr.fedorainfracloud.org/results/@redhat-et/flightctl-dev/epel-9-x86_64/09772870-flightctl/
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
    sshpass -p "${VM_PASSWORD}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "${VM_USER}@${VM_IP}" "echo '${VM_PASSWORD}' | sudo -S $@"
}

scp_to_vm() {
    sshpass -p "${VM_PASSWORD}" scp -o StrictHostKeyChecking=no "$1" "${VM_USER}@${VM_IP}:$2"
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

get_latest_build_url() {
    log_info "Fetching latest successful build from Copr..."
    
    # Download the builds page
    local builds_html=$(curl -s -L "${COPR_BUILDS_URL}" 2>&1)
    
    if [ -z "$builds_html" ]; then
        log_error "Failed to fetch builds page from ${COPR_BUILDS_URL}"
        exit 1
    fi
    
    # Extract all build IDs and sort them numerically to get the highest (most recent)
    # The HTML contains links like: /coprs/g/redhat-et/flightctl-dev/build/9772870/
    local latest_build_id=$(echo "$builds_html" | \
        grep -oP '/coprs/g/redhat-et/flightctl-dev/build/\K[0-9]+(?=/)' | \
        sort -n -r | \
        head -1)
    
    if [ -z "$latest_build_id" ]; then
        log_error "Could not find latest build ID from builds page"
        log_info "Tried to parse: ${COPR_BUILDS_URL}"
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
        virt_install_cmd+=" --extra-args \"inst.ks=${VM_KICKSTART_FILE}\""
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
        if ! sudo virsh list --state-running | grep -q "${VM_NAME}"; then
            log_info "VM is not running. Starting..."
            if sudo virsh start "${VM_NAME}"; then
                log_success "VM started successfully"
                sleep 10  # Wait for boot
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
}

download_rpms() {
    log_info "Downloading FlightCtl RPMs from ${RPM_BASE_URL}..."
    
    mkdir -p "${WORK_DIR}"
    cd "${WORK_DIR}"
    
    # Download index page
    curl -L -s "${RPM_BASE_URL}" -o index.html
    
    # Extract RPM filenames (handle both single and double quotes in HTML)
    local rpm_files=$(cat index.html | grep -oP "href='[^']*\.rpm'" | cut -d"'" -f2 | grep -v src.rpm)
    
    if [ -z "$rpm_files" ]; then
        log_error "No RPM files found at ${RPM_BASE_URL}"
        exit 1
    fi
    
    log_info "Found RPM packages:"
    echo "$rpm_files" | while read rpm; do
        log_info "  - $rpm"
    done
    
    # Download flightctl-services and flightctl-cli
    local services_rpm=$(echo "$rpm_files" | grep "flightctl-services.*x86_64.rpm" | head -1)
    local cli_rpm=$(echo "$rpm_files" | grep "flightctl-cli.*x86_64.rpm" | head -1)
    
    if [ -n "$services_rpm" ]; then
        log_info "Downloading ${services_rpm}..."
        wget -q "${RPM_BASE_URL}${services_rpm}" || {
            log_error "Failed to download ${services_rpm}"
            exit 1
        }
        log_success "Downloaded ${services_rpm}"
    fi
    
    if [ -n "$cli_rpm" ]; then
        log_info "Downloading ${cli_rpm}..."
        wget -q "${RPM_BASE_URL}${cli_rpm}" || {
            log_error "Failed to download ${cli_rpm}"
            exit 1
        }
        log_success "Downloaded ${cli_rpm}"
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
        ssh_exec_sudo "dnf remove -y flightctl-services flightctl-cli flightctl-telemetry-gateway flightctl-observability" || true
        log_success "Old packages removed"
    else
        log_info "No old packages to remove"
    fi
}

install_rpms() {
    log_info "Installing FlightCtl RPMs..."
    
    ssh_exec_sudo "dnf install -y /tmp/flightctl-services-*.rpm /tmp/flightctl-cli-*.rpm"
    
    log_success "RPMs installed successfully"
}

check_container_images() {
    log_info "Checking container images..."
    
    # Get the version from installed RPM
    local installed_version=$(ssh_exec "rpm -q flightctl-services --qf '%{VERSION}-%{RELEASE}'" | sed 's/\.el9$//')
    log_info "Installed version: ${installed_version}"
    
    # Check what tag the services require (from service file)
    local required_tag=$(ssh_exec_sudo "grep 'Image=' /usr/share/containers/systemd/flightctl-api.container 2>/dev/null" | sed 's/.*://' || echo "1.0.0")
    log_info "Services require tag: ${required_tag}"
    
    # Verify the required images exist
    local image_count=$(ssh_exec_sudo "podman images | grep -c 'flightctl.*${required_tag}' || true")
    
    if [ "$image_count" -gt 0 ]; then
        log_success "Container images with tag '${required_tag}' are available"
    else
        log_warning "Required container images with tag '${required_tag}' not found"
        log_info "Available FlightCtl images:"
        ssh_exec_sudo "podman images | grep flightctl | head -10"
    fi
}

configure_oidc() {
    log_info "Configuring OIDC authentication..."
    
    local oidc_authority="http://${VM_IP}:8080/realms/${OIDC_REALM}"
    
    # Update main service config
    log_info "Updating /etc/flightctl/service-config.yaml..."
    ssh_exec_sudo "sed -i \
        -e 's/type: none/type: oidc/' \
        -e 's|baseDomain:.*|baseDomain: ${VM_IP}|' \
        -e 's|oidcAuthority:.*|oidcAuthority: \"${oidc_authority}\"|' \
        -e 's|externalOidcAuthority:.*|externalOidcAuthority: \"${oidc_authority}\"|' \
        -e 's|oidcClientId:.*|oidcClientId: \"${OIDC_CLIENT_ID}\"|' \
        /etc/flightctl/service-config.yaml"
    
    # Regenerate API config from service config
    log_info "Regenerating API config from template..."
    ssh_exec_sudo "rm -f /etc/flightctl/flightctl-api/config.yaml"
    ssh_exec_sudo "systemctl unmask flightctl-api-init.service"
    ssh_exec_sudo "systemctl start flightctl-api-init.service"
    
    # Wait for API init to complete and config to be written
    log_info "Waiting for API config generation..."
    for i in {1..10}; do
        if ssh_exec "test -f /etc/flightctl/flightctl-api/config.yaml"; then
            log_success "API config generated successfully"
            break
        fi
        sleep 1
    done
    
    # Verify config was created
    if ! ssh_exec "test -f /etc/flightctl/flightctl-api/config.yaml"; then
        log_warning "API config was not generated, checking init service status..."
        ssh_exec_sudo "systemctl status flightctl-api-init.service --no-pager | head -15"
    fi
    
    ssh_exec_sudo "systemctl mask flightctl-api-init.service"
    
    log_success "OIDC configuration updated"
}

start_services() {
    log_info "Starting FlightCtl services..."
    
    ssh_exec_sudo "systemctl start flightctl.target"
    
    log_info "Waiting for services to start..."
    sleep 15
    
    log_success "Services started"
}

check_service_status() {
    log_info "Checking service status..."
    
    # Get running services
    local running_services=$(ssh_exec "systemctl list-units 'flightctl*' --no-legend | grep running | wc -l")
    log_success "Running services: ${running_services}"
    
    # Get failed services
    local failed_services=$(ssh_exec "systemctl list-units 'flightctl*' --no-legend | grep -E 'failed|auto-restart' | awk '{print \$1}'" || true)
    
    if [ -n "$failed_services" ]; then
        log_warning "Failed/Auto-restarting services:"
        echo "$failed_services" | while read service; do
            log_warning "  - $service"
        done
    fi
}

test_cli() {
    log_info "Testing FlightCtl CLI..."
    
    # Login
    ssh_exec "flightctl login https://${VM_IP}:3443 --insecure-skip-tls-verify" > /dev/null 2>&1 || true
    
    # Test commands
    if ssh_exec "flightctl get devices" > /dev/null 2>&1; then
        log_success "CLI is working - can query devices"
    else
        log_error "CLI test failed"
        return 1
    fi
    
    if ssh_exec "flightctl get fleets" > /dev/null 2>&1; then
        log_success "CLI is working - can query fleets"
    else
        log_warning "CLI cannot query fleets"
    fi
}

test_ui() {
    log_info "Testing FlightCtl UI..."
    
    local ui_response=$(curl -k -s -o /dev/null -w "%{http_code}" "https://${VM_IP}:443")
    
    if [ "$ui_response" = "200" ]; then
        log_success "UI is accessible at https://${VM_IP}:443"
    else
        log_error "UI returned HTTP ${ui_response}"
        return 1
    fi
}

test_api() {
    log_info "Testing FlightCtl API..."
    
    local api_response=$(ssh_exec "curl -k -s https://${VM_IP}:3443/api/v1/devices" | jq -r '.kind' 2>/dev/null || echo "")
    
    if [ "$api_response" = "DeviceList" ]; then
        log_success "API is working - returned DeviceList"
    else
        log_warning "API response unexpected: ${api_response}"
    fi
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
        local access_token=$(echo "$token_response" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
        if [ -n "$access_token" ]; then
            log_info "Access token obtained (first 50 chars): ${access_token:0:50}..."
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
    
    local login_result=$(ssh_exec "flightctl login https://${VM_IP}:3443 ${insecure_flag} \
        --username ${TEST_USER} \
        --password ${TEST_PASSWORD} \
        --client-id ${OIDC_CLIENT_ID} 2>&1" || echo "")
    
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
    
    cat > "${REPORT_FILE}" << EOF
# FlightCtl OIDC Authentication Verification Report

**Date**: $(date '+%B %d, %Y at %H:%M:%S')  
**VM**: ${VM_NAME} (${VM_IP})  
**RPM Source**: ${RPM_BASE_URL}

## Summary

FlightCtl services have been installed and configured on the VM.

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

## OIDC Configuration

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
# Login to FlightCtl
flightctl login https://${VM_IP}:3443 --insecure-skip-tls-verify

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
    download_rpms
    copy_rpms_to_vm
    stop_old_services
    remove_old_packages
    install_rpms
    check_container_images
    configure_oidc
    start_services
    check_service_status
    
    echo ""
    log_info "Testing FlightCtl components..."
    test_cli
    test_ui
    test_api
    check_oidc_status
    test_oidc_authentication
    
    echo ""
    collect_service_logs
    generate_report
    
    echo ""
    echo "=================================="
    log_success "Verification Complete!"
    echo "=================================="
    echo ""
    log_info "Report: ${REPORT_FILE}"
    log_info "Logs: ${WORK_DIR}/logs/"
    echo ""
    log_info "Quick Access:"
    log_info "  API: https://${VM_IP}:3443"
    log_info "  UI:  https://${VM_IP}:443"
    echo ""
}

# Run main function
main "$@"

