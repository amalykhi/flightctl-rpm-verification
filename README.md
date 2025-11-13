# FlightCtl OIDC Verification Script

This script automates the complete process of installing, configuring, and verifying FlightCtl services with OIDC authentication on a libvirt VM.

## Prerequisites

The script requires the following tools to be installed on your host machine:

```bash
sudo dnf install -y virsh sshpass curl wget jq

# Optional: For VM auto-creation
sudo dnf install -y virt-install libvirt qemu-kvm
```

## Configuration

**All settings are now centralized in `verification.conf`!**

Edit this file to customize your environment:

```bash
vim verification.conf
```

### Key Configuration Options

```bash
# VM Configuration
VM_NAME="eurolinux9"              # VM name
VM_USER="amalykhi"                # SSH user
VM_PASSWORD=" "                   # SSH password

# VM Auto-Creation (NEW!)
CREATE_VM_IF_MISSING="false"     # Set to "true" to auto-create VM
VM_MEMORY="4096"                  # RAM in MB
VM_CPUS="2"                       # Number of CPUs
VM_DISK_SIZE="20"                 # Disk size in GB
VM_INSTALL_SOURCE="https://..."  # Installation URL or ISO

# RPM Source
RPM_SOURCE="LATEST"               # Or specific URL

# OIDC Configuration
OIDC_REALM="myrealm"
OIDC_CLIENT_ID="my_client"

# Test User
TEST_USER="testuser"
TEST_PASSWORD="password"
```

**See `verification.conf` for all available options.**

## Usage

### Method 1: Using Configuration File (Recommended)

**Step 1**: Edit `verification.conf` with your settings

**Step 2**: Run the script:

```bash
./verify_flightctl_oidc.sh
```

That's it! The script reads all settings from `verification.conf`.

### Method 2: Using Command-Line Arguments (Legacy)

```bash
./verify_flightctl_oidc.sh <VM_NAME> <RPM_URL|LATEST>
```

**Parameters:**
- `VM_NAME`: Name of the libvirt VM (e.g., `eurolinux9`)
- `RPM_URL|LATEST`: Either:
  - Full URL to the RPM repository, OR
  - `LATEST` to automatically use the most recent successful build

## Examples

### 🌟 Example 1: Use Default Config

```bash
# Edit config first
vim verification.conf

# Run with config
./verify_flightctl_oidc.sh
```

### 🚀 Example 2: Auto-Create VM (NEW!)

In `verification.conf`:

```bash
# Enable VM auto-creation
CREATE_VM_IF_MISSING="true"

# VM will be created if it doesn't exist!
VM_NAME="my-new-vm"
VM_MEMORY="4096"
VM_CPUS="2"
VM_DISK_SIZE="20"
VM_INSTALL_SOURCE="https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/"
VM_KICKSTART_FILE="https://myserver.com/kickstart.cfg"  # Optional
```

Run the script - VM will be created automatically:

```bash
./verify_flightctl_oidc.sh
```

**See `VM_CREATION_GUIDE.md` for complete VM creation documentation.**

### Example 3: Use Custom Config File

```bash
# Create custom config
cp verification.conf my_test.conf
vim my_test.conf

# Run with custom config
./verify_flightctl_oidc.sh my_test.conf
```

### Example 4: Legacy Mode with LATEST

```bash
./verify_flightctl_oidc.sh eurolinux9 LATEST
```

## What the Script Does

### Complete Workflow

1. **Configuration Loading**:
   - Loads settings from `verification.conf`
   - Supports command-line overrides for backward compatibility

2. **Prerequisites Check**: 
   - Verifies all required tools are available
   - Checks for virt-install if VM creation is enabled

3. **VM Management** (NEW!):
   - Checks if VM exists
   - **Auto-creates VM** if missing (when `CREATE_VM_IF_MISSING=true`)
   - Starts VM if it's stopped
   - Waits for VM to be ready
   - Gets VM IP address
   - Tests connectivity

4. **RPM Source Detection**:
   - If `LATEST` or `RPM_SOURCE="LATEST"`: Automatically queries Copr builds page and finds the newest successful build
   - If URL is specified: Uses the provided URL directly

5. **RPM Download**: 
   - Downloads flightctl-services and flightctl-cli RPMs from the determined source
   - Saves to timestamped work directory

6. **VM Preparation**:
   - Copies RPMs to VM
   - Stops existing FlightCtl services
   - Removes old packages

7. **Installation**:
   - Installs new RPM packages
   - Verifies container images are available

8. **OIDC Configuration**:
   - Updates `/etc/flightctl/service-config.yaml`
   - Regenerates `/etc/flightctl/flightctl-api/config.yaml` from template
   - Configures OIDC with Keycloak settings

9. **Service Management**:
   - Starts all FlightCtl services
   - Waits for services to stabilize
   - Checks service status

10. **OIDC Authentication Testing** (NEW!):
   - Tests Keycloak token endpoint with test user
   - Tests FlightCtl CLI login
   - Tests authenticated device/fleet queries
   - Verifies end-to-end auth flow

11. **Verification**:
   - Tests CLI access (flightctl get devices/fleets)
   - Tests UI accessibility (HTTP 200 check)
   - Tests API functionality
   - Checks OIDC authentication status

12. **Reporting**:
   - Collects logs from failed services
   - Generates comprehensive verification report

## Output

The script creates a timestamped directory with:

```
flightctl_verification_YYYYMMDD_HHMMSS/
├── verification_report.md    # Detailed verification report
├── logs/                      # Service logs (if any failures)
│   ├── service1.log
│   └── service2.log
├── *.rpm                      # Downloaded RPM files
└── index.html                 # Repository index
```

## Configuration

### VM Requirements

- **OS**: RHEL-based (RHEL 9, CentOS 9, EuroLinux 9, etc.)
- **User**: `amalykhi` with password ` ` (single space)
- **Access**: SSH access with sudo privileges
- **Network**: Reachable from host machine
- **Registry Access**: For Brew RPMs, login to Red Hat registry is required:

```bash
# Run on the VM
sudo podman login registry.redhat.io -u <RH_username>
```

> **Note**: This is required when using Brew RPMs as they pull container images from `registry.redhat.io` which requires authentication. Copr builds use public registries and don't require this step.

### OIDC Settings (Customizable in script)

- **Realm**: `myrealm`
- **Client ID**: `my_client`
- **Authority**: `http://VM_IP:8080/realms/myrealm`

To change these, edit the script variables:

```bash
OIDC_REALM="myrealm"
OIDC_CLIENT_ID="my_client"
```

## Verification Report

The generated report includes:

- ✅ Installation summary
- 📦 Installed packages and versions
- 🐳 Container images
- 🔄 Service status (running/failed)
- 🔐 OIDC configuration
- 🔗 Access points (API, UI, CLI)
- 📝 CLI usage examples
- 📋 Failed service logs

## Accessing FlightCtl After Installation

### CLI Access

```bash
# SSH to VM
ssh amalykhi@<VM_IP>

# Login to FlightCtl
flightctl login https://<VM_IP>:3443 --insecure-skip-tls-verify

# List devices
flightctl get devices

# List fleets
flightctl get fleets
```

### UI Access

Open in browser:
```
https://<VM_IP>:443
```

### API Access

```bash
curl -k https://<VM_IP>:3443/api/v1/devices
```

## 🌟 Key Features

### ✅ Centralized Configuration
- **All settings in `verification.conf`**
- No need to edit scripts
- Easy to maintain multiple environments
- Version control friendly

### ✅ Automated VM Creation (NEW!)
- Auto-create VMs if missing
- Multiple installation methods (URL, ISO, PXE)
- Kickstart and Cloud-init support
- Perfect for CI/CD pipelines

### ✅ OIDC Authentication Testing (NEW!)
- End-to-end authentication verification
- Keycloak token endpoint testing
- CLI login testing
- Authenticated API query testing

### ✅ Smart VM Management
- Auto-starts stopped VMs
- Waits for VM readiness
- Handles IP address detection
- Tests connectivity

### ✅ Automatic LATEST Build Detection
- Queries Copr for newest build
- No manual URL lookup needed
- Always uses most recent version

### ✅ Comprehensive Reporting
- Timestamped work directories
- Service status details
- OIDC configuration
- Failed service logs
- CLI usage examples

## 📖 Additional Documentation

- **`verification.conf`** - Main configuration file with all options
- **`VM_CREATION_GUIDE.md`** - Complete VM auto-creation guide
- **`CONFIG_AND_AUTH_TESTING.md`** - Configuration and OIDC testing details
- **`TEST_RESULTS_SUCCESS.md`** - Example successful test results
- **`FINAL_OIDC_STATUS_REPORT.md`** - Detailed OIDC analysis

## Common Issues and Solutions

### Issue: VM not found
**Solution**: Either:
- Set `CREATE_VM_IF_MISSING="true"` in `verification.conf` to auto-create VM
- Create VM manually first
- Verify VM name with `sudo virsh list --all`

### Issue: Cannot connect to VM
**Solution**: 
- Check VM is running: `sudo virsh list`
- Verify network: `sudo virsh domifaddr <VM_NAME>`
- Check SSH access manually: `ssh amalykhi@<VM_IP>`

### Issue: RPM download fails
**Solution**: Verify RPM URL is correct and accessible

### Issue: Container images missing
**Script handles**: Automatically retags 0.10.0 images to required version

### Issue: OIDC not working
**Expected**: OIDC authentication may be disabled if:
- Keycloak is not configured for HTTPS
- PAM issuer image is not available
- This is documented in the report

## Exit Codes

- `0`: Success
- `1`: Error (with descriptive message)

## Logs and Debugging

### View script output:
The script provides colored output with INFO, SUCCESS, WARNING, and ERROR messages.

### Check service status on VM:
```bash
ssh amalykhi@<VM_IP>
sudo systemctl list-units 'flightctl*'
```

### View service logs on VM:
```bash
ssh amalykhi@<VM_IP>
sudo journalctl -u flightctl-api.service -n 50
sudo podman logs flightctl-api
```

## Customization

To modify VM credentials, edit these variables in the script:

```bash
VM_USER="amalykhi"
VM_PASSWORD=" "  # Single space character
```

To use a different work directory:

```bash
WORK_DIR="/custom/path"
```

## Notes

- The script is idempotent - safe to run multiple times
- Old packages are cleanly removed before new installation
- Container images are automatically managed
- All operations are logged with timestamps
- Authentication may be disabled by default (documented in report)

## Support

For issues or questions:
1. Check the generated verification report
2. Review service logs in the logs directory
3. Check FlightCtl documentation

## Example Run

### Using LATEST option:

```bash
$ ./verify_flightctl_oidc.sh eurolinux9 LATEST

==================================
FlightCtl OIDC Verification Script
==================================

[INFO] VM Name: eurolinux9
[INFO] Work Directory: /home/amalykhi/flightctl_verification_20251106_154530

[INFO] Checking prerequisites...
[SUCCESS] All prerequisites available
[INFO] Determining RPM source URL...
[INFO] Using LATEST build option
[INFO] Fetching latest successful build from Copr...
[INFO] Found latest build ID: 9772870
[SUCCESS] Latest build URL: https://download.copr.fedorainfracloud.org/results/@redhat-et/flightctl-dev/epel-9-x86_64/09772870-flightctl/
[SUCCESS] Build URL verified and accessible
[INFO] RPM Base URL: https://download.copr.fedorainfracloud.org/results/@redhat-et/flightctl-dev/epel-9-x86_64/09772870-flightctl/

[INFO] Checking prerequisites...
[SUCCESS] All prerequisites available
[INFO] Getting VM IP address for eurolinux9...
[SUCCESS] VM IP: 192.168.122.219
[SUCCESS] VM is reachable
[INFO] Downloading FlightCtl RPMs...
[SUCCESS] Downloaded flightctl-services-1.0.0~main~222-1.el9.x86_64.rpm
[SUCCESS] Downloaded flightctl-cli-1.0.0~main~222-1.el9.x86_64.rpm
[INFO] Copying RPMs to VM...
[SUCCESS] RPMs copied to VM
...
[SUCCESS] CLI is working - can query devices
[SUCCESS] UI is accessible at https://192.168.122.219:443
[SUCCESS] API is working - returned DeviceList

==================================
[SUCCESS] Verification Complete!
==================================

[INFO] Report: /home/amalykhi/flightctl_verification_20251106_154530/verification_report.md
[INFO] Quick Access:
[INFO]   API: https://192.168.122.219:3443
[INFO]   UI:  https://192.168.122.219:443
```

