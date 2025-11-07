# FlightCtl OIDC Verification Script

This script automates the complete process of installing, configuring, and verifying FlightCtl services with OIDC authentication on a libvirt VM.

## Prerequisites

The script requires the following tools to be installed on your host machine:

```bash
sudo dnf install -y virsh sshpass curl wget jq
```

## Usage

### Basic Usage

```bash
./verify_flightctl_oidc.sh <VM_NAME> <RPM_URL|LATEST>
```

**Parameters:**
- `VM_NAME`: Name of the libvirt VM (e.g., `eurolinux9`)
- `RPM_URL|LATEST`: Either:
  - Full URL to the RPM repository, OR
  - `LATEST` to automatically use the most recent successful build

### Examples

#### 🌟 Using LATEST (Recommended) - Automatically fetches the newest build:

```bash
./verify_flightctl_oidc.sh eurolinux9 LATEST
```

This will:
1. Query the [Copr builds page](https://copr.fedorainfracloud.org/coprs/g/redhat-et/flightctl-dev/builds/)
2. Find the most recent successful build
3. Automatically construct the RPM download URL
4. Proceed with installation

#### Using a specific RPM build:

```bash
./verify_flightctl_oidc.sh eurolinux9 https://download.copr.fedorainfracloud.org/results/@redhat-et/flightctl-dev/epel-9-x86_64/09772870-flightctl/
```

#### Using custom VM with LATEST:

```bash
./verify_flightctl_oidc.sh my-fedora-vm LATEST
```

#### Using a different specific build:

```bash
./verify_flightctl_oidc.sh eurolinux9 https://download.copr.fedorainfracloud.org/results/@redhat-et/flightctl-dev/epel-9-x86_64/09773000-flightctl/
```

## What the Script Does

1. **Prerequisites Check**: Verifies all required tools are available
2. **RPM Source Detection**:
   - If `LATEST` is specified: Automatically queries Copr builds page and finds the newest successful build
   - If URL is specified: Uses the provided URL directly
3. **VM Setup**: 
   - Checks if VM exists and is running
   - Gets VM IP address
   - Tests connectivity
4. **RPM Download**: 
   - Downloads flightctl-services and flightctl-cli RPMs from the determined source
   - Saves to timestamped work directory
5. **VM Preparation**:
   - Copies RPMs to VM
   - Stops existing FlightCtl services
   - Removes old packages
6. **Installation**:
   - Installs new RPM packages
   - Retags container images if needed (0.10.0 → 1.0.0-main-222)
7. **OIDC Configuration**:
   - Updates `/etc/flightctl/service-config.yaml`
   - Updates `/etc/flightctl/flightctl-api/config.yaml`
   - Configures OIDC with Keycloak settings
8. **Service Management**:
   - Starts all FlightCtl services
   - Waits for services to stabilize
   - Checks service status
9. **Verification**:
   - Tests CLI access (flightctl get devices/fleets)
   - Tests UI accessibility (HTTP 200 check)
   - Tests API functionality
   - Checks OIDC authentication status
10. **Reporting**:
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

## Common Issues and Solutions

### Issue: VM not found
**Solution**: Verify VM name with `sudo virsh list --all`

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

