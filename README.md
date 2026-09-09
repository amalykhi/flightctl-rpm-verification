# FlightCtl RPM Verification Script

Automates installation, configuration, and full verification of FlightCtl services on libvirt VMs — including PAM Issuer + Keycloak authentication, resource CRUD, UI, and device onboarding.

## Quick Start: Verifying a New Build

### Step 1 — Set the RPM URLs in the config file

**For RHEL9** — edit `verification.conf`:
```bash
vim verification.conf
```

Update these four fields with the Brew task URLs:
```bash
RPM_SOURCE="https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/work/tasks/<TASK_ID>/<FULL_TASK_ID>/"

SERVICES_RPM_URL="https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/work/tasks/<TASK_ID>/<FULL_TASK_ID>/flightctl-services-X.Y.Z-1.el9.x86_64.rpm"
CLI_RPM_URL="https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/work/tasks/<TASK_ID>/<FULL_TASK_ID>/flightctl-cli-X.Y.Z-1.el9.x86_64.rpm"

AGENT_RPM_URL="https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/work/tasks/<TASK_ID>/<FULL_TASK_ID>/flightctl-agent-X.Y.Z-1.el9.x86_64.rpm"
AGENT_SELINUX_RPM_URL="https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/work/tasks/<TASK_ID>/<FULL_TASK_ID>/flightctl-selinux-X.Y.Z-1.el9.noarch.rpm"
```

**For RHEL10** — edit `verification-rhel10.conf`:
```bash
vim verification-rhel10.conf
```

Update the same four fields using `el10` RPM URLs:
```bash
RPM_SOURCE="https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/work/tasks/<TASK_ID>/<FULL_TASK_ID>/"

SERVICES_RPM_URL="https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/work/tasks/<TASK_ID>/<FULL_TASK_ID>/flightctl-services-X.Y.Z-1.el10.x86_64.rpm"
CLI_RPM_URL="https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/work/tasks/<TASK_ID>/<FULL_TASK_ID>/flightctl-cli-X.Y.Z-1.el10.x86_64.rpm"

AGENT_RPM_URL="https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/work/tasks/<TASK_ID>/<FULL_TASK_ID>/flightctl-agent-X.Y.Z-1.el10.x86_64.rpm"
AGENT_SELINUX_RPM_URL="https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/work/tasks/<TASK_ID>/<FULL_TASK_ID>/flightctl-selinux-X.Y.Z-1.el10.noarch.rpm"
```

> **You do not download or copy RPMs manually.** The script downloads them automatically from the URLs above.

---

### Step 2 — Ensure the VM is logged in to the Red Hat registry

Brew builds pull container images from `registry.redhat.io`. The VM must be authenticated as root:

```bash
# SSH into the service VM and run:
sudo podman login registry.redhat.io
```

Verify it worked:
```bash
sudo podman login --get-login registry.redhat.io
```

VMs and their default IPs:
| VM | Libvirt name | Default IP |
|----|-------------|------------|
| RHEL9 service VM | `eurolinux9` | `192.168.122.220` |
| RHEL10 service VM | `rhel10-fips-vm` | `192.168.122.19` |

---

### Step 3 — Run the verification

**RHEL9:**
```bash
./verify_flightctl_oidc.sh
```

**RHEL10:**
```bash
./verify_flightctl_oidc.sh verification-rhel10.conf
```

The script will:
1. Clean up any previous installation
2. Download and install the RPMs
3. Start all FlightCtl services (pulls container images from `registry.redhat.io`)
4. Test PAM Issuer authentication
5. Deploy Keycloak and test OIDC authentication
6. Test UI, CLI, and API
7. Create a bootc agent VM and enroll a device
8. Generate a report in `flightctl_verification_<timestamp>/verification_report.md`

---

## Configuration Files

| File | Purpose |
|------|---------|
| `verification.conf` | RHEL9 verification (default) |
| `verification-rhel10.conf` | RHEL10 verification |
| `verification-rhel9-ds.conf` | RHEL9 downstream builds |
| `verification-rhel10-ds.conf` | RHEL10 downstream builds |

---

## What Gets Verified

| Check | Description |
|-------|-------------|
| RPM install | `flightctl-services` + `flightctl-cli` installed |
| Services | All 16 flightctl systemd services running |
| FIPS | FIPS mode status on VM |
| API version | Server reports expected version |
| UI | HTTP 200 at `https://<VM_IP>:443` |
| PAM Issuer auth | Login + fleet/device/repo CRUD |
| Keycloak OIDC auth | Login + JWT claims (`organizations`, `roles`) |
| Device onboarding | Agent VM created, enrolled, joined fleet, status Online |
| SELinux | Agent binary has `flightctl_agent_exec_t` context |

---

## Prerequisites

Install on the host machine:
```bash
sudo dnf install -y virsh sshpass curl wget jq
```

---

## Key Configuration Options

### `verification.conf` / `verification-rhel10.conf`

```bash
# Which VM to use
VM_NAME="eurolinux9"          # RHEL9 | "rhel10-fips-vm" for RHEL10
VM_USER="amalykhi"
VM_PASSWORD=" "               # Single space

# RPM source (Brew task directory URL)
RPM_SOURCE="https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/work/tasks/..."

# Direct RPM overrides (set these for each new build)
SERVICES_RPM_URL="https://..."
CLI_RPM_URL="https://..."
AGENT_RPM_URL="https://..."
AGENT_SELINUX_RPM_URL="https://..."

# Authentication (both = PAM Issuer + Keycloak)
AUTH_TYPE="both"              # pam | keycloak | both | none

# Device onboarding
ENABLE_DEVICE_ONBOARDING="true"
AGENT_VM_NAME="flightctl-agent-test-2"   # RHEL9 | "flightctl-agent-test-rhel10" for RHEL10
AGENT_VM_IMAGE="bootc"
BOOTC_IMAGE="quay.io/centos-bootc/centos-bootc:stream9"   # stream9 for el9 | stream10 for el10

# Full cleanup before each run (recommended)
FULL_CLEANUP="true"

# FIPS
ENABLE_FIPS="verify"          # verify | true | false
```

---

## Output

Each run creates a timestamped directory:

```
flightctl_verification_YYYYMMDD_HHMMSS/
├── verification_report.md     # Full verification report
├── logs/                      # Logs from any failed services
├── flightctl-services-*.rpm   # Downloaded RPMs
├── flightctl-cli-*.rpm
└── enrollment-config.yaml     # Agent enrollment config
```

---

## Access Points After Verification

| Endpoint | RHEL9 | RHEL10 |
|----------|-------|--------|
| UI | https://192.168.122.220:443 | https://192.168.122.19:443 |
| API | https://192.168.122.220:3443 | https://192.168.122.19:3443 |

**Login commands (PAM Issuer):**
```bash
flightctl login https://<VM_IP>:3443 -k -u admin -p admin123
```

**Login commands (Keycloak):**
```bash
flightctl login https://<VM_IP>:3443 -k -u testuser -p password
```

---

## Troubleshooting

### Services stuck in `auto-restart`
The VM is not logged in to the registry. Run on the VM:
```bash
sudo podman login registry.redhat.io
```

### Agent VM SSH fails
The agent VM has a stale/broken state. Destroy it and rerun — the script will create a fresh one:
```bash
sudo virsh destroy flightctl-agent-test-2
sudo virsh undefine flightctl-agent-test-2 --remove-all-storage
./verify_flightctl_oidc.sh
```

### Check service status on VM
```bash
ssh amalykhi@<VM_IP>
sudo systemctl list-units 'flightctl*' --all
sudo journalctl -u flightctl-api.service -n 50
```
