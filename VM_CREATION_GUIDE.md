# 🖥️ Automated VM Creation Feature

**Feature Added**: November 10, 2025  
**Repository**: https://github.com/amalykhi/flightctl-rpm-verification

---

## 📖 Overview

The verification script can now automatically create a new VM if the specified VM doesn't exist! This makes it easy to start from scratch without manual VM setup.

---

## 🚀 Quick Start

### 1. Enable Auto-Creation

Edit `verification.conf`:

```bash
# Set this to true to enable VM auto-creation
CREATE_VM_IF_MISSING="true"
```

### 2. Configure VM Specifications

```bash
# VM specifications
VM_MEMORY="4096"           # Memory in MB
VM_CPUS="2"                # Number of vCPUs
VM_DISK_SIZE="20"          # Disk size in GB
VM_OS_VARIANT="rhel9.0"    # OS variant for virt-install

# Installation source (choose one):
# - Network URL
VM_INSTALL_SOURCE="https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/"

# - Or ISO file
# VM_INSTALL_SOURCE="/path/to/rhel-9.iso"

# - Or PXE boot
# VM_INSTALL_SOURCE="pxe"

# Network
VM_NETWORK="default"       # Libvirt network name
```

### 3. Run the Script

```bash
./verify_flightctl_oidc.sh
```

The script will:
- ✅ Check if VM exists
- ✅ Create VM if missing (when `CREATE_VM_IF_MISSING=true`)
- ✅ Wait for installation to complete
- ✅ Start the VM if it's stopped
- ✅ Continue with FlightCtl verification

---

## 📋 Configuration Options

### Required Parameters

```bash
VM_NAME="eurolinux9"              # Name for your VM
VM_MEMORY="4096"                  # RAM in MB
VM_CPUS="2"                       # Number of CPUs
VM_DISK_SIZE="20"                 # Disk size in GB
VM_OS_VARIANT="rhel9.0"           # OS type
VM_INSTALL_SOURCE="<url/iso>"    # Installation source
```

### Installation Sources

#### Option 1: Network Installation (HTTP/HTTPS)
```bash
# Rocky Linux 9
VM_INSTALL_SOURCE="https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/"

# AlmaLinux 9
VM_INSTALL_SOURCE="https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/"

# Fedora 39
VM_INSTALL_SOURCE="https://download.fedoraproject.org/pub/fedora/linux/releases/39/Server/x86_64/os/"
```

#### Option 2: ISO File
```bash
VM_INSTALL_SOURCE="/var/lib/libvirt/images/rhel-9.iso"
```

#### Option 3: PXE Boot
```bash
VM_INSTALL_SOURCE="pxe"
```

### Automated Installation

#### With Kickstart (Recommended)
```bash
VM_KICKSTART_FILE="https://example.com/kickstart.cfg"
# Or local file:
# VM_KICKSTART_FILE="/path/to/kickstart.cfg"
```

#### With Cloud-Init
```bash
VM_CLOUD_INIT_USER_DATA="/path/to/user-data.yaml"
VM_CLOUD_INIT_META_DATA="/path/to/meta-data.yaml"
```

---

## 📝 Sample Kickstart File

Create a kickstart file for fully automated installation:

```bash
# kickstart.cfg
lang en_US.UTF-8
keyboard us
timezone America/New_York --isUtc
rootpw --plaintext yourpassword
user --name=amalykhi --password=yourpassword --plaintext --groups=wheel

# Network
network --bootproto=dhcp --device=eth0 --onboot=yes --activate

# Disk
zerombr
clearpart --all --initlabel
autopart --type=lvm

# Packages
%packages
@^server-product-environment
openssh-server
%end

# Services
services --enabled=sshd

# Reboot after installation
reboot

# Post-installation
%post
# Enable password authentication for SSH
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl enable sshd
%end
```

---

## 🔧 Example Configurations

### Example 1: Rocky Linux 9 with Network Install

```bash
# verification.conf
CREATE_VM_IF_MISSING="true"
VM_NAME="rocky9-test"
VM_MEMORY="4096"
VM_CPUS="2"
VM_DISK_SIZE="20"
VM_OS_VARIANT="rhel9.0"
VM_INSTALL_SOURCE="https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/"
VM_NETWORK="default"
VM_KICKSTART_FILE="https://myserver.com/rocky9-kickstart.cfg"
```

### Example 2: AlmaLinux 9 from ISO

```bash
CREATE_VM_IF_MISSING="true"
VM_NAME="alma9-test"
VM_MEMORY="8192"
VM_CPUS="4"
VM_DISK_SIZE="30"
VM_OS_VARIANT="rhel9.0"
VM_INSTALL_SOURCE="/var/lib/libvirt/images/AlmaLinux-9-latest-x86_64-dvd.iso"
VM_NETWORK="default"
```

### Example 3: Fedora 39 with Cloud-Init

```bash
CREATE_VM_IF_MISSING="true"
VM_NAME="fedora39-test"
VM_MEMORY="4096"
VM_CPUS="2"
VM_DISK_SIZE="20"
VM_OS_VARIANT="fedora39"
VM_INSTALL_SOURCE="https://download.fedoraproject.org/pub/fedora/linux/releases/39/Server/x86_64/os/"
VM_NETWORK="default"
VM_CLOUD_INIT_USER_DATA="/path/to/user-data.yaml"
VM_CLOUD_INIT_META_DATA="/path/to/meta-data.yaml"
```

---

## 🎬 Workflow

### When VM Doesn't Exist

```
1. Script checks if VM exists
   ↓ NO
2. Check CREATE_VM_IF_MISSING
   ↓ TRUE
3. Run virt-install command
   ↓
4. Wait for VM to appear in virsh list (up to 5 minutes)
   ↓
5. Wait for VM to reach running state (up to 10 minutes)
   ↓
6. Wait 30 seconds for SSH to be ready
   ↓
7. Continue with FlightCtl verification
```

### When VM Exists But is Stopped

```
1. Script checks if VM exists
   ↓ YES
2. Check if VM is running
   ↓ NO
3. Start the VM with virsh start
   ↓
4. Wait 10 seconds
   ↓
5. Continue with FlightCtl verification
```

---

## 🕐 Typical Installation Times

| Installation Method | Expected Time |
|---------------------|---------------|
| **Network Install** (fast connection) | 10-15 minutes |
| **Network Install** (slow connection) | 20-30 minutes |
| **ISO Install** | 5-10 minutes |
| **With Kickstart** | 5-10 minutes (automated) |
| **With Cloud-Init** | 2-5 minutes (fastest) |

---

## ⚠️ Prerequisites

Make sure you have these installed:

```bash
# Required packages
sudo dnf install -y virt-install libvirt qemu-kvm

# Start and enable libvirt
sudo systemctl enable --now libvirtd

# Add your user to libvirt group (optional)
sudo usermod -aG libvirt $USER
```

---

## 🐛 Troubleshooting

### Issue: "virt-install not found"

```bash
sudo dnf install -y virt-install
```

### Issue: VM creation is taking too long

Check the VM console:

```bash
sudo virsh console <VM_NAME>
# Press Ctrl+] to exit
```

### Issue: VM is created but not getting IP

1. Check if VM is running:
```bash
sudo virsh list
```

2. Check VM network:
```bash
sudo virsh domifaddr <VM_NAME>
```

3. Try restarting the VM:
```bash
sudo virsh destroy <VM_NAME>
sudo virsh start <VM_NAME>
```

### Issue: Installation fails

1. Check the installation source is accessible:
```bash
curl -I <VM_INSTALL_SOURCE>
```

2. View VM logs:
```bash
sudo journalctl -u libvirtd
```

3. Check virsh logs:
```bash
sudo virsh dumpxml <VM_NAME>
```

---

## 📊 Status Messages

### During VM Creation

```
[INFO] VM 'eurolinux9' not found. Creating new VM...
[INFO] Creating VM with command: sudo virt-install ...
[SUCCESS] VM creation started successfully
[INFO] Waiting for VM installation to complete...
[INFO] This may take 10-30 minutes depending on your system and network speed
[INFO] Still waiting for VM... (30s elapsed)
[SUCCESS] VM 'eurolinux9' is now visible in virsh
[INFO] Waiting for VM to be in running state...
[SUCCESS] VM 'eurolinux9' is now running
```

### When VM Already Exists

```
[INFO] VM 'eurolinux9' exists
[INFO] VM is not running. Starting...
[SUCCESS] VM started successfully
```

---

## 🎯 Use Cases

### 1. **CI/CD Pipelines**
Create fresh VMs for each test run:
```bash
CREATE_VM_IF_MISSING="true"
VM_NAME="flightctl-test-${CI_JOB_ID}"
```

### 2. **Development Environment**
Quickly spin up test environments:
```bash
CREATE_VM_IF_MISSING="true"
VM_NAME="dev-env-$(date +%Y%m%d)"
```

### 3. **Automated Testing**
Create multiple VMs for parallel testing:
```bash
for i in {1..3}; do
  VM_NAME="test-vm-$i" ./verify_flightctl_oidc.sh custom_config_$i.conf
done
```

---

## 🔒 Security Considerations

1. **SSH Credentials**: Configure SSH keys in kickstart/cloud-init instead of passwords
2. **Firewall**: The created VM will use the default libvirt network (usually NAT)
3. **Storage**: VM disks are created in libvirt's default storage pool
4. **Root Access**: Requires sudo for virsh commands

---

## 📝 Complete Example

### Step 1: Create Kickstart File

```bash
cat > /tmp/flightctl-kickstart.cfg << 'EOF'
lang en_US.UTF-8
keyboard us
timezone America/New_York
rootpw --plaintext redhat
user --name=amalykhi --password=" " --plaintext --groups=wheel
network --bootproto=dhcp --device=eth0 --onboot=yes
zerombr
clearpart --all --initlabel
autopart
reboot

%packages
@^minimal-environment
openssh-server
%end

%post
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
echo "amalykhi ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/amalykhi
%end
EOF
```

### Step 2: Configure verification.conf

```bash
# Enable VM creation
CREATE_VM_IF_MISSING="true"

# VM specs
VM_NAME="flightctl-test"
VM_MEMORY="4096"
VM_CPUS="2"
VM_DISK_SIZE="20"
VM_OS_VARIANT="rhel9.0"

# Installation
VM_INSTALL_SOURCE="https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/"
VM_KICKSTART_FILE="file:///tmp/flightctl-kickstart.cfg"
VM_NETWORK="default"

# SSH credentials
VM_USER="amalykhi"
VM_PASSWORD=" "
```

### Step 3: Run Verification

```bash
./verify_flightctl_oidc.sh
```

The script will:
1. ✅ Create the VM (10-15 minutes)
2. ✅ Wait for it to be ready
3. ✅ Install FlightCtl
4. ✅ Configure OIDC
5. ✅ Test authentication
6. ✅ Generate report

---

## 🎓 Tips & Best Practices

### 1. Use Kickstart for Automation
Always provide a kickstart file for fully automated installations.

### 2. Set Appropriate Resources
- **Development**: 2 CPUs, 4GB RAM
- **Testing**: 4 CPUs, 8GB RAM
- **Production-like**: 8 CPUs, 16GB RAM

### 3. Monitor First Run
For the first VM creation, monitor the console to ensure everything works:
```bash
sudo virsh console <VM_NAME>
```

### 4. Keep Installation Sources Local
For faster installations, mirror repositories locally or use ISOs.

### 5. Clean Up Test VMs
```bash
# After testing
sudo virsh destroy <VM_NAME>
sudo virsh undefine <VM_NAME> --remove-all-storage
```

---

## 📚 Additional Resources

- [virt-install documentation](https://linux.die.net/man/1/virt-install)
- [Kickstart documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/performing_an_advanced_rhel_9_installation/kickstart-commands-and-options-reference_installing-rhel-as-an-experienced-user)
- [Cloud-init documentation](https://cloudinit.readthedocs.io/)
- [Libvirt documentation](https://libvirt.org/docs.html)

---

## ✅ Summary

| Feature | Status |
|---------|--------|
| **Auto VM Creation** | ✅ Supported |
| **Multiple Install Methods** | ✅ URL, ISO, PXE |
| **Kickstart Support** | ✅ Yes |
| **Cloud-Init Support** | ✅ Yes |
| **Auto Start Existing VM** | ✅ Yes |
| **Progress Monitoring** | ✅ Real-time logs |
| **Error Handling** | ✅ Comprehensive |

---

**Status**: ✅ Production Ready  
**Tested**: November 10, 2025  
**Repository**: https://github.com/amalykhi/flightctl-rpm-verification

