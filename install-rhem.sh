#!/usr/bin/env bash
#
# Install Red Hat Edge Manager (RHEM / Flight Control) standalone on RHEL,
# version-pinned, from the edge-manager subscription repo. Optionally builds a
# bootc device agent image and enrolls a device.
#
# RHEL-version-agnostic: proven on RHEL 10.1 (defaults below) and RHEL 9.6
# (override --repo / --agent-base — see the RHEL 9 example). GA release 1.2.1.
#
# Docs: https://docs.redhat.com/en/documentation/red_hat_edge_manager
#
# Usage:
#   ./install-rhem.sh --version 1.2.1 --base-domain <fqdn> [options]
#
# RHEL 10 (defaults):
#   ./install-rhem.sh --base-domain rhem.example.com --build-agent
#
# RHEL 9 (override repo + agent base):
#   ./install-rhem.sh --base-domain rhem.example.com \
#       --repo edge-manager-1.2-for-rhel-9-x86_64-rpms \
#       --agent-base registry.redhat.io/rhel9/rhel-bootc:9.6 --build-agent
#
# Options:
#   --version <v>       RPM version to pin (default 1.2.1; or full 1.2.1-1.el10)
#   --repo <r>          subscription repo (default RHEL 10 edge-manager-1.2)
#   --base-domain <d>   FQDN/hostname for the UI/API (required; IPs are rejected)
#   --admin-user <u>    admin username (default: admin)
#   --with-agent        also dnf-install flightctl-agent on THIS host
#   --build-agent       build a device bootc image (agent + enroll config)
#   --agent-base <ref>  base bootc image (default: registry.redhat.io/rhel10/rhel-bootc:10.1)
#   --agent-image <t>   image tag to build (default: flightctl-agent-rhelN:<ver>
#                       derived from --agent-base's RHEL major, N=9 or 10)
#   --agent-out <dir>   output dir for bootc-image-builder (qcow2)
#   --agent-export <t>  qcow2 | iso | vmdk (default: qcow2)
#   --boot-device       boot the exported qcow2 as a nested libvirt VM and add a
#                       libvirt DNS host entry for --base-domain (needs --build-agent)
#   --force             re-do steps even if already satisfied (reinstall/restart)
#   --no-clean          keep any existing deployment (default: clean + reinstall)
#   --cleanup           full uninstall of RHEM (destructive), then exit
#   --list              only show available versions, then exit
#
# By default every run cleans any existing RHEM deployment first, then reinstalls
# from scratch. Use --no-clean to run idempotently on top of an existing install.
#
# Env: ADMIN_PASSWORD='...'  set the admin password non-interactively
#
# Prereqs you have already done:
#   - subscription-manager repos --enable=<repo>
#   - podman login registry.redhat.io
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults / args
# ---------------------------------------------------------------------------
FCVER="1.2.1"                  # e.g. 1.2.1  (or full 1.2.1-1.el10)
REPO="edge-manager-1.2-for-rhel-10-x86_64-rpms"
BASE_DOMAIN=""                 # DNS name to reach the UI/API (FQDN, not IP)
ADMIN_USER="admin"
INSTALL_AGENT=0                # install flightctl-agent RPM on THIS host too (test device)
LIST_ONLY=0                    # only show available versions, then exit
FORCE=0                        # re-do steps even if already satisfied (reinstall/restart)
CLEANUP=0                      # full uninstall of RHEM, then exit
CLEAN_FIRST=1                  # clean any existing RHEM before installing (default on); --no-clean to disable

# --- device bootc image build + enrollment (--build-agent) ---
# There is NO prebuilt rhem/flightctl-device image. The documented released
# pattern is to build your own bootc image: start FROM the RHEL bootc base,
# dnf-install flightctl-agent from the edge-manager repo, enable its service,
# and embed the enrollment config.
BUILD_AGENT=0                  # build a device bootc image with the agent + enrollment config
BOOT_DEVICE=0                  # boot the exported qcow2 as a nested libvirt VM + add DNS host entry
AGENT_BASE="registry.redhat.io/rhel10/rhel-bootc:10.1"   # RHEL 10 bootc base (image mode)
AGENT_IMAGE=""                # image tag to build; default derived from AGENT_BASE's RHEL major
AGENT_OUT="./agent-image"     # output dir for bootc-image-builder (qcow2)
AGENT_EXPORT="qcow2"          # qcow2 | iso | vmdk
ENROLL_EXPIRE="365d"          # enrollment cert lifetime

# Ports the device agent uses to reach the server (opened in firewalld if active).
RHEM_PORTS=(7443 3443)         # 7443 management/gRPC, 3443 UI/enrollment
LIBVIRT_NET="default"          # libvirt network the nested device boots on
LIBVIRT_HOST_IP="192.168.124.1" # virbr host IP that serves libvirt dnsmasq DNS

usage() {
    grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -60
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)     FCVER="$2"; shift 2 ;;
        --repo)        REPO="$2"; shift 2 ;;
        --base-domain) BASE_DOMAIN="$2"; shift 2 ;;
        --admin-user)  ADMIN_USER="$2"; shift 2 ;;
        --with-agent)  INSTALL_AGENT=1; shift ;;
        --build-agent) BUILD_AGENT=1; shift ;;
        --boot-device) BOOT_DEVICE=1; shift ;;
        --agent-base)  AGENT_BASE="$2"; shift 2 ;;
        --agent-image) AGENT_IMAGE="$2"; shift 2 ;;
        --agent-out)   AGENT_OUT="$2"; shift 2 ;;
        --agent-export) AGENT_EXPORT="$2"; shift 2 ;;
        --force)       FORCE=1; shift ;;
        --cleanup)     CLEANUP=1; shift ;;
        --no-clean)    CLEAN_FIRST=0; shift ;;
        --list)        LIST_ONLY=1; shift ;;
        -h|--help)     usage 0 ;;
        *) echo "Unknown arg: $1" >&2; usage 1 ;;
    esac
done

log() { echo -e "\n=== $* ==="; }

# ---------------------------------------------------------------------------
# --cleanup: full uninstall of RHEM, then exit
# ---------------------------------------------------------------------------
# Tears down a Flight Control / RHEM deployment completely:
#   stop+disable the target, remove the RPMs, delete /etc/flightctl, and prune
#   all flightctl containers, pods, volumes, and images. DESTRUCTIVE: removes
#   the running deployment and any enrolled devices' server-side state.
cleanup_rhem() {
    log "CLEANUP: full uninstall of RHEM (destructive)"

    echo "-> Stopping and disabling flightctl.target"
    sudo systemctl disable --now flightctl.target 2>/dev/null || true
    # Stop any lingering flightctl-*.service units
    mapfile -t units < <(systemctl list-units --all --plain --no-legend 'flightctl-*' 2>/dev/null | awk '{print $1}')
    if [[ ${#units[@]} -gt 0 ]]; then
        sudo systemctl stop "${units[@]}" 2>/dev/null || true
    fi

    echo "-> Removing flightctl RPMs"
    sudo dnf remove -y 'flightctl-services*' 'flightctl-cli*' 'flightctl-agent*' 2>/dev/null || true

    echo "-> Pruning flightctl containers, pods, and volumes (root podman)"
    # Containers
    mapfile -t ctrs < <(sudo podman ps -a --filter name=flightctl --format '{{.ID}}' 2>/dev/null)
    [[ ${#ctrs[@]} -gt 0 ]] && sudo podman rm -f "${ctrs[@]}" 2>/dev/null || true
    # Pods
    mapfile -t pods < <(sudo podman pod ps --filter name=flightctl --format '{{.ID}}' 2>/dev/null)
    [[ ${#pods[@]} -gt 0 ]] && sudo podman pod rm -f "${pods[@]}" 2>/dev/null || true
    # Volumes (names contain flightctl)
    mapfile -t vols < <(sudo podman volume ls --format '{{.Name}}' 2>/dev/null | grep -i flightctl || true)
    [[ ${#vols[@]} -gt 0 ]] && sudo podman volume rm -f "${vols[@]}" 2>/dev/null || true
    # Images
    mapfile -t imgs < <(sudo podman images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -Ei 'rhem/flightctl|flightctl' || true)
    [[ ${#imgs[@]} -gt 0 ]] && sudo podman rmi -f "${imgs[@]}" 2>/dev/null || true

    echo "-> Removing config and state directories"
    sudo rm -rf /etc/flightctl 2>/dev/null || true
    # Leftover quadlet unit definitions installed by the RPM
    sudo rm -f /etc/containers/systemd/flightctl-*.container \
               /etc/containers/systemd/flightctl-*.network \
               /etc/containers/systemd/flightctl-*.volume \
               /etc/containers/systemd/flightctl*.target 2>/dev/null || true
    sudo systemctl daemon-reload 2>/dev/null || true

    echo "-> Removing local flightctl CLI client config"
    rm -rf "${HOME}/.config/flightctl" "${HOME}/.flightctl" 2>/dev/null || true

    log "CLEANUP complete"
    echo "Verify: rpm -qa | grep flightctl ; sudo podman ps -a | grep flightctl"
}

if [[ "$CLEANUP" -eq 1 ]]; then
    cleanup_rhem
    exit 0
fi

# ---------------------------------------------------------------------------
# Open the RHEM server ports in firewalld (fix #5)
# ---------------------------------------------------------------------------
# On RHEL 9 the libvirt firewalld zone permitted only dhcp/dns/ssh/tftp, so a
# nested device could not reach 7443 (management/gRPC) or 3443 (UI/enrollment)
# and enrollment silently stalled. Open both, permanently, when firewalld is
# active. No-op (with a note) when firewalld is not running.
open_firewall_ports() {
    if ! command -v firewall-cmd >/dev/null 2>&1; then
        echo "firewalld not installed; skipping port opening (ensure ${RHEM_PORTS[*]} reachable)."
        return 0
    fi
    if ! sudo firewall-cmd --state >/dev/null 2>&1; then
        echo "firewalld not active; skipping port opening (ensure ${RHEM_PORTS[*]} reachable)."
        return 0
    fi
    log "Opening RHEM ports in firewalld: ${RHEM_PORTS[*]}/tcp"
    local changed=0 p
    for p in "${RHEM_PORTS[@]}"; do
        # Runtime (immediate) + permanent (survives reload/reboot).
        sudo firewall-cmd --add-port="${p}/tcp" >/dev/null 2>&1 || true
        if sudo firewall-cmd --permanent --query-port="${p}/tcp" >/dev/null 2>&1; then
            echo "  ${p}/tcp already permitted (permanent)."
        else
            sudo firewall-cmd --permanent --add-port="${p}/tcp" >/dev/null 2>&1 \
                && { echo "  opened ${p}/tcp (permanent)."; changed=1; } \
                || echo "  WARN: could not open ${p}/tcp." >&2
        fi
    done
    [[ "$changed" -eq 1 ]] && sudo firewall-cmd --reload >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Boot the exported device as a nested libvirt VM + libvirt DNS entry (fix #6)
# ---------------------------------------------------------------------------
# The nested device resolves --base-domain through libvirt's dnsmasq, so we add
# a dns-host entry mapping baseDomain -> the host IP on the libvirt network, then
# import and boot the exported qcow2 on that same network. Requires --build-agent
# (so the qcow2 exists) and libvirt tooling (virsh/virt-install).
boot_device_vm() {
    local disk vm_name os_variant libvirt_disk gw
    disk="$(realpath "${AGENT_OUT}")/${AGENT_EXPORT}/disk.${AGENT_EXPORT}"
    vm_name="rhem-device-${FCVER//./-}"

    # Pick the libvirt os-variant from the agent base image's RHEL major.
    os_variant="rhel10.2"
    case "${AGENT_BASE}" in
        *rhel9*) os_variant="rhel9.6" ;;
    esac

    if ! command -v virsh >/dev/null 2>&1 || ! command -v virt-install >/dev/null 2>&1; then
        echo "WARN: virsh/virt-install not found; skipping --boot-device." >&2
        echo "      Install libvirt/virt-install or boot ${disk} manually." >&2
        return 0
    fi
    if [[ ! -f "$disk" ]]; then
        echo "WARN: expected disk ${disk} not found; skipping boot." >&2
        return 0
    fi

    # Determine the gateway IP that serves DNS on the libvirt network, rather
    # than assuming a fixed value — nested hosts vary (e.g. 192.168.122.1 vs
    # 192.168.124.1). Fall back to the configured default if it can't be read.
    gw="$(sudo virsh net-dumpxml "${LIBVIRT_NET}" 2>/dev/null \
            | grep -oP "ip address='\K[0-9.]+" | head -1)"
    [[ -n "$gw" ]] && LIBVIRT_HOST_IP="$gw"

    # qemu (the qemu/libvirt user) cannot read a disk under a locked-down $HOME
    # (0700). Copy the exported image into the libvirt images pool where qemu has
    # access, and boot from that copy.
    libvirt_disk="/var/lib/libvirt/images/${vm_name}.${AGENT_EXPORT}"
    log "Copying device disk to ${libvirt_disk} (qemu-readable)"
    sudo install -m 0644 "$disk" "$libvirt_disk"
    sudo chown qemu:qemu "$libvirt_disk" 2>/dev/null || true
    sudo restorecon "$libvirt_disk" 2>/dev/null || true
    disk="$libvirt_disk"

    log "Adding libvirt DNS host entry: ${BASE_DOMAIN} -> ${LIBVIRT_HOST_IP} (net ${LIBVIRT_NET})"
    # Idempotent: remove any stale entry for this hostname first, then add.
    sudo virsh net-update "${LIBVIRT_NET}" delete dns-host \
        "<host ip='${LIBVIRT_HOST_IP}'><hostname>${BASE_DOMAIN}</hostname></host>" \
        --live --config >/dev/null 2>&1 || true
    sudo virsh net-update "${LIBVIRT_NET}" add dns-host \
        "<host ip='${LIBVIRT_HOST_IP}'><hostname>${BASE_DOMAIN}</hostname></host>" \
        --live --config \
        && echo "OK: DNS host entry added." \
        || echo "WARN: could not add DNS host entry (add it manually)." >&2

    log "Booting device VM '${vm_name}' from ${disk} on network ${LIBVIRT_NET}"
    # Tear down any prior device VM of the same name so we boot a fresh one.
    if sudo virsh dominfo "${vm_name}" >/dev/null 2>&1; then
        echo "Removing existing VM '${vm_name}' for a fresh boot."
        sudo virsh destroy "${vm_name}" >/dev/null 2>&1 || true
        sudo virsh undefine "${vm_name}" --nvram >/dev/null 2>&1 \
            || sudo virsh undefine "${vm_name}" >/dev/null 2>&1 || true
    fi
    sudo virt-install \
        --name "${vm_name}" \
        --memory 2048 --vcpus 2 \
        --import --disk "path=${disk},format=${AGENT_EXPORT}" \
        --os-variant "${os_variant}" \
        --network network="${LIBVIRT_NET}" \
        --graphics none --noautoconsole \
        && echo "Device VM '${vm_name}' started; it will phone home for enrollment." \
        || echo "WARN: virt-install failed; boot ${disk} manually." >&2
}

# ---------------------------------------------------------------------------
# 0. Sanity: repo enabled + registry login
# ---------------------------------------------------------------------------
log "Checking prerequisites"
if ! sudo subscription-manager repos --list-enabled 2>/dev/null | grep -q "$REPO"; then
    echo "ERROR: repo '$REPO' is not enabled. Run:" >&2
    echo "  sudo subscription-manager repos --enable=$REPO" >&2
    exit 1
fi
if ! sudo podman login --get-login registry.redhat.io >/dev/null 2>&1; then
    echo "ERROR: not logged in to registry.redhat.io. Run:" >&2
    echo "  sudo podman login registry.redhat.io" >&2
    exit 1
fi
echo "Repo enabled and registry login OK."

# ---------------------------------------------------------------------------
# 1. Show available versions
# ---------------------------------------------------------------------------
log "Available versions in $REPO"
sudo dnf --showduplicates list \
    flightctl-services flightctl-cli flightctl-agent 2>/dev/null || true

if [[ "$LIST_ONLY" -eq 1 ]]; then
    echo -e "\nRe-run with:  $0 --version <ver> --base-domain <fqdn>"
    exit 0
fi

# ---------------------------------------------------------------------------
# Require version + base domain for an actual install
# ---------------------------------------------------------------------------
if [[ -z "$FCVER" ]]; then
    echo "ERROR: --version is required (pick one from the list above)." >&2
    echo "       e.g. --version 1.2.1   or   --version 1.2.1-1.el10" >&2
    exit 1
fi
if [[ -z "$BASE_DOMAIN" ]]; then
    echo "ERROR: --base-domain is required (must be a hostname/FQDN)." >&2
    exit 1
fi
# RHEM's config validator REQUIRES an FQDN and rejects bare IPs — an IP here
# makes flightctl-certs-init/api/db-wait crash-loop with:
#   global.baseDomain: Invalid value ... (not an IP address)
# Fail fast with a clear message instead.
if [[ "$BASE_DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$BASE_DOMAIN" == *:* ]]; then
    echo "ERROR: --base-domain '$BASE_DOMAIN' looks like an IP address." >&2
    echo "       RHEM requires an FQDN/hostname (e.g. rhem.example.com)." >&2
    echo "       Use a resolvable name; add an /etc/hosts entry if needed." >&2
    exit 1
fi
# Must match RHEM's own hostname regex (lowercase labels, dot-separated).
if ! [[ "$BASE_DOMAIN" =~ ^([a-z0-9]([-a-z0-9]*[a-z0-9])?\.)*[a-z]([-a-z0-9]*[a-z0-9])?$ ]]; then
    echo "ERROR: --base-domain '$BASE_DOMAIN' is not a valid hostname/FQDN." >&2
    echo "       Expected pattern like 'host.example.com' (lowercase)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 1b. Clean any existing RHEM first (default), then reinstall from scratch
# ---------------------------------------------------------------------------
# Every run starts from a clean slate: fully uninstall any prior deployment,
# then reinstall. Pass --no-clean to keep an existing deployment and run the
# idempotent path instead. Cleaning implies a full (re)install, so force the
# install/restart steps below.
if [[ "$CLEAN_FIRST" -eq 1 ]]; then
    cleanup_rhem
    FORCE=1
else
    echo "--no-clean: keeping any existing deployment (idempotent run)."
fi

# ---------------------------------------------------------------------------
# 2. Install version-pinned services
# ---------------------------------------------------------------------------
log "Installing flightctl-services-$FCVER"
if [[ "$FORCE" -eq 0 ]] && rpm -q "flightctl-services-$FCVER" >/dev/null 2>&1; then
    echo "Already installed: $(rpm -q flightctl-services) — skipping (use --force to reinstall)."
else
    sudo dnf install -y "flightctl-services-$FCVER"
fi

# ---------------------------------------------------------------------------
# 3. Configure baseDomain
# ---------------------------------------------------------------------------
log "Setting baseDomain=$BASE_DOMAIN in /etc/flightctl/service-config.yaml"
if [[ -f /etc/flightctl/service-config.yaml ]]; then
    if sudo grep -qE '^\s*baseDomain:' /etc/flightctl/service-config.yaml; then
        sudo sed -i -E "s|^(\s*baseDomain:).*|\1 ${BASE_DOMAIN}|" \
            /etc/flightctl/service-config.yaml
    else
        echo "baseDomain: ${BASE_DOMAIN}" | sudo tee -a /etc/flightctl/service-config.yaml >/dev/null
    fi
    sudo grep baseDomain: /etc/flightctl/service-config.yaml
else
    echo "WARNING: /etc/flightctl/service-config.yaml not found; check the RPM install." >&2
fi

# ---------------------------------------------------------------------------
# 4. Confirm which image tags the quadlets reference (RPM ver != image tag)
# ---------------------------------------------------------------------------
log "Container image tags referenced by the install"
sudo grep -rhn "registry.redhat.io/rhem" \
    /etc/containers/systemd/ /etc/flightctl/ 2>/dev/null | sort -u || true
echo "(Verify the tags above match ${FCVER%%-*}; edit before starting if not.)"

# ---------------------------------------------------------------------------
# 5. Start & enable the target
# ---------------------------------------------------------------------------
log "Starting flightctl.target (pulls images on first run; can take a few min)"
if [[ "$FORCE" -eq 0 ]] && sudo systemctl is-active --quiet flightctl.target; then
    echo "flightctl.target already active — leaving running services untouched (use --force to restart)."
else
    sudo systemctl enable --now flightctl.target
fi

# Open the ports the device agent needs to reach this server (fix #5).
open_firewall_ports

# ---------------------------------------------------------------------------
# 6. Verify services
# ---------------------------------------------------------------------------
log "Service status"
sudo systemctl list-units 'flightctl-*.service' --no-pager || true
echo "(active(exited)=one-shot init, active(running)=persistent; both are healthy)"

# ---------------------------------------------------------------------------
# 7. Create admin user via PAM issuer
# ---------------------------------------------------------------------------
if [[ "$FORCE" -eq 0 ]] && sudo podman exec flightctl-pam-issuer id "$ADMIN_USER" >/dev/null 2>&1; then
    log "Admin user '$ADMIN_USER' already exists — skipping (use --force to reset password)."
else
    log "Creating admin user '$ADMIN_USER'"
    if [[ -n "${ADMIN_PASSWORD:-}" ]]; then
        # The flightctl CLI treats a whitespace-only password as empty and
        # refuses to log in ("--username and --password must be used together"),
        # so reject it here rather than create an unusable account.
        if [[ -z "${ADMIN_PASSWORD// }" ]]; then
            echo "ERROR: ADMIN_PASSWORD is empty/whitespace-only." >&2
            echo "       flightctl login rejects such passwords; use a real value." >&2
            exit 1
        fi
        HASH="$(openssl passwd -6 "$ADMIN_PASSWORD")"      # non-interactive
    else
        HASH="$(openssl passwd -6)"                        # prompts
    fi
    sudo podman exec flightctl-pam-issuer groupadd -f flightctl-admin || true
    if sudo podman exec flightctl-pam-issuer id "$ADMIN_USER" >/dev/null 2>&1; then
        echo "User '$ADMIN_USER' already exists; updating password."
        sudo podman exec flightctl-pam-issuer usermod -p "$HASH" "$ADMIN_USER"
    else
        sudo podman exec flightctl-pam-issuer useradd -m --groups flightctl-admin \
            -p "$HASH" "$ADMIN_USER"
    fi
fi

# ---------------------------------------------------------------------------
# 8. Install matching CLI (must equal server version)
# ---------------------------------------------------------------------------
log "Installing flightctl-cli-$FCVER (must match server)"
if [[ "$FORCE" -eq 0 ]] && rpm -q "flightctl-cli-$FCVER" >/dev/null 2>&1; then
    echo "Already installed: $(rpm -q flightctl-cli) — skipping (use --force to reinstall)."
else
    sudo dnf install -y "flightctl-cli-$FCVER"
fi
flightctl version || true

# ---------------------------------------------------------------------------
# 9. Optional: install agent RPM on this host (same-host test device)
# ---------------------------------------------------------------------------
if [[ "$INSTALL_AGENT" -eq 1 ]]; then
    log "Installing flightctl-agent-$FCVER on this host (test device)"
    sudo dnf install -y "flightctl-agent-$FCVER"
    echo "NOTE: for real edge devices the agent ships inside the bootc image,"
    echo "      not via dnf on the server."
fi

# ---------------------------------------------------------------------------
# 10. Optional: build a bootc agent image + enroll a device
# ---------------------------------------------------------------------------
# Build a RHEL bootc image with the flightctl agent + an embedded enrollment
# config, export a qcow2, then approve the enrollment request on the server.
if [[ "$BUILD_AGENT" -eq 1 ]]; then
    log "Building bootc agent image with embedded enrollment config"

    # Derive the local image tag from the agent base's RHEL major unless the
    # caller overrode it with --agent-image (e.g. flightctl-agent-rhel9:1.2.1
    # for a RHEL 9 base, flightctl-agent-rhel10:1.2.1 for RHEL 10).
    if [[ -z "$AGENT_IMAGE" ]]; then
        rhel_major="rhel10"
        case "$AGENT_BASE" in
            *rhel9*) rhel_major="rhel9" ;;
        esac
        AGENT_IMAGE="localhost/flightctl-agent-${rhel_major}:${FCVER}"
    fi
    echo "Image tag: ${AGENT_IMAGE}"

    # Tooling check (docs: podman >=5.0, skopeo >=1.14, bootc-image-builder)
    command -v podman >/dev/null || { echo "ERROR: podman is required" >&2; exit 1; }
    if ! command -v skopeo >/dev/null; then
        echo "skopeo not found; installing..."
        sudo dnf install -y skopeo
    fi
    command -v skopeo >/dev/null || { echo "ERROR: skopeo install failed" >&2; exit 1; }
    echo "skopeo present: $(skopeo --version)"
    command -v jq >/dev/null || sudo dnf install -y jq
    command -v jq >/dev/null || { echo "ERROR: jq is required for tag preflight" >&2; exit 1; }

    # Preflight: ensure the RHEL 10.2 post-quantum (ML-DSA) release key is
    # imported. RHEL 10.2 dual-signs packages with "release key 4" (05707a62).
    # A host still on the 10.1 image does not have this key, so any dnf install
    # of el10_2 content (including virt tooling, or agent deps) fails with
    # "GPG check FAILED / NOKEY". We import it from the newer redhat-release rpm
    # (the legitimate source) rather than bypassing GPG.
    #
    # This only matters for RHEL 10 agent bases — skip it entirely on RHEL 9,
    # where the key does not exist and the import is a pure no-op. The whole
    # block is wrapped so a failure here (e.g. a subscription hiccup) only WARNs
    # and never aborts the build under `set -e`.
    if [[ "$AGENT_BASE" == *rhel10* ]] \
       && ! rpm -q gpg-pubkey --qf '%{version}\n' 2>/dev/null | grep -q '^05707a62$'; then
        echo "RHEL 10.2 PQC release key (05707a62) missing; importing from redhat-release..."
        import_pqc_key() {
            local keytmp rr
            keytmp="$(mktemp -d)"
            # Send dnf's "Updating Subscription Management..." chatter to stderr so
            # only the rpm path is captured; then pick the newest downloaded rpm.
            sudo dnf download --downloaddir="$keytmp" redhat-release >&2 2>/dev/null || true
            rr="$(ls "$keytmp"/redhat-release-*.rpm 2>/dev/null | sort -V | tail -1)"
            if [[ -n "$rr" && -f "$rr" ]]; then
                ( cd "$keytmp" && rpm2cpio "$rr" | cpio -idm ./etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release >/dev/null 2>&1 )
                if sudo rpm --import "$keytmp/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release" 2>/dev/null; then
                    echo "OK: imported release key from $(basename "$rr")"
                else
                    echo "WARN: could not import PQC key; el10_2 installs may fail GPG check" >&2
                fi
            else
                echo "WARN: could not download redhat-release to obtain PQC key" >&2
            fi
            rm -rf "$keytmp"
        }
        import_pqc_key || echo "WARN: PQC key import step failed (continuing)" >&2
    else
        echo "OK: RHEL 10.2 PQC release key not required for this base (${AGENT_BASE##*/})"
    fi

    # Preflight: confirm the agent base image tag actually exists before building.
    # AGENT_BASE is "<repo>:<tag>" — split on the LAST colon so ports in the
    # registry host (rare) don't break the split.
    base_repo="${AGENT_BASE%:*}"
    base_tag="${AGENT_BASE##*:}"
    base_registry="${base_repo%%/*}"   # first path segment = registry host

    # Ensure we're logged in to the base image's registry (public quay needs no
    # auth; registry.redhat.io does). Reuse existing creds if already logged in.
    log "Checking registry login for ${base_registry}"
    if sudo skopeo list-tags "docker://${base_repo}" >/dev/null 2>&1; then
        echo "OK: ${base_registry} is reachable (already authenticated or public)"
    else
        echo "Not authenticated (or private) to ${base_registry}; logging in..."
        sudo podman login "${base_registry}"
    fi

    log "Verifying base image tag exists: ${base_tag} in ${base_repo}"
    if sudo skopeo list-tags "docker://${base_repo}" 2>/dev/null \
         | jq -e --arg t "${base_tag}" '.Tags | index($t)' >/dev/null; then
        echo "OK: found tag ${base_tag}"
    else
        echo "ERROR: tag '${base_tag}' not found in ${base_repo} (or repo not accessible)." >&2
        echo "Available tags:" >&2
        sudo skopeo list-tags "docker://${base_repo}" 2>/dev/null \
            | jq -r '.Tags[]' | head -30 >&2 || \
            echo "  (could not list tags; check the repo path / registry login)" >&2
        echo "Re-run with a valid --agent-base <repo>:<tag>." >&2
        exit 1
    fi

    workdir="$(mktemp -d)"
    echo "Build workdir: $workdir"

    # (a) Log in the CLI so we can request an enrollment cert.
    #     Use ADMIN_PASSWORD when set so the build runs non-interactively (the
    #     CLI requires --username and --password together; a lone --username
    #     errors). The server presents a self-signed cert, so skip TLS verify.
    echo "Logging in flightctl CLI (needed to request enrollment config)..."
    login_args=(--username "${ADMIN_USER}" --insecure-skip-tls-verify)
    if [[ -n "${ADMIN_PASSWORD:-}" ]]; then
        login_args+=(--password "${ADMIN_PASSWORD}")
    fi
    flightctl login "https://${BASE_DOMAIN}:3443" "${login_args[@]}"

    # (b) Request an agent config with embedded enrollment certificate.
    #     SECRET: contains cert material — never commit config.yaml.
    log "Requesting enrollment config (expires ${ENROLL_EXPIRE})"
    umask 077
    flightctl certificate request \
        --signer=enrollment \
        --expiration="${ENROLL_EXPIRE}" \
        --output=embedded > "${workdir}/config.yaml"
    echo "Wrote ${workdir}/config.yaml (treat as a secret)"

    # (c) Containerfile: layer flightctl-agent onto the RHEL bootc base and
    #     embed the enrollment config. Agent reads /etc/flightctl/config.yaml on
    #     first boot. bootc-fetch-apply-updates.timer is masked because updates
    #     are driven by Red Hat Edge Manager, not bootc's own timer.
    #     The dnf install needs the edge-manager repo entitlement, which we pass
    #     through from the host's subscription (podman build --volume of the
    #     entitlement + rhsm dirs; RHEL bootc honors these at build time).
    # Pin the agent to the SAME version as the server. Other edge-manager repos
    # (e.g. edge-manager-1.3) may be enabled on the host and would otherwise win
    # dnf's version resolution, producing an agent that mismatches the 1.2.1
    # server. We pin flightctl-agent-<FCVER> and disable the other 1.x streams.
    agent_pkg="flightctl-agent-${FCVER}"
    cat > "${workdir}/Containerfile" <<CF
FROM ${AGENT_BASE}
RUN dnf -y install --disablerepo='edge-manager-*' --enablerepo='${REPO}' ${agent_pkg} && \\
    dnf -y clean all && \\
    systemctl enable flightctl-agent.service && \\
    systemctl mask bootc-fetch-apply-updates.timer
COPY config.yaml /etc/flightctl/config.yaml
CF

    # (d) Build the bootc container image, passing host subscription entitlement
    #     so the edge-manager repo is available inside the build.
    log "Building bootc image ${AGENT_IMAGE} from ${AGENT_BASE}"
    sudo podman build -t "${AGENT_IMAGE}" \
        -v /etc/pki/entitlement:/etc/pki/entitlement:ro \
        -v /etc/rhsm:/etc/rhsm:ro \
        -v /etc/yum.repos.d/redhat.repo:/etc/yum.repos.d/redhat.repo:ro \
        -f "${workdir}/Containerfile" "${workdir}"

    # (e) Export a disk image (qcow2/iso/vmdk) with bootc-image-builder.
    #     Use a bootc-image-builder matching the base image's RHEL major so the
    #     builder content aligns with the agent image (RHEL 9 vs 10).
    bib_image="registry.redhat.io/rhel10/bootc-image-builder:latest"
    case "$base_repo" in
        *rhel9*) bib_image="registry.redhat.io/rhel9/bootc-image-builder:latest" ;;
    esac
    log "Exporting ${AGENT_EXPORT} to ${AGENT_OUT} via ${bib_image}"
    mkdir -p "${AGENT_OUT}"
    sudo podman run --rm -it --privileged --pull=newer \
        --security-opt label=type:unconfined_t \
        -v "$(realpath "${AGENT_OUT}")":/output \
        -v /var/lib/containers/storage:/var/lib/containers/storage \
        "${bib_image}" \
        --type "${AGENT_EXPORT}" \
        --local "${AGENT_IMAGE}"

    echo "Disk image written under ${AGENT_OUT}/ (boot this in your VM)."
    rm -f "${workdir}/config.yaml"   # scrub the secret from the temp dir

    # (f) Optionally add the libvirt DNS host entry + boot the device (fix #6)
    if [[ "$BOOT_DEVICE" -eq 1 ]]; then
        boot_device_vm
    else
        cat <<EOF

To boot the exported device manually you must first make baseDomain resolvable
to this host on the libvirt network (the device resolves it via libvirt
dnsmasq), then boot the qcow2:

  # add a libvirt DNS host entry mapping baseDomain -> host IP on the libvirt net
  sudo virsh net-update ${LIBVIRT_NET} add dns-host \\
    "<host ip='${LIBVIRT_HOST_IP}'><hostname>${BASE_DOMAIN}</hostname></host>" \\
    --live --config

  # then boot ${AGENT_OUT}/qcow2/disk.qcow2 as a VM on the ${LIBVIRT_NET} network
  # (virt-install / your usual tooling). Re-run with --boot-device to automate.
EOF
    fi

    # (g) Approve the enrollment once the device boots and phones home
    log "Waiting for the device to submit an enrollment request"
    echo "Once the device boots and phones home, approve it:"
    cat <<EOF
  # list pending enrollment requests
  flightctl get enrollmentrequests --field-selector="status.approval.approved!=true"

  # approve by name (add labels as desired)
  flightctl approve -l site=test-lab enrollmentrequest/<device_name>

  # confirm it registered
  flightctl get devices
EOF
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
log "Done"
cat <<EOF
UI:    https://${BASE_DOMAIN}/          (web console, port 443; self-signed cert)
API:   https://${BASE_DOMAIN}:3443      (CLI/enrollment endpoint; 7443 for agents)
Login: flightctl login https://${BASE_DOMAIN}:3443 --username ${ADMIN_USER} --password <password> --insecure-skip-tls-verify
Logs:  journalctl -u flightctl-<service> -b --no-pager
EOF
