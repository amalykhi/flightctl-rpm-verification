# Installing Red Hat Edge Manager (RHEM) from a subscription

`install-rhem.sh` installs Red Hat Edge Manager (RHEM / Flight Control) standalone
on a RHEL host from the edge-manager subscription repo, verifies it, and
optionally builds a bootc device agent image and enrolls a device.

The script is **RHEL-version-agnostic**. It is proven on:

| Host | baseDomain | Services + CLI | Agent | Result |
|------|------------|----------------|-------|--------|
| RHEL 10.1 (rhel10-fips-vm) | `rhel10-fips-vm.local` | `1.2.1-1.el10` | `1.2.1` | device Online / UpToDate |
| RHEL 9.6 (eurolinux9 VM)   | `eurolinux9.lab`       | `1.2.1-1.el9`  | `1.2.1` | device Online (firewall ports opened) |

Docs: <https://docs.redhat.com/en/documentation/red_hat_edge_manager>

## Prerequisites

Done once on the target host, before running the script:

```bash
sudo subscription-manager repos --enable=edge-manager-1.2-for-rhel-10-x86_64-rpms
sudo podman login registry.redhat.io
```

## Quick start

RHEL 10 (defaults — version 1.2.1, RHEL 10 repo + bootc base):

```bash
ADMIN_PASSWORD='<pw>' ./install-rhem.sh --base-domain rhem.example.com --build-agent
```

RHEL 9 (override the repo and the agent base image):

```bash
ADMIN_PASSWORD='<pw>' ./install-rhem.sh --base-domain rhem.example.com \
    --repo edge-manager-1.2-for-rhel-9-x86_64-rpms \
    --agent-base registry.redhat.io/rhel9/rhel-bootc:9.6 --build-agent
```

## Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--version <v>` | `1.2.1` | RPM version to pin (or full `1.2.1-1.el10`) |
| `--repo <r>` | `edge-manager-1.2-for-rhel-10-x86_64-rpms` | subscription repo |
| `--base-domain <d>` | *(required)* | FQDN/hostname for the UI/API; **IPs are rejected** |
| `--admin-user <u>` | `admin` | admin username |
| `--with-agent` | off | also `dnf install flightctl-agent` on this host |
| `--build-agent` | off | build a device bootc image (agent + enroll config) |
| `--agent-base <ref>` | `registry.redhat.io/rhel10/rhel-bootc:10.1` | base bootc image |
| `--agent-export <t>` | `qcow2` | `qcow2` \| `iso` \| `vmdk` |
| `--boot-device` | off | add libvirt DNS entry + boot the qcow2 as a nested VM |
| `--force` | off | re-do steps even if already satisfied |
| `--cleanup` | — | full uninstall of RHEM (destructive), then exit |
| `--list` | — | show available versions, then exit |

Env: `ADMIN_PASSWORD='...'` sets the admin password non-interactively.

## What it does

1. **Validate** `--base-domain` is an FQDN (RHEM's config validator rejects IPs,
   which otherwise crash-loop certs-init/api/gateway). Reject empty/whitespace
   `ADMIN_PASSWORD` (RHEM `flightctl login` treats it as empty).
2. Verify repo enabled + `registry.redhat.io` login; confirm 1.2.1 is available.
3. `dnf install flightctl-services flightctl-cli` (pinned to `--version`).
4. Set `baseDomain`, start `flightctl.target`, create the admin user (OIDC via
   `flightctl-pam-issuer`, password hashed with `openssl passwd -6`).
5. **Open firewalld ports** 7443 (management/gRPC) and 3443 (UI/enrollment),
   runtime + permanent, when firewalld is active.
6. With `--build-agent`: build a bootc image `FROM` the RHEL bootc base, install
   the version-pinned agent (other `edge-manager-*` streams disabled so a newer
   1.3 repo can't win resolution), embed the enrollment config, export a disk.
7. With `--boot-device`: add a libvirt `dns-host` entry mapping `baseDomain` to
   the host IP on the libvirt network, then boot the qcow2 as a nested VM.

The install is idempotent — re-runs skip already-satisfied steps unless `--force`.

## Environmental fixes captured in the script

These were discovered during real runs and are handled automatically:

- **baseDomain must be an FQDN, not an IP** — validated in-script.
- **Whitespace-only admin password** is rejected by RHEM — validated in-script.
- **RHEL 10.1→10.2 PQC signing key (`05707a62`, ML-DSA)** — a host on the 10.1
  image lacks it, so `el10_2` content fails GPG (`NOKEY`). Imported from the
  `redhat-release` rpm during `--build-agent` preflight. Harmless no-op on RHEL 9.
- **Agent version drift** — an enabled `edge-manager-1.3` repo would make an
  unpinned `dnf install flightctl-agent` pull 1.3.0. Fixed by pinning +
  `--disablerepo='edge-manager-*'`.
- **firewalld blocks device→server** — ports 7443/3443 are opened permanently
  when firewalld is active.
- **libvirt DNS for the device** — the device resolves `baseDomain` via libvirt
  dnsmasq; `--boot-device` adds the `dns-host` entry. Without `--boot-device`,
  the script prints the manual `virsh net-update` command.

## Secrets — never commit

- `config.yaml` — the embedded **enrollment certificate** (`--build-agent`
  scrubs the temp copy after building). Gitignored.
- Admin password files (`*-pw.txt`). Gitignored.

## Cleanup

```bash
./install-rhem.sh --cleanup
```

Stops/disables `flightctl.target`, removes the RPMs, prunes flightctl
containers/pods/volumes/images, and deletes `/etc/flightctl` and local CLI
config. **Destructive** — removes the running deployment and enrolled devices'
server-side state.
