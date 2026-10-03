# Hostdesk

A private, per-machine Linux service desk. Discover what is running, which sockets it owns, how it is published, and which projects it belongs to. Start, stop, or restart permitted services through an explicit approval flow. Preview and apply an interface-specific inbound port policy with automatic rollback.

The repository contains software, not a machine configuration. Discovery happens on the installation host. Hostnames, addresses, port assignments, identities, inventory, tokens, and audit records stay in private local configuration and state directories.

## What it discovers

- System and current-user systemd services, including installed inactive and failed units.
- Local Docker and Podman containers, including stopped containers and published bindings. Rootless engines are inventoried when accessible.
- Listening TCP/UDP sockets, IPv4/IPv6 binding scope, visible process ownership, and service associations.
- Projects identified by Git or language/build manifests under configured roots and service working directories. Explicit roots are scanned first. Traversal is bounded; inaccessible directories and scan limits are reported rather than hidden.
- Tailscale Serve/Funnel routes and readable local Cloudflare ingress configurations.
- Available kernel firewall evidence, including the Tailscale-before-UFW ordering hazard.

A successful backend TCP connection means **reachable**, not application healthy. A socket binding or configured tunnel is not proof of Internet reachability. Remotely managed Cloudflare ingress requires its separate control plane and cannot be enumerated from local configuration alone.

## Requirements

- Linux. Release binaries are provided for amd64 and arm64; no Go or Node runtime is required to run them.
- systemd for the automatic service installer. Without systemd, `init` and `serve` can run in the foreground, while systemd inventory/control is unavailable.
- `ss` from iproute2 for socket discovery and live SSH protection.
- `nft` and root approval for managed firewall changes.
- Docker, Podman, Tailscale, Cloudflare, iptables, and UFW are optional sources, not services Hostdesk installs or starts automatically.

Missing tools and denied sources produce explicit partial-inventory diagnostics. Discovery never starts a discovered service, grants root control, or opens a port.

Docker uses its local Unix daemon socket. Podman uses its local API socket, not daemonless commands inside the broker sandbox. If Podman is installed and you choose to expose its local API, enable `podman.socket` through the system manager for rootful inventory/control, or through the user manager for rootless inventory. Hostdesk never enables it automatically. The explicit Unix endpoints follow the [Podman remote-client contract](https://docs.podman.io/en/latest/markdown/podman.1.html#url-value); saved remote-engine contexts are not used.

## Install a release

Download and inspect the installer, then run it as the dashboard owner, not root:

```sh
curl --fail --location https://raw.githubusercontent.com/astoreyai/hostdesk/main/install.sh --output install-hostdesk.sh
less install-hostdesk.sh
sh install-hostdesk.sh --with-broker
```

Omit `--with-broker` for unprivileged discovery and current-user service control. The optional broker installation invokes `sudo` and installs a separate root service. Its initial system-service and container control allowlists are empty, and its initial firewall policy makes no changes.

The installer detects the architecture, downloads a release binary, verifies its SHA-256 against the release checksums, and installs a systemd user service. Checksums detect corrupted or mismatched downloads; they are not an independent publisher signature. `HOSTDESK_VERSION` can select a release tag instead of the latest release.

```sh
~/.local/bin/hostdesk address
~/.local/bin/hostdesk token
systemctl --user status hostdesk.service
```

Open the reported loopback origin and enter the owner token. Do not paste the token into URLs, issue reports, screenshots, or shell history. The token is never stored in browser local storage. An automatically chosen backend port is saved privately and reused across restarts; an occupied saved port causes a visible startup failure, not a silently broken proxy route.

For startup without an interactive login, enable lingering for the owner deliberately:

```sh
sudo loginctl enable-linger "$(id -un)"
```

## Configure discovery

`hostdesk init --help` lists configuration flags. `init` updates only explicitly supplied options; repeatable project-root or identity options replace their corresponding lists. Configuration is separate from the source checkout.

To include the actual directory you are currently working in:

```sh
~/.local/bin/hostdesk init --project-root "$PWD"
systemctl --user restart hostdesk.service
```

Repeat `--project-root` to include multiple existing roots. The scanner does not follow symlinks, read Git remote URLs, collect environment variables, or expose arbitrary file contents. Large roots may reach the reported traversal limits.

## Private remote access

The web server rejects non-loopback listen addresses. Use a private transport, not a public port forward. Tailscale Serve is supported with an exact HTTPS origin and exact permitted login names.

Before changing Serve, inspect `tailscale serve status`; its default HTTPS route may already belong to another application. Back up that configuration and choose the intended route. Hostdesk does not publish or overwrite proxy routes automatically.

For an untagged, user-owned Tailscale node, the following obtains the actual node origin and owner login rather than embedding machine values:

```sh
HOSTDESK_ORIGIN=$(tailscale status --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print("https://"+d["Self"]["DNSName"].rstrip("."))')
HOSTDESK_OWNER=$(tailscale status --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["User"][str(d["Self"]["UserID"])]["LoginName"])')
~/.local/bin/hostdesk init --external-origin "$HOSTDESK_ORIGIN" --tailscale-user "$HOSTDESK_OWNER"
systemctl --user restart hostdesk.service
HOSTDESK_BACKEND=$(~/.local/bin/hostdesk address | python3 -c 'import json,sys; print(json.load(sys.stdin)["origin"])')
tailscale serve --bg "$HOSTDESK_BACKEND"
```

These commands require Python only to extract local Tailscale JSON. Tagged nodes do not have a usable personal owner identity in the same way: configure an explicitly chosen permitted login instead of deriving one from a tag-owned node. Do not use Funnel for this control plane.

**Proxy identity mode trusts local processes.** Tailscale identity headers are accepted only from loopback with the configured external Host, but they are not cryptographically signed. Another process on the same machine can impersonate that trusted proxy. Use this mode only on a trusted host; see [SECURITY.md](SECURITY.md). The owner-token login remains available for direct loopback access.

## Service controls

Every lifecycle change requires a fresh preview and exact typed confirmation. The server checks the target's state and permissions again at apply time. Approvals expire, are bound to the actor, and cannot be replayed.

- Current-user services run through the owner's systemd manager. Essential session infrastructure and Hostdesk itself are protected.
- System services and root-managed containers require both the root broker and a matching root-owned allowlist entry.
- Rootless containers are discovery-only; they are not granted root-engine controls.
- Arbitrary shell commands, process-kill buttons, environment editing, and application-specific configuration rewriting are not provided.

Inspect the actual service/container inventory before granting control. Root may edit `/etc/hostdesk/broker.json`, or invoke `hostdesk install-broker --help` for explicit `--allow-unit`, `--allow-container`, and `--protect-port` options. Repeatable allowlist flags replace that list when supplied. Restart `hostdesk-broker.service` after a manual policy-file edit. Do not grant units whose files or execution behavior you have not reviewed.

## Ports and access policy

The dashboard edits **host inbound TCP/UDP filtering**, not an application's listening-port setting. Application port reassignment still belongs to that application's own configuration.

1. Add the actual interface name and the TCP/UDP ports it must retain.
2. Review the generated nftables transaction and warnings.
3. Type the requested confirmation and apply.
4. Establish a **new** connection through each required access path.
5. Confirm the pending policy within 90 seconds, or let it roll back. An explicit rollback button is also available.

The broker owns only `inet hostdesk_guard`, at INPUT priority `-20`, ahead of the usual iptables filter hook. It does not rewrite UFW, Tailscale, Docker, or other firewall tables. An allow decision can still be denied by later host rules.

- Only selected interfaces are managed. Other interfaces retain their existing policy.
- Established/related connections, loopback, and ICMP remain intact.
- Actual SSH listener ports and root-configured management TCP ports must be preserved on every managed interface.
- The optional Tailscale peer API setting derives current peer API ports from the local daemon and refreshes them when they change; it does not allow arbitrary newly discovered application ports.
- Docker bridge/NAT forwarding traverses FORWARD, not host INPUT. Those published ports are **not protected by this guard**. Host-network container sockets do traverse INPUT.
- A wildcard listener spans multiple interfaces, so its policy is reported as mixed rather than globally safe or blocked.

Rollback state is persisted before changing nftables. A pending policy is rolled back after the deadline, on graceful broker shutdown, or during crash recovery before the broker accepts requests. Confirmed policy is restored on broker startup. Removing all interface entries explicitly removes Hostdesk's managed policy; it does not reset other firewall systems.

## Private files and services

| Item | Location |
| --- | --- |
| Owner configuration | `$XDG_CONFIG_HOME/hostdesk/config.json`, normally `~/.config/hostdesk/config.json` |
| Owner token, bound address, audit | `$XDG_STATE_HOME/hostdesk`, normally `~/.local/state/hostdesk` |
| User binary | `~/.local/bin/hostdesk` |
| User service | `hostdesk.service` |
| Root broker binary | `/usr/local/libexec/hostdesk` |
| Root capability policy | `/etc/hostdesk/broker.json` |
| Root durable policy and audit | `/var/lib/hostdesk` |
| Root broker socket | `/run/hostdesk/broker.sock` |
| System service | `hostdesk-broker.service` |

Configuration and state directories are private; secret/state files are mode `0600`. The broker socket directory is root-controlled, the socket is accessible to the configured owner UID, and both ends verify Unix peer credentials. The HTTP process is never root.

`hostdesk inventory` emits real private host data. Do not redirect it into this repository or attach it to a public issue. Application logs, environment values, raw command lines, and tunnel credentials are not exposed by the dashboard. Audit records are bounded operational records, not a tamper-proof compliance archive.

## Build from source

The module uses a Go 1.23 language baseline. Use a supported Go toolchain; the implementation is built with `CGO_ENABLED=0` and embeds the UI.

```sh
make check
make build
./hostdesk init
./hostdesk serve
```

`make release VERSION=0.1.0` builds Linux amd64 and arm64 binaries and `dist/SHA256SUMS`. Build outputs are ignored by Git. `make check` runs vet, the available Go tests, and installer syntax checking; it is not a substitute for real service, firewall, or browser verification.

## Recovery and removal

Keep an independent administrative connection before editing access policy. Do not confirm a policy based only on an already-established connection: established traffic is intentionally preserved.

A pending policy recovers automatically. Stopping the broker leaves a **confirmed** guard installed; this avoids accidentally reopening ports. To retire management, explicitly apply and confirm an empty interface policy first, then stop/disable the broker. If the control plane is unavailable, root can remove the owned table with `nft delete table inet hostdesk_guard`, but that removes its protection immediately and the saved confirmed policy will return on the next broker start.

User and system services can be disabled using the corresponding `systemctl --user disable --now hostdesk.service` and `sudo systemctl disable --now hostdesk-broker.service` commands. Preserve private policy/audit state for recovery until you have reviewed what to retain or delete. Re-running the installer preserves existing configuration and root policy unless explicit replacement flags are supplied.

See [SECURITY.md](SECURITY.md) for trust boundaries and safe reporting. Dependency license notices accompany the release.
