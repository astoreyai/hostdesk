# Security model

Hostdesk is an administrative control plane, not a public status page. Keep its HTTP listener on loopback and its remote transport private. A public source repository does not make the deployed dashboard public.

## Trust boundaries

- The web process runs as the installation owner, never root. Its owner token is generated on that host and stored in a private state directory.
- A configured Tailscale proxy can authenticate exact permitted login names. That mode requires an exact HTTPS origin, matching Host, and a loopback peer. **Local processes are trusted:** the identity headers are not signed, and a process able to reach the local listener can impersonate the proxy. Do not enable identity-header mode on an untrusted multi-user host. Use the owner-token path through a privately authenticated transport instead.
- Mutations require authentication, an exact Origin, and a session CSRF token. Lifecycle and policy approvals are short-lived, actor-bound, one-use, and require exact typed confirmation. Service state and policy revisions are revalidated.
- The privileged broker is a separate root process with a narrow Unix-socket API. The root-owned capability policy specifies the permitted owner UID, system services, containers, and protected ports. The socket and peer checks reject other UIDs; the client also rejects a non-root broker peer.
- System and container allowlists are independent of discovery. An inventory entry is not permission to control it. Root policy changes require root; the HTTP API cannot add capabilities.
- Commands use fixed argument structures and a controlled environment, not a shell. Validated executable paths are separate from their invocation names so Linux multicall binaries retain correct dispatch.
- Container commands select explicit local Unix endpoints. Saved Docker contexts and remote Podman connections do not redirect operations to another machine. Podman requires its local API socket; container processes do not inherit the broker's service sandbox.
- Automatic SSH exceptions require a real root-owned SSH process and executable, not merely a process name. Root-managed SSH socket activation and explicitly configured management ports are also preserved.

Anyone able to execute code as the dashboard owner already possesses its token, session state, user-service authority, and broker capability. Anyone controlling root can change the capability policy or firewall. Hostdesk does not attempt to defend against either principal.

## Firewall scope and recovery

Hostdesk owns only `inet hostdesk_guard`. It filters new TCP/UDP traffic addressed to the host on explicitly selected interfaces. It does not change proxy publication, application bindings, other firewall tables, unmanaged interfaces, established connections, or container FORWARD traffic. Later firewall hooks may still deny an allowed port.

Before application, one atomic private state document records both the last confirmed policy and the pending recovery information. nftables changes are syntax-checked and applied as a transaction. The pending state survives process death. Startup recovers an unconfirmed change before exposing the broker socket; graceful shutdown also rolls it back. A live broker performs deadline rollback independently of the browser.

A failed audit write prevents normal mutations. Recovery is different: restoring a pending firewall policy must proceed even if audit persistence fails. Check actual rules and audit diagnostics after storage failures. No software timer can recover while the machine is powered off; pending recovery runs at the next broker startup.

Confirmed policy remains installed when the broker stops and is restored when it starts. An administrator who changes or removes the owned table outside Hostdesk must reconcile that change explicitly. Listener annotations decline to assert filtering when the observed table differs from the last installed policy.

Keep an independent management connection. Verify a **new connection** before confirmation. Do not rely solely on an existing SSH session, because established traffic is deliberately preserved.

## Host-private data

Private configuration/state is outside the checkout. Files include the owner token, bound address, allowlists, policy, and audit; do not publish them. Inventory can contain hostnames, addresses, internal ports, usernames, paths, project names, container names, tunnel hostnames, and process ownership.

The collector selects fields rather than returning raw systemd/container inspection. It does not expose environment variables, raw command lines, application logs, Git remote URLs, or tunnel credentials. Project scanning identifies filenames and directories, not arbitrary file contents. Tunnel configuration is parsed locally and only ingress routing fields are returned.

HTTP responses are no-store, and the embedded UI loads no third-party scripts, fonts, analytics, or telemetry. Audit records intentionally contain identities and action targets, remain private, are bounded, and are not tamper-proof. Back them up separately if retention matters.

## Availability and limitations

Missing tools, engine sockets, permission restrictions, scan caps, and remote-only tunnel configuration are reported. A degraded source is not an empty successful inventory. Some administrative status commands require writable shared lock files and can be unavailable inside the broker sandbox; readable nftables/iptables kernel evidence remains a separate source.

The local API sockets of Docker or Podman can themselves grant extensive authority. Do not expose them over unauthenticated TCP or grant access to untrusted users. Hostdesk does not install or start those engines automatically.

No promise of application health, public reachability, complete filesystem indexing, or protection of arbitrary container networking follows from a green inventory source. Review the scope and evidence shown by each result.

## Reporting

Do not open a public issue containing a token, private configuration, raw inventory, firewall dump, logs, or host screenshot. Report the affected version, code location, and a redacted description. Use GitHub private vulnerability reporting when it is available for the repository; otherwise contact the maintainer privately before sharing sensitive reproduction details.
