# Hostdesk: agent operating contract

## Purpose

Hostdesk is a private, per-machine Linux service desk. It discovers services, sockets, containers, projects, and publication routes, and controls permitted services and an owned nftables table through explicit approval flows. Read `README.md` and `SECURITY.md` before changing behavior.

## Architecture

| Path | Responsibility |
|---|---|
| `cmd/hostdesk/` | CLI entry point: `init`, `serve`, `address`, `token`, broker commands |
| `internal/discovery/` | Read-only inventory: systemd, containers, listeners, firewall, routes, projects |
| `internal/webserver/` | Loopback HTTP server, owner-token auth, CSRF, approvals, audit, embedded assets |
| `internal/broker/` | Separate root broker: Unix-socket API, allowlisted actions, nftables policy with rollback |
| `internal/config/`, `internal/model/` | Private configuration and shared data types |
| `install.sh` | Release installer (systemd user service, optional root broker) |

## Setup and verification

- Go toolchain: go.mod requires Go 1.23 or later. CGO is disabled for releases.
- Verify with `sh scripts/verify`. It runs `gofmt -l`, `go vet`, `go test`, `sh -n install.sh`, and a static build, and exits nonzero on any failure.
- The repository currently has no `_test.go` files. New behavior needs tests in the package it changes.

## Conventions

- Commands use fixed argument vectors and a controlled environment, never a shell.
- Discovery never starts services, grants control, or opens ports.
- Keep machine-specific values (hostnames, addresses, tokens, inventory) out of the repository.

## Prohibited operations

- Do not run the broker, `install.sh`, `nft`, `systemctl`, `sudo`, or anything that changes the host.
- Do not modify `.github/`, `scripts/verify`, `AGENTS.md`, `install.sh`, `Makefile`, `go.mod`, `go.sum`, or `SECURITY.md` in automated tasks; those changes need the owner.
- Do not add dependencies, network calls, telemetry, or weaken an authentication, approval, or rollback check.
- Do not commit; the ALICE controller commits and verifies candidates.
