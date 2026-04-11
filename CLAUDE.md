# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

clashx-rs is a pure Rust CLI proxy tool — a headless alternative to ClashX for macOS and Linux. It parses Clash-compatible YAML configs and provides CLI-first control (no GUI, no REST API in v1). See `docs/superpowers/specs/2026-04-09-clashx-rs-design.md` for the full design spec.

## Build & Development

```bash
cargo build                          # Debug build
cargo build --release                # Release build
cargo run -- run --config <path>     # Run daemon with config
cargo run -- status                  # CLI client commands

cargo test                           # Run all tests
cargo test -p clashx-rs-config       # Test a single crate
cargo test <test_name>               # Run a specific test

cargo clippy --all-targets           # Lint
cargo fmt --check                    # Check formatting
```

**Pre-commit hooks**: `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` run automatically before every `git commit` via Claude Code hooks (`.claude/settings.json`). Commits are blocked if either check fails.

## Architecture

Single binary, two modes (daemon + CLI client) in a Cargo workspace:

```
crates/
  config/    - Clash YAML parsing with serde. Silently ignores unknown fields for compatibility.
  proxy/     - Inbound (mixed-port: HTTP+SOCKS5 auto-detect) and outbound (Trojan, SOCKS5, DIRECT, REJECT)
  rule/      - Top-to-bottom rule engine: DOMAIN-SUFFIX, IP-CIDR, PROCESS-NAME, MATCH
  dns/       - DNS resolution (standard resolver; fake-ip deferred)
  sysproxy/  - macOS: networksetup commands. Linux: env var helpers.
src/
  main.rs    - CLI entry (clap). Routes to daemon.rs or client.rs based on subcommand.
  daemon.rs  - Starts proxy engine + Unix socket control server
  client.rs  - Sends JSON commands to daemon via Unix socket
```

**Crate dependency order (no cycles):** config and dns are standalone; rule depends on config; proxy depends on config + dns; sysproxy is standalone; the binary depends on all.

## Key Design Decisions

- **Mixed-port detection**: peek first byte — `0x05` = SOCKS5, else HTTP proxy
- **Trojan protocol**: SHA-224(password) hex-encoded as auth, TLS with configurable SNI, no server response before relay
- **Rule matching**: DOMAIN-SUFFIX uses dot-boundary check (`foo.com` matches `a.foo.com` but not `afoo.com`)
- **Control socket**: `~/.config/clashx-rs/clashx-rs.sock` with JSON request-response
- **System proxy cleanup**: signal handlers (SIGTERM/SIGINT) always unset macOS system proxy before exit
- **Config compatibility**: unknown YAML fields are ignored, not rejected — subscription provider configs work unmodified

## Protocols in Scope (v1)

Trojan and SOCKS5 outbound only. These are the protocols actively used in the user's config. VMess, VLESS, Hysteria, etc. are deferred.

## Runtime Paths

- Config: `~/.config/clashx-rs/config.yaml` (default) or `--config <path>`
- PID file: `~/.config/clashx-rs/clashx-rs.pid`
- Control socket: `~/.config/clashx-rs/clashx-rs.sock`

## Platform-Specific Code

Process name resolution and system proxy are platform-specific:
- **macOS**: `libproc` for process lookup, `networksetup` for system proxy
- **Linux**: `/proc/net/tcp` + `/proc/<pid>/comm` for process lookup, env var helpers for proxy
