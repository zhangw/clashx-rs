# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

clashx-rs is a pure Rust CLI proxy tool — a headless alternative to ClashX for macOS and Linux. It parses Clash-compatible YAML configs and provides CLI-first control (no GUI, no REST API in v1). See `docs/superpowers/specs/2026-04-09-clashx-rs-design.md` for the full design spec.

## Build & Development

```bash
cargo run -- run --config <path>     # Run daemon with config
cargo run -- status                  # CLI client commands
```

**Pre-commit hooks**: `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` run automatically before every `git commit` via Claude Code hooks (`.claude/settings.json`). Commits are blocked if either check fails.

## Architecture

Single binary, two modes (daemon + CLI client) in a Cargo workspace: `crates/` holds config, proxy, rule, dns, and sysproxy; `src/` is the CLI entry that routes to daemon or client mode.

## Key Design Decisions

- **Mixed-port detection**: peek first byte — `0x05` = SOCKS5, else HTTP proxy
- **Trojan protocol**: SHA-224(password) hex-encoded as auth, TLS with configurable SNI, no server response before relay
- **Rule matching**: DOMAIN-SUFFIX uses dot-boundary check (`foo.com` matches `a.foo.com` but not `afoo.com`)
- **Control socket**: `~/.config/clashx-rs/clashx-rs.sock` with JSON request-response
- **DNS resolution**: mihomo-compatible `dns:` block drives rule/DIRECT resolution and proxy-server dialing (UDP/DoH/DoT race, bootstrap, hosts, fail-open system fallback) — see `docs/dns-resolver-design.md`
- **System proxy cleanup**: signal handlers (SIGTERM/SIGINT) always unset macOS system proxy before exit
- **Config compatibility**: unknown YAML fields are ignored, not rejected — subscription provider configs work unmodified

## Protocols in Scope (v1)

Trojan and SOCKS5 outbound only. These are the protocols actively used in the user's config. VMess, VLESS, Hysteria, etc. are deferred.

## Runtime Paths

- Config: `~/.config/clashx-rs/config.yaml` (default) or `--config <path>`
- PID file: `~/.config/clashx-rs/clashx-rs.pid`
- Control socket: `~/.config/clashx-rs/clashx-rs.sock`
