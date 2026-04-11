# clashx-rs

A pure Rust, headless Clash-compatible proxy CLI for macOS and Linux.

`clashx-rs` is a CLI-first proxy daemon designed as a lightweight alternative to ClashX for users who want Clash-style configuration and rule-based routing without a GUI. It reads Clash-compatible YAML, exposes a local mixed HTTP/SOCKS5 proxy, routes traffic through Trojan, SOCKS5, DIRECT, or REJECT targets, and provides daemon control entirely from the command line.

## Features

- Pure Rust workspace
- macOS and Linux support
- Clash-compatible YAML parsing
- Mixed inbound listener:
  - HTTP proxy
  - SOCKS5 proxy
- Outbound connectors:
  - Trojan
  - SOCKS5
  - DIRECT
  - REJECT
- Rule-based routing:
  - `DOMAIN-SUFFIX`
  - `IP-CIDR`
  - `PROCESS-NAME`
  - `MATCH`
- Config modes:
  - `rule`
  - `global`
  - `direct`
- Proxy-group selection with live switching
- Local control socket and CLI commands for status, reload, rules, groups, and switching
- System proxy helpers:
  - macOS: `networksetup`
  - Linux: shell export/unset snippets
- Timeout protection for inbound handshakes and outbound setup

## Non-goals

Current non-goals for v1:

- GUI
- REST API
- TUN / transparent proxying
- Fake-IP DNS mode
- Protocols beyond Trojan and SOCKS5

## Current Status

This project is usable as a local CLI proxy, but it is still early-stage software.

Known caveats:

- `clashx-rs run -d` is not implemented yet
- DNS config fields are parsed, but DNS policy is not yet a first-class runtime subsystem
- `PROCESS-NAME` lookup is best-effort and platform-dependent
- `allow-lan` can expose an unauthenticated proxy listener on the configured address; use carefully
- Trojan `skip-cert-verify` weakens upstream TLS security and should be avoided unless you understand the tradeoff

## Why This Exists

ClashX is convenient, but many environments do not need a desktop app. `clashx-rs` focuses on:

- keeping the runtime small and scriptable
- preserving compatibility with existing Clash config files
- making all control available from the terminal
- staying easy to inspect, hack on, and extend

## Architecture

`clashx-rs` is a single binary with two roles:

- daemon mode:
  runs the local proxy listener and control socket
- client mode:
  sends control commands to the daemon

High-level flow:

1. App traffic enters the mixed-port listener.
2. The inbound handler detects HTTP vs SOCKS5.
3. The daemon builds match input from target host/IP and, when available, source process name.
4. Routing resolves through config mode, rules, and proxy-group selection.
5. Traffic is relayed to Trojan, SOCKS5, DIRECT, or REJECT.

Workspace crates:

- `crates/config`
  Clash YAML parsing and typed config structures
- `crates/rule`
  rule parsing, evaluation, and process lookup helpers
- `crates/dns`
  system resolver helper
- `crates/proxy`
  inbound protocol handling, outbound connectors, relay, and timeouts
- `crates/sysproxy`
  macOS/Linux system proxy helpers

## Build

Requirements:

- Rust stable toolchain
- Cargo

Build:

```bash
cargo build
```

Release build:

```bash
cargo build --release
```

Run tests:

```bash
cargo test
```

Lint:

```bash
cargo clippy --all-targets -- -D warnings
```

## Usage

Show help:

```bash
cargo run -- --help
```

Start the daemon in the foreground:

```bash
cargo run -- run --config ~/.config/clashx-rs/config.yaml
```

Show status:

```bash
cargo run -- status
```

List groups:

```bash
cargo run -- groups
```

Switch a proxy inside a group:

```bash
cargo run -- switch Proxy sg-trojan
```

Reload config:

```bash
cargo run -- reload
```

Stop the daemon:

```bash
cargo run -- stop
```

Manage system proxy:

```bash
cargo run -- sysproxy on
cargo run -- sysproxy status
cargo run -- sysproxy off
```

## CLI Commands

The current command surface:

```text
clashx-rs run [--config <path>]
clashx-rs stop
clashx-rs reload
clashx-rs status
clashx-rs proxies
clashx-rs groups
clashx-rs rules
clashx-rs switch <group> <proxy>
clashx-rs test <domain>
clashx-rs sysproxy on|off|status
```

## Configuration

Default config path:

```text
~/.config/clashx-rs/config.yaml
```

Example:

```yaml
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info

proxies:
  - name: sg-trojan
    type: trojan
    server: sg.example.com
    port: 443
    password: supersecret
    sni: sg.example.com
    skip-cert-verify: false

  - name: local-socks5
    type: socks5
    server: 127.0.0.1
    port: 1080
    username: alice
    password: hunter2

proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - sg-trojan
      - local-socks5
      - DIRECT

rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - PROCESS-NAME,curl,DIRECT
  - MATCH,DIRECT
```

Currently supported proxy types:

- `trojan`
- `socks5`

Currently supported group types:

- `select`

Unknown fields are ignored so existing Clash configs are easier to reuse.

## Runtime Files

`clashx-rs` stores local runtime state under:

```text
~/.config/clashx-rs/
```

Important paths:

- control socket:
  `~/.config/clashx-rs/clashx-rs.sock`
- PID file:
  `~/.config/clashx-rs/clashx-rs.pid`

## System Proxy Behavior

macOS:

- uses `networksetup`
- can enable or disable local web / secure web / SOCKS proxy settings

Linux:

- prints `http_proxy`, `https_proxy`, and `all_proxy` shell exports
- does not attempt to modify a global desktop setting

## Security Notes

- Do not enable `allow-lan` unless you intend to expose the proxy on your network.
- Prefer loopback-only operation for workstation use.
- Avoid Trojan `skip-cert-verify` unless you explicitly accept the MITM risk.
- Control is local through a Unix socket under the runtime directory; keep the runtime directory private to your user account.

## Development Notes

Useful commands:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo audit
```

For a deeper dependency policy pass:

```bash
cargo deny check advisories
cargo deny check
```

## Roadmap Ideas

- background daemon mode
- richer integration tests
- stronger DNS integration and caching
- more Clash-compatible routing features
- more outbound protocols
- optional REST API

## License

Apache-2.0
