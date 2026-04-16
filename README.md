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
  - `DOMAIN`
  - `DOMAIN-SUFFIX`
  - `DOMAIN-KEYWORD`
  - `IP-CIDR`
  - `PROCESS-NAME`
  - `GEOIP` (MaxMind mmdb)
  - `MATCH`
- Config modes:
  - `rule`
  - `global`
  - `direct`
- Proxy-group selection with live switching
- DNS pre-resolve with positive/negative caching and singleflight
- Lazy two-phase rule evaluation — DNS/process lookups only run when a rule needs them
- Per-proxy cooldown + failover across candidate proxies
- Parallel-instance support — socket/pid files are keyed by mixed-port
- Config subscriptions — download Clash YAML from URLs and auto-refresh
- GeoIP mmdb download (optionally through the running proxy)
- Local control socket and CLI commands for status, reload, rules, groups, and switching
- System proxy helpers:
  - macOS: `networksetup` with configurable bypass rules
  - Linux: shell export/unset snippets
- Timeout protection for inbound handshakes and outbound setup
- Admission control — caps in-flight connections to bound worst-case memory

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

- `clashx-rs run -d` (background daemon mode) is not implemented yet
- DNS resolution uses the system resolver with a TTL-based cache; fake-ip mode is deferred
- `PROCESS-NAME` lookup is best-effort and platform-dependent
- `GEOIP` requires a MaxMind Country mmdb at `~/.config/clashx-rs/Country.mmdb` (or provide `--mmdb <path>`)
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
  system resolver with TTL-based positive/negative cache and singleflight
- `crates/proxy`
  inbound protocol handling, outbound connectors, relay, and timeouts
- `crates/sysproxy`
  macOS/Linux system proxy helpers
- `crates/geoip`
  MaxMind mmdb loader and downloader for `GEOIP` rules
- `crates/subscribe`
  subscription downloader for Clash-compatible YAML feeds

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
cargo run -- sysproxy on --bypass 10.0.0.0/8 --bypass *.corp.example
cargo run -- sysproxy status
cargo run -- sysproxy off
```

Download the GeoIP database (optionally through the running proxy):

```bash
cargo run -- mmdb-download
cargo run -- mmdb-download --proxy socks5://127.0.0.1:7890
```

Manage config subscriptions:

```bash
cargo run -- subscribe add --name wgetcloud --url https://example.com/sub --output ~/.config/clashx-rs/config.yaml
cargo run -- subscribe list
cargo run -- subscribe update
cargo run -- subscribe remove wgetcloud
```

## CLI Commands

The current command surface:

```text
clashx-rs [--config <path>] [--port <port>] <command>

Commands:
  run [-d] [--select GROUP=PROXY] [--mmdb <path>] [--mmdb-auto-download]
  stop
  reload
  status
  proxies
  groups
  rules
  switch <group> <proxy>
  test <domain>
  sysproxy on [--bypass <pattern>]... | off | status
  mmdb-download [--proxy <url>] [--url <url>] [--output <path>]
  subscribe add --name <n> --url <u> --output <path> [--interval <secs>]
  subscribe list
  subscribe update [--name <n>]
  subscribe remove <name>
```

`--port` overrides the mixed-port so multiple daemons can run in parallel —
socket and pid files are keyed by port.

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

skip-proxy:
  - 10.0.0.0/8
  - *.corp.example

rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN-KEYWORD,github,Proxy
  - PROCESS-NAME,curl,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
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

Important paths (port defaults to 7890; change via `--port` or `mixed-port`):

- control socket:
  `~/.config/clashx-rs/clashx-rs-<port>.sock`
- PID file:
  `~/.config/clashx-rs/clashx-rs-<port>.pid`
- GeoIP database:
  `~/.config/clashx-rs/Country.mmdb`
- subscriptions:
  `~/.config/clashx-rs/subscriptions.yaml`

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
- `subscriptions.yaml` may contain provider tokens; the file is written with `0600` and a warning is logged if permissions widen.

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

- background daemon mode (`run -d`)
- richer integration tests
- fake-ip DNS mode
- more Clash-compatible routing features (rule providers, URL-test groups)
- more outbound protocols (VMess, VLESS, Hysteria)
- optional REST API

## License

Apache-2.0
