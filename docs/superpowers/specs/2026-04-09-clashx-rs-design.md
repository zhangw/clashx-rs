# clashx-rs: CLI Proxy Tool Design Spec

## Overview

A pure Rust CLI proxy tool — a headless alternative to ClashX. Runs on macOS and Linux without a GUI. Uses CLI commands for all user interaction. Fully compatible with existing Clash YAML configuration files.

## Goals

- Drop-in replacement for ClashX's proxy engine (no GUI, no TUN)
- Parse and use existing Clash YAML configs without modification
- CLI-first control: start/stop daemon, switch proxies, inspect state
- Cross-platform: macOS and Linux
- Single binary, two modes: daemon and client

## Non-Goals (v1)

- RESTful API (deferred — will be Clash-API compatible when added)
- TUN/TAP transparent proxying
- DNS fake-ip mode (config is parsed but the feature is not active)
- Protocols beyond Trojan and SOCKS5 (VMess, VLESS, Hysteria, etc.)
- Web dashboard
- Pretty/TUI output (optional future enhancement)

## Architecture

### Single Binary, Two Modes

`clashx-rs` is one binary with two modes:

- **Daemon mode** (`clashx-rs run`): starts the proxy engine, listens for traffic and control commands
- **Client mode** (`clashx-rs status`, `switch`, etc.): sends commands to the running daemon

Communication between client and daemon uses a Unix domain socket at `~/.config/clashx-rs/clashx-rs.sock` with JSON request-response messages.

### Data Flow

```
App Traffic
    │
    ▼
Mixed-Port Listener (7890)
    │  detect: 0x05 → SOCKS5, else → HTTP
    ▼
Inbound Handler (extract target host:port)
    │
    ▼
Rule Engine (top-to-bottom, first match)
    │  DOMAIN-SUFFIX, IP-CIDR, PROCESS-NAME, MATCH
    ▼
Proxy Group Resolution (select → specific node)
    │
    ▼
Outbound Connector
    ├─ Trojan (TLS + Trojan header + relay)
    ├─ SOCKS5 (handshake + relay)
    ├─ DIRECT (TCP connect + relay)
    └─ REJECT (drop connection)
```

### Cargo Workspace Structure

```
clashx-rs/
├── Cargo.toml              # workspace root
├── crates/
│   ├── config/             # Clash YAML parsing, typed structs
│   ├── proxy/              # Protocol implementations
│   │   └── src/
│   │       ├── inbound/    # mixed-port listener (HTTP + SOCKS5)
│   │       ├── outbound/   # trojan, socks5, direct, reject
│   │       └── relay.rs    # bidirectional data relay
│   ├── rule/               # Rule matching engine
│   ├── dns/                # DNS resolution (standard resolver)
│   └── sysproxy/           # System proxy configuration
├── src/
│   ├── main.rs             # CLI entry (clap)
│   ├── daemon.rs           # Daemon mode: engine + control socket
│   └── client.rs           # Client mode: send commands to daemon
```

**Crate dependencies (directed, no cycles):**
- `config`: standalone (serde + serde_yaml)
- `dns`: standalone (tokio)
- `rule`: depends on `config`
- `proxy`: depends on `config`, `dns`
- `sysproxy`: standalone
- Binary (`src/`): depends on all crates

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime (full features: net, io, signal, process) |
| `serde` + `serde_yaml` | Clash YAML config parsing |
| `tokio-rustls` + `rustls` | TLS for Trojan outbound |
| `clap` | CLI argument parsing (derive API) |
| `sha2` | SHA-224 hashing for Trojan password |
| `tracing` + `tracing-subscriber` | Structured logging |
| `serde_json` | Control socket messages |

## Protocol Specifications

### Inbound: Mixed-Port Listener

A single TCP listener on the configured `mixed-port`. On each accepted connection, peek at the first byte:

- `0x05` → SOCKS5: perform SOCKS5 handshake (method negotiation, connect request), extract target address
- Any other byte → HTTP proxy: parse HTTP CONNECT (for HTTPS) or plain HTTP request, extract target from Host header or request URI

Both paths produce a `(target_host, target_port, client_stream)` tuple passed to the rule engine.

### Outbound: Trojan

Connection sequence:
1. TCP connect to `server:port`
2. TLS handshake using `rustls` with:
   - SNI set to `sni` field value (e.g. `baidu.com`)
   - Certificate verification disabled when `skip-cert-verify: true`
3. Send Trojan request header over TLS:
   ```
   hex(SHA224(password)) | CRLF
   CMD(0x01) | ATYP | DST.ADDR | DST.PORT | CRLF
   ```
   - Password is SHA-224 hashed, hex-encoded (56 characters)
   - ATYP: 0x01 (IPv4), 0x03 (domain), 0x04 (IPv6)
   - No server response — payload relay begins immediately after header
4. Bidirectional relay between client stream and TLS stream

### Outbound: SOCKS5

Standard SOCKS5 client (RFC 1928):
1. TCP connect to SOCKS5 server
2. Method negotiation (no auth — 0x00)
3. Send CONNECT request with target address
4. Read server response (bound address)
5. Bidirectional relay

### Outbound: DIRECT

TCP connect directly to the target address. Bidirectional relay.

### Outbound: REJECT

Close the client connection immediately. No outbound connection made.

## Rule Engine

Rules are evaluated top-to-bottom. First match determines the action (proxy group or DIRECT/REJECT).

| Rule Type | Input | Match Logic |
|-----------|-------|-------------|
| `DOMAIN-SUFFIX` | Target hostname | `host == suffix` or `host.ends_with("." + suffix)` (dot-boundary, so `foo.com` does not match `oo.com`) |
| `IP-CIDR` | Target IP address | IP falls within CIDR range |
| `PROCESS-NAME` | Source process name | Look up PID owning the source TCP connection |
| `MATCH` | (none) | Always matches — catch-all, must be last |

### Process Name Resolution

- **macOS**: Use `libproc` APIs (`proc_pidinfo`) to map source IP:port → PID → process name
- **Linux**: Parse `/proc/net/tcp` to find inode for source IP:port, scan `/proc/*/fd/` to find PID owning that inode, read `/proc/<pid>/comm` for process name

### Performance

Build a domain suffix trie at config load time for O(1) domain rule lookups. IP-CIDR rules use prefix matching. With ~130 rules in typical configs, even linear scan is fast, but the trie optimizes the hot path.

## Proxy Groups

v1 supports only the `select` type:
- A named group containing an ordered list of proxy names
- One proxy is "selected" (active) at any time — defaults to the first
- CLI command `clashx-rs switch <group> <proxy>` changes the selection at runtime
- Selection state is held in memory; resets to first proxy on daemon restart

## CLI Interface

```
clashx-rs run [--config <path>]       # Start daemon (foreground)
clashx-rs run -d [--config <path>]    # Start daemon (background/detached)
clashx-rs stop                        # Stop running daemon
clashx-rs reload                      # Reload config without restart

clashx-rs status                      # Running state, config path, port, connection count
clashx-rs proxies                     # List all proxy nodes
clashx-rs groups                      # List proxy groups and current selections
clashx-rs switch <group> <proxy>      # Switch active proxy in a group
clashx-rs rules                       # List active rules
clashx-rs test <domain>               # Test which rule matches a domain

clashx-rs sysproxy on                 # Enable system proxy
clashx-rs sysproxy off                # Disable system proxy
clashx-rs sysproxy status             # Show system proxy state
```

### Daemon Lifecycle

- PID file: `~/.config/clashx-rs/clashx-rs.pid`
- Control socket: `~/.config/clashx-rs/clashx-rs.sock`
- On `run`: check PID file, refuse if already running
- On `stop`: send shutdown via socket, daemon cleans up (unsets system proxy, closes listeners)
- On `reload`: daemon re-reads YAML, diffs config, applies changes live
- Signal handling: SIGTERM/SIGINT trigger graceful shutdown (unset system proxy before exit)

### Control Protocol

Client → Daemon: JSON over Unix socket
```json
{"command": "switch", "group": "@singapo", "proxy": "新加坡 02"}
{"command": "status"}
{"command": "reload"}
{"command": "stop"}
```

Daemon → Client: JSON response
```json
{"ok": true, "data": {...}}
{"ok": false, "error": "group not found: @foo"}
```

## System Proxy Management

### macOS

Use `networksetup` commands:
```sh
# Detect active network services
networksetup -listnetworkserviceorder

# Enable (for each active service)
networksetup -setwebproxy <service> 127.0.0.1 <port>
networksetup -setsecurewebproxy <service> 127.0.0.1 <port>
networksetup -setsocksfirewallproxy <service> 127.0.0.1 <port>

# Disable
networksetup -setwebproxystate <service> off
networksetup -setsecurewebproxystate <service> off
networksetup -setsocksfirewallproxystate <service> off
```

Apply to all active services. Daemon always unsets proxy on shutdown (via signal handlers).

### Linux

No unified system proxy. Instead:
- `clashx-rs sysproxy on` prints `export http_proxy=http://127.0.0.1:<port>` commands
- `clashx-rs sysproxy off` prints `unset http_proxy` commands
- Optionally writes `~/.config/clashx-rs/proxy.env` for sourcing

## Config Handling

### Clash YAML Compatibility

Parse existing Clash YAML files using `serde_yaml`. Unknown fields are silently ignored (`#[serde(flatten)]` with `HashMap` sink or simply no `deny_unknown_fields`). This ensures configs from subscription providers work without modification.

Default config path: `~/.config/clashx-rs/config.yaml`
Override: `--config <path>` (supports symlinks to existing Clash configs)

### Supported Config Fields (v1)

```yaml
mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule           # rule | global | direct
log-level: info

dns:                 # parsed but fake-ip not implemented in v1
  enable: false

proxies:             # Trojan and SOCKS5 only
  - name: ...
    type: trojan
    server: ...
    port: ...
    password: ...
    sni: ...
    skip-cert-verify: true/false

  - name: ...
    type: socks5
    server: ...
    port: ...

proxy-groups:        # select type only
  - name: ...
    type: select
    proxies: [...]

rules:               # DOMAIN-SUFFIX, IP-CIDR, PROCESS-NAME, MATCH
  - DOMAIN-SUFFIX,example.com,group-name
  - IP-CIDR,10.0.0.0/8,group-name
  - PROCESS-NAME,AppName,group-name
  - MATCH,group-name
```

## Complexity Assessment

| Component | Effort | Risk | Notes |
|-----------|--------|------|-------|
| Config parser | Medium | Low | serde handles most work; edge cases in Clash format |
| Mixed-port inbound | Medium | Low | Well-documented protocols |
| Trojan outbound | High | Medium | TLS + custom protocol; must match server expectations exactly |
| SOCKS5 outbound | Low | Low | Simple, well-documented (RFC 1928) |
| Rule engine | Medium | Low | Straightforward pattern matching |
| Process name lookup | Medium | Medium | Platform-specific, may need fallback |
| CLI + control socket | Low | Low | Standard clap + serde_json over UDS |
| System proxy (macOS) | Medium | Medium | Relies on networksetup; must handle cleanup on crash |
| System proxy (Linux) | Low | Low | Just print env var commands |
