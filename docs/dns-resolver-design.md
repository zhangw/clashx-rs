# DNS Resolver Design (mihomo-compatible semantics)

Status: implemented on `feat/dns-resolver`. This document describes the
as-built design; deviations from the original plan are called out inline.

## Goal

Make the Clash `dns:` block a first-class data-plane subsystem: configured
nameservers (UDP/DoH/DoT), `hosts:` mappings, `proxy-server-nameserver`,
negative caching and singleflight — with mihomo-compatible config keys only
(no invented keys), and fail-open behavior everywhere DNS can break
connectivity.

## Consumed config keys

- `dns.enable`, `dns.ipv6`, `dns.nameserver`, `dns.default-nameserver`,
  `dns.proxy-server-nameserver`, `dns.enhanced-mode`, `dns.fake-ip-range`,
  `dns.fake-ip-filter`, `dns.use-hosts`
- top-level `hosts:` map

`fake-ip-range`/`fake-ip-filter` keep landing in `DnsConfig::extra` (parsed,
not interpreted).

## Semantics (confirmed decisions)

- **All nameservers fail → system resolver fallback** (fail-open, `warn`
  log). Connectivity is never sacrificed for DNS policy.
- **`dns.enable=false`** (or no `dns:` block) → everything goes through the
  system resolver; `hosts:` does NOT apply. If a nameserver list is
  configured anyway, a one-time warning says it is ignored.
- **fake-ip**: keys parse normally, but no pool is implemented. With
  `enhanced-mode: fake-ip` a one-time warning explains that without a
  TUN/DNS entry point the daemon behaves as in plain mode.
- **`ipv6: true`** → one-time warning that AAAA queries are unsupported;
  behavior equals `false`. **`ipv6: false`** → no AAAA queries are sent, and
  the system-resolver path discards pure-IPv6 results (treated as failure
  and negative-cached). Wire format supports AAAA (parameterized QTYPE) but
  v1 never sends it.
- **hosts**: values must be IP literals (otherwise warn + skip that entry).
  Keys support exact match plus `*.suffix` wildcards (a wildcard also matches
  the bare suffix). IPv6 values are honored regardless of the `ipv6`
  setting. `use-hosts` absent means enabled.

## crates/dns layout

- `lib.rs` — public API re-exports (`Resolver`, `build_resolvers`) plus
  `system_resolve` (getaddrinfo, A-only) and the shared `warn_once!` /
  system-TTL constants.
- `cache.rs` — the pre-existing `DnsCache` (crate-private): TTL clamp
  10..3600s, negative cache 10s, 4096-entry bound (eviction via
  `select_nth_unstable`), singleflight primitives.
- `wire.rs` — query builder / response parser parameterized on `QType`
  (A/AAAA). Transaction IDs come from `next_tx_id()` here.
- `upstream.rs` — `Upstream` enum (`Udp` / `Doh` / `Dot`), config-string
  classification, per-variant `exchange` (each variant enforces its own
  participant deadline), and the `race_first` first-success-wins primitive
  shared by the resolver race and bootstrap. No `async-trait`; enum +
  async fns.
- `bootstrap.rs` — `Bootstrap` resolver for DoH/DoT server hostnames.
- `resolver.rs` — top-level `Resolver`, `Hosts`, `build_resolvers`.

### Upstreams

- `Upstream::Udp { addr }` — the pre-existing UDP logic, 2s timeout. Bare
  IPs and `udp://IP[:port]`; the host must be an IP literal.
- `Upstream::Doh` — RFC 8484 POST `application/dns-message` via reqwest
  (one client per upstream). The client is pinned to the bootstrap-resolved
  IP with `ClientBuilder::resolve_to_addrs`, so reqwest never invokes the
  system resolver. **The client is built with `.no_proxy()`** — otherwise
  reqwest could honor `HTTP(S)_PROXY` env vars and loop DoH back into our
  own inbound listener (the highest-risk trap in this design). The workspace
  reqwest currently lacks the `system-proxy` feature, but `.no_proxy()`
  keeps a feature change from reintroducing the loop. Stale-if-error: each
  exchange re-consults the bootstrap cache (TTL enforced there); an IP
  change rebuilds the client, a bootstrap failure keeps serving with the old
  client/old IP.
- `Upstream::Dot` — RFC 7858: TCP to the bootstrap IP (default port 853) →
  tokio-rustls handshake (SNI = server hostname, webpki-roots) → 2-byte
  big-endian length prefix + wire query → parse response. One fresh
  connection per query; no reuse. One webpki-roots TLS config is shared by
  all DoT upstreams; it pins the ring provider explicitly because workspace
  feature unification enables both ring and aws-lc-rs (via reqwest), which
  makes the auto-detecting rustls builder panic.
- Other schemes (`dhcp://`, `quic://`, …) are warned about and skipped —
  "unknown is ignored, not rejected", matching repo config style.

### Bootstrap

- Uses ONLY the plain-UDP entries of `default-nameserver` — never the main
  race group (that would be circular).
- Own `DnsCache` instance keyed by DoH/DoT server hostname.
- Empty/all-invalid `default-nameserver` → system resolver fallback with a
  one-time warning.
- `build_resolvers` spawns a background warm-up task resolving every
  DoH/DoT server hostname (skipped when no tokio runtime is present, e.g.
  plain unit tests).

### Resolver

```text
Resolver { mode, cache }
mode = System | Custom { group, bootstrap, hosts }
```

Custom-mode `resolve(host)`:

1. IP-literal short-circuit
2. hosts hit → return immediately (never cached)
3. cache lookup / singleflight (leader resolves, followers wait + re-read)
4. race the group via `race_first` — per-participant deadline enforced
   inside `Upstream::exchange` (UDP 2s, DoH/DoT 4s), total window = max +
   100ms, first success wins
5. all failed → system fallback (`warn`) → cache write (TTL clamp /
   negative cache)

System mode: getaddrinfo (A only) + 300s cache + negative cache.

`Resolver::invalidate(host)` / `Resolver::clear()` back `dns flush`.

### proxy-server-nameserver

`build_resolvers` returns a **pair**: the target resolver (rules + DIRECT)
and the proxy resolver (group from `proxy-server-nameserver`; when that key
is absent both resolvers share the same `Arc<[Upstream]>` instances, so DoH
client state is built once). Both share the bootstrap instance and the
hosts mappings.

## daemon wiring

- `DaemonState` holds `resolver` + `proxy_resolver` (`Arc<Resolver>`),
  replacing the old `nameservers` + `dns_cache`. Both are built in
  `from_config`, so a reload naturally rebuilds everything (the bootstrap
  cache is not exposed to `dns flush`; reload clears it).
- `dns flush` flushes both resolvers (`hit` = present in either; `flushed`
  = sum of dropped entries).
- Rule pre-resolve (`handle_connection`) → `resolver.resolve(host)`.
- DIRECT path: when the target is a domain and the rule phase produced no
  IP, `resolver.resolve` runs first and the IP is handed to
  `direct::connect`; on failure the previous behavior remains (tokio
  getaddrinfo fallback). This unifies DIRECT resolution under the
  configured DNS policy.
- `connect_outbound(proxy, target, proxy_resolver)`: trojan/socks5 server
  domains are resolved via the proxy resolver (IP literals short-circuit,
  failures degrade to `None` = old getaddrinfo path). The resolved IP is
  passed to the connectors as `resolved_server_ip: Option<IpAddr>`; trojan
  dials the literal `SocketAddr` while **SNI/ServerName keep the domain**.
- `probe_once` receives the proxy resolver so health probes match the data
  plane. `latency::measure_full` also takes it (signature follows
  `connect_outbound`).

### Known inconsistencies (deliberately out of scope)

- `probe.rs` `server_is_probeable` uses the system `lookup_host` to decide
  whether a server is publicly routable.
- `latency.rs` `measure_tcp` uses the system `lookup_host`.

Both may disagree with the proxy resolver when custom DNS is configured.

## Deviations from the original plan

- `connect_outbound` takes the resolver and resolves internally; callers do
  not pass `Option<IpAddr>` themselves (same effect, fewer call sites).
- DoH staleness is driven by the bootstrap cache TTL instead of a separate
  per-client expiry: same observable behavior (re-resolve on expiry,
  keep-old-IP on failure) with less state.
- `crates/dns` now depends on `crates/config` (`build_resolvers(&Config)`);
  config itself stays pure data — classification lives in `upstream.rs`.
- `resolve_with_nameservers` / `resolve_via` free functions were removed;
  their logic lives in `Resolver`/`race_group`/`udp_exchange`.
- `rcgen 0.13` added as the single new dev-dependency (loopback DoT TLS
  test); not in release dependencies.

## Testing

- wire: QTYPE parameterization (AAAA build/parse, A ignores AAAA).
- upstream classification: table-driven over bare IP / `udp://` /
  `https://` with port+path / `tls://` default port / invalid entries.
- UDP exchange: loopback mock DNS server — success, timeout, ID mismatch.
- bootstrap: mock UDP default-nameserver — resolve, cache hit, IP-literal
  short-circuit, dead server does not panic.
- DoH: loopback plain-HTTP mock (RFC 8484 body) via a `#[cfg(test)]`
  constructor — success and HTTP-500 paths. No hyper/axum.
- DoT: framing pure-function tests + a full loopback TLS exchange using an
  rcgen self-signed cert pinned into the client root store.
- resolver: hosts priority (hit never touches the network), wildcard
  matching, invalid hosts values skipped, System mode (localhost), race
  first-success-wins, all-fail system fallback, flush.
- DoH no-proxy guard: `.no_proxy()` in `build_doh_client` with an explicit
  comment (no reqwest API to assert it at runtime; kept by review).
