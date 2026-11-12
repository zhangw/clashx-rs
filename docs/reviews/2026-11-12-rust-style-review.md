# Rust Style Review — 2026-11-12

- Branch: `feat/rust-style-guide` (base `e878c55`)
- Guide: [docs/rust-style-guide.md](../rust-style-guide.md)
- Toolchain: rustc 1.99.1, cargo 1.99.1
- Scope: 46 Rust files, 15,089 lines (`src/`, `crates/`, `tests/`)

## Method

1. `cargo fmt --check` and the default `cargo clippy --all-targets` baseline
   (both clean at the start of the branch).
2. `cargo clippy --all-targets` with `-W clippy::pedantic`,
   `-W missing_docs`, `-W missing_debug_implementations`, `-W unsafe_code`,
   `-W rust_2018_idioms`, plus probes for `unwrap_used` / `expect_used` /
   `undocumented_unsafe_blocks` (see [Reproduce](#reproduce)).
3. A scripted inventory of per-file size, public-item doc coverage, production
   `unwrap`/`expect`/`panic` counts, module docs, and test layout.
4. Manual reading of the relay, resource-budget, retry, config, and daemon
   control paths.

Result: about 490 strict-lint diagnostics. The default lint set stays clean,
so every finding below is a style/robustness gap rather than an existing CI
failure.

## Summary

| Severity | Findings | Theme |
| --- | ---: | --- |
| Major | 5 | API documentation, panic-prone error handling, oversized functions |
| Minor | 7 | naming, module layout, stale suppressions, lint sweep |
| Info | 5 | accepted exceptions and test hygiene |

| Area | Files | Missing docs | Missing `# Errors` | `doc_markdown` | Other |
| --- | ---: | ---: | ---: | ---: | ---: |
| `crates/config` | 4 | 93 | 1 | 0 | 8 |
| `crates/dns` | 8 | 1 | 2 | 5 | 15 |
| `crates/geoip` | 2 | 5 | 2 | 2 | 3 |
| `crates/proxy` | 10 | 29 | 9 | 7 | 21 |
| `crates/rule` | 3 | 13 | 0 | 3 | 26 |
| `crates/subscribe` | 4 | 14 | 11 | 0 | 5 |
| `crates/sysproxy` | 3 | 7 | 5 | 0 | 5 |
| `src/` (binary) | 11 | 2 | 0 | 38 | 154 |
| `tests/` | 3 | 3 | 0 | 0 | 6 |

`Other` counts pedantic findings such as `must_use_candidate`,
`map_unwrap_or`, `redundant_closure_for_method_calls`, `items_after_statements`,
and the rustc lints (`missing_debug_implementations`, `unsafe_code`,
`unused_qualifications`).

## Findings

### F-01 — Public API is largely undocumented (Major, `DOC-1`/`DOC-2`/`DOC-3`)

167 `missing_docs` diagnostics: 9 crate docs, 18 module docs, 12 structs,
69 struct fields, 7 enums, 27 variants, 10 methods, 5 associated functions,
5 constants, 4 free functions. `crates/config` alone accounts for 93 (the
config schema fields), `crates/proxy` for 29. 30 public functions returning
`Result` lack an `# Errors` section.

Impact: the config schema is the user-facing contract; undocumented fields
leave defaults and units ambiguous. Reviewers cannot tell which `pub` items
are intentional API.

Fix: crate and module docs for every file; docs for every `pub` item,
including field semantics and defaults; `# Errors` sections. Tracked in
commit 1 below.

### F-02 — Panic-prone lock handling (Major, `ERR-3`/`ERR-5`)

`src/retry.rs` unwraps poisoned `RwLock`s in every accessor:
`should_warn_stalled` (line 108), `is_cooled_down` (119, 122),
`is_sidelined` (135), `sideline` (141), `record_failure` (145),
`degrade` (159), `is_degraded` (164), `record_success` (172–174).
`crates/dns/src/cache.rs:77,87` does the same with `expect("inflight mutex
poisoned")`, and `src/resources.rs:147` expects the global budget to be
initialized.

Impact: one panic in any thread poisons the lock; every later connection then
panics instead of degrades. The relay loop is the last place that should
abort on a diagnostic lock.

Fix: add a small poisoning-recovery helper (`read()`/`write()` that uses
`PoisonError::into_inner`), or restructure to avoid shared locks; turn the
budget expectation into a real error. Tracked in commit 2.

### F-03 — Silent fallbacks and `Option::unwrap` in error paths (Major, `ERR-1`/`ERR-3`)

- `src/main.rs:353` parses the daemon latency response with
  `serde_json::from_value(data).unwrap_or_default()`: a malformed response
  prints an empty table and exits 0.
- `src/main.rs:357` and `src/daemon.rs:1828` serialize with
  `unwrap_or_default()`, turning a serialization bug into an empty payload.
- `src/daemon.rs:1219` and `1343` end with `Err(last_err.unwrap())`; an empty
  candidate list (or a loop that never attempted) panics instead of returning
  a contextual error.

Fix: context-bearing errors; `last_err.ok_or_else(|| anyhow!("no proxy
candidates"))?`. Tracked in commit 2.

### F-04 — Oversized functions (Major, `ORG-5`)

Unique functions over the 100-line Clippy threshold (14 warnings because
several targets compile the same file):

| Function | Lines | Plan |
| --- | ---: | --- |
| `src/daemon.rs::handle_connection` | 354 | split route / connect / first-byte / relay phases |
| `src/daemon.rs::run_daemon` | 252 | split setup, accept loop, reload/shutdown |
| `src/daemon.rs::dispatch_control` | 144 | one handler per control command |
| `src/main.rs::main` | 148 | extract `run_*` command handlers |
| `src/main.rs::run_subscribe` | 120 | move nested helpers to module scope |
| `src/probe.rs::run` | 132 | split round scheduling from probe execution |
| `crates/proxy/src/outbound/socks5.rs::connect_with_timeout` | 101 | split handshake and setup writes |
| `crates/proxy/src/relay.rs::relay_with_policy` | 146 | split tick and half-close handling |

Behavior must not change; relay-related splits are covered by the existing
daemon/relay tests and are landed in commit 4.

### F-05 — Undocumented `unsafe` blocks (Major, `UNS-2`)

Six production blocks without a `// SAFETY:` note:
`src/resources.rs:85,95,99` (`getrlimit`/`setrlimit`),
`crates/proxy/src/socket.rs:55` (`setsockopt` keepalive),
`crates/rule/src/process.rs:207-208` (union field access after checking
`soi_kind`). Four more are in tests.

Impact: the `libproc` union access is the highest-risk code in the workspace;
the discriminant check that makes it sound is not written down.

Fix: `// SAFETY:` comments stating invariants and platform assumptions;
`unsafe_code` denied at workspace level with local `#[allow(unsafe_code)]` on
those functions, and `clippy::undocumented_unsafe_blocks` denied. Commit 2/3.

### F-06 — `mod.rs` layout (Minor, `ORG-2`)

`crates/proxy/src/inbound/mod.rs` and `crates/proxy/src/outbound/mod.rs` use
the pre-2018 layout. Rename to `inbound.rs` / `outbound.rs` (the module
directories stay). Commit 4.

### F-07 — Naming and parameter ergonomics (Minor, `NAME-3`/`API-3`/`API-4`)

- `get_` prefixes: `crates/proxy/src/outbound/trojan.rs:96`
  (`get_connector` → `tls_connector`), `crates/sysproxy/src/macos.rs:24`
  (`get_active_services` → `active_services`).
- Boolean parameters: `src/main.rs:228,246,462`, `src/latency.rs:225`,
  `src/daemon.rs:1383`, `src/resources.rs:455`,
  `crates/proxy/src/outbound/trojan.rs:70,96`,
  `crates/proxy/src/relay.rs:74`. Introduce small enums where the call site
  is ambiguous; keep flags that mirror documented config keys.
- `crates/rule/src/process.rs:133` returns `Option<Option<String>>`;
  replace with a three-state enum (`Hit`/`Miss`/`Stale`) or document the
  exception with `#[expect]`.
- `crates/rule/src/lib.rs:177` has an unused `self` (make it an associated
  function).
- `src/client.rs:8` takes `ControlRequest` by value but does not consume it;
  take `&ControlRequest`.

Commit 3.

### F-08 — Stale suppressions (Minor, `API-8`)

`src/control.rs:28,37,46` mark used constructors `#[allow(dead_code)]`.
`crates/dns/src/wire.rs:28` is different: `QType::Aaaa` is intentionally
test-only and the comment explains it, so it stays. Commit 3.

### F-09 — Documentation and API lint sweep (Minor, `DOC-4`/`API-2`)

55 `doc_markdown`, 24 `must_use_candidate`, 18 `unused_qualifications`,
8 `unreadable_literal`, 7 `uninlined_format_args`, and the remaining
pedantic findings (`map_unwrap_or` 20, redundant closures 23,
`single_match_else` 11, `items_after_statements` 10, …). These are mechanical
and land with the lint configuration in commit 5.

### F-10 — Missing `Debug` on public types (Minor, `API-7`)

11 public types do not implement `Debug`: `GeoIpDb`, `SysProxy`,
`MatchInput`, `RuleEngine`, `ProcessLookup`, `Resolver`, the inbound/outbound
stream types, and the relay stats type. Add derives where all fields support
it, manual impls otherwise. Commit 5.

### F-11 — Items declared after statements (Minor, `ORG-3`)

`src/daemon.rs:200,1395`, `src/latency.rs:231,235`,
`crates/dns/src/resolver.rs:211,215`. Move `const`/`struct`/`impl` items to
module scope. Commit 5.

### F-12 — Test lint opt-out is not in place yet (Info, `TEST-5`)

31 test modules and 3 integration test files use `unwrap`/`expect` freely,
which is correct. Once `clippy::unwrap_used` / `expect_used` are denied, each
test module needs the documented opt-out header; production code must not.
Commit 5.

### F-13 — Protocol casts are an accepted exception (Info, `API-9`)

26 pedantic cast diagnostics are all bounded wire-format or platform values
(DNS lengths, SOCKS5 address sizes, keepalive constants, latency display).
The workspace allows `cast_possible_truncation`, `cast_possible_wrap`,
`cast_precision_loss`, and `cast_sign_loss`; `cast_lossless` and
`cast_possible_truncation` at true trust boundaries are still fixed. Reviewers
apply API-9 to new casts.

### F-14 — Linux sysproxy prints shell exports (Info, `LOG-1`)

`crates/sysproxy/src/linux.rs:7-23` prints `export`/`unset` lines. This is the
documented behavior of the Linux helper (it cannot mutate a desktop proxy),
so the guide allows it explicitly. No change.

### F-15 — `start_background` is a stub returning `Result` (Info, `API-6`)

`src/daemon.rs:387` prints "not yet implemented" and always returns `Ok(())`,
which triggers `unnecessary_wraps`. Keep the signature for the planned daemon
mode and document the exception with
`#[expect(clippy::unnecessary_wraps, reason = "...")]` rather than changing
the CLI contract.

## Remediation plan

| Commit | Scope | Findings |
| --- | --- | --- |
| 1 | `docs(api)`: crate/module/public-item docs, `# Errors` | F-01 |
| 2 | `fix(errors)`: lock recovery, context, remove `unwrap` panics, SAFETY notes | F-02, F-03, F-05 |
| 3 | `refactor(api)`: naming, flags, stale allows, `ControlRequest` borrow | F-07, F-08 |
| 4 | `refactor(modules)`: `foo.rs` layout, split oversized functions | F-04, F-06 |
| 5 | `style(lints)`: enable workspace lints, sweep remaining pedantic findings, test opt-outs | F-09–F-12, F-15 |
| 6 | `docs(style)`: link the guide from `AGENTS.md`, final verification | — |

Each commit keeps `cargo fmt --check`, `cargo clippy --all-targets -- -D
warnings`, and `cargo test` green. Commit 5 is the one that turns on the
stricter lint table, so it lands last.

## Strengths worth preserving

- `rustfmt` is already clean and the default Clippy set reports zero warnings.
- 335 tests, with behavior-oriented names and a consistent
  `#[cfg(test)] mod tests` layout.
- The relay and resource-budget modules are the best-documented code in the
  repository (module invariants, const assertions, throttled diagnostics);
  the rest of the workspace should follow their pattern.
- No `panic!` in production code today; the remaining panic risk is confined
  to `unwrap`/`expect` sites listed above.

## Reproduce

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --message-format=short -- \
  -W clippy::pedantic -W missing_docs -W missing_debug_implementations \
  -W unsafe_code -W rust_2018_idioms -W unused_qualifications
```
