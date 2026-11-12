# Rust Style Guide

Status: adopted 2026-11-12 for the whole workspace.

This guide is the review baseline for `clashx-rs`. It distills the
[rust-lang style guide](https://doc.rust-lang.org/style-guide/), the
[Rust API Guidelines](https://rust-lang.github.io/api-guidelines/), and the
conventions this repository already follows. Where the upstream guides are
silent, the rule below is the project decision.

Keywords **MUST**, **SHOULD**, and **MAY** follow RFC 2119. A rule may be
waived only with a local `#[expect(lint, reason = "...")]` or an explicit note
in the commit message or change description; blanket `#![allow(...)]` is
reserved for test builds.

## How to use this guide

- Reviewers cite rule IDs (for example `ERR-3`) in findings.
- Authors run the enforcement commands in [Enforcement](#enforcement) before
  every commit.
- Style-only changes must not change behavior. If a rule cannot be satisfied
  without a behavior change, land the behavior change separately first.
- When the guide and the code disagree, either fix the code or amend the guide
  in the same change; do not leave a silent exception.

## 1. Formatting (`FMT`)

- **FMT-1 (MUST)** Code is formatted by `rustfmt` with the repository
  `rustfmt.toml`. Never hand-align or hand-wrap code that `cargo fmt` owns.
- **FMT-2 (MUST)** Maximum line width is 100 columns; indentation is four
  spaces; files use Unix newlines.
- **FMT-3 (MUST)** One statement per line. Chained one-liners are allowed only
  for trivial `let` bindings and `?` propagation.
- **FMT-4 (MUST)** Imports are grouped in this order, separated by one blank
  line: `std`, external crates, `crate::`/`super::`/`self`. Within a group,
  imports are sorted and merged (rustfmt does the sorting).
- **FMT-5 (MUST)** No glob imports (`use foo::*`) in production code. Test
  modules may use `use super::*` to reach the code under test.
- **FMT-6 (MUST)** Multi-line calls, structs, and match arms end with a
  trailing comma.

## 2. Naming (`NAME`)

- **NAME-1 (MUST)** Follow RFC 430 casing: `UpperCamelCase` types and traits,
  `snake_case` functions/modules/fields, `SCREAMING_SNAKE_CASE` constants and
  statics.
- **NAME-2 (MUST)** Acronyms are words in identifiers: `HttpRequest`,
  `DnsCache`, `TlsConfig`, `Socks5Stream`, `GeoIpDb`. Do not write `HTTPRequest`
  or `getDNS`. Acronyms stay uppercase in prose and log messages.
- **NAME-3 (MUST)** Getters are named after the field, without a `get_`
  prefix: `fn port(&self)`, not `fn get_port(&self)`. The only exception is an
  established FFI-style name that is part of an external contract.
- **NAME-4 (MUST)** Conversion prefixes follow the API Guidelines: `as_` for a
  cheap borrowed-to-borrowed view, `to_` for an owned or expensive conversion,
  `into_` for a consuming conversion. Do not use `to_` for a cheap `Copy`
  value.
- **NAME-5 (MUST)** Constructors are `new` or `with_<thing>`; fallible
  constructors are `try_new`. Predicates start with `is_`, `has_`, `can_`, or
  `should_`, never `check_`.
- **NAME-6 (MUST)** Error types are `<Thing>Error` and implement `Display` and
  `std::error::Error`. Functions that return `Result` use the crate-local
  `Result<T>` alias when one exists.
- **NAME-7 (SHOULD)** Avoid repeating the module name in a type name when the
  type is re-exported at the crate root (`relay::Policy`, not
  `relay::RelayPolicy`, if `Policy` is unambiguous there).
- **NAME-8 (MUST)** Numeric constants carry their unit in the name (`_SECS`,
  `_MS`, `_BYTES`); constants whose type is `Duration` are exempt because the
  type carries the unit. A bare number in a timeout calculation is a review
  finding.
- **NAME-9 (MUST)** Single-letter names are limited to loop indices (`i`,
  `j`) and coordinate-style tuples. `e` is acceptable for an error binding in
  `map_err(|e| ...)`; nothing else.

## 3. Modules, files, and item order (`ORG`)

- **ORG-1 (MUST)** Every module file starts with a `//!` module doc. The crate
  root documents purpose, entry points, invariants, and links to the relevant
  `docs/` design page.
- **ORG-2 (MUST)** Prefer `foo.rs` plus a `foo/` directory over `foo/mod.rs`.
  `mod.rs` is allowed only when it is the only file in the directory.
- **ORG-3 (MUST)** Item order within a file: `mod` declarations, imports,
  constants, type definitions, inherent `impl`s, trait `impl`s, free
  functions, then `#[cfg(test)] mod tests`.
- **ORG-4 (MUST)** Unit tests live in one `#[cfg(test)] mod tests` at the
  bottom of the file. Do not interleave tests with production items.
- **ORG-5 (SHOULD)** Keep files under roughly 600 lines and functions under
  roughly 80 lines. Split by responsibility, not by line count. A cohesive
  state machine that is longer is acceptable with
  `#[expect(clippy::too_many_lines, reason = "...")]` and a comment explaining
  the invariant that keeps it together. The binary's orchestration entry
  points (for example `src/daemon.rs`) may exceed the file budget when the
  startup/shutdown ordering invariant is only visible as one sequence; note
  the invariant and keep protocol/transport out (see ORG-8).
- **ORG-6 (MUST)** Platform code lives in `macos.rs`/`linux.rs` modules behind
  `#[cfg(target_os = ...)]`; `lib.rs` exposes one portable facade.
- **ORG-7 (MUST)** `lib.rs` re-exports the minimum public API and keeps
  implementation modules private or `pub(crate)`. A `pub mod` is allowed when
  the module is part of the crate's documented public API (the crate root docs
  or the module docs explain its role); any new `pub mod` is still an API
  commitment.
- **ORG-8 (SHOULD)** The binary's `daemon.rs` stays orchestration-only.
  Protocol parsing and transport belong to `crates/proxy`, DNS to
  `crates/dns`, and so on.

## 4. Documentation (`DOC`)

- **DOC-1 (MUST)** Every crate has crate-level `//!` docs: what it does, its
  main entry points, and the invariants a caller must uphold.
- **DOC-2 (MUST)** Every public item is documented. Document semantics,
  defaults, units, and side effects, not the type signature.
- **DOC-3 (MUST)** Fallible public functions document an `# Errors` section;
  functions that can panic document `# Panics`; `unsafe fn` documents
  `# Safety`.
- **DOC-4 (MUST)** Use backticks for identifiers and code in docs, and link
  types with `[`Type`]` when the link is useful. This is enforced by
  `clippy::doc_markdown`.
- **DOC-5 (MUST)** Doc comments are complete sentences ending with a period.
  No marketing filler, no "This function ..." when the name already says it.
- **DOC-6 (SHOULD)** Document non-obvious private items, especially state
  machines, lock ordering, and platform assumptions.
- **DOC-7 (MUST)** Deprecated APIs carry `#[deprecated(since = "...",
  note = "...")]` and docs that name the replacement.
- **DOC-8 (MUST)** A comment that no longer describes the code is a bug; fix
  it in the same change.

## 5. Errors (`ERR`)

- **ERR-1 (MUST)** Fallible operations return `Result`. Do not swallow errors
  with `unwrap_or_default()`, `ok()`, or `let _ =` unless the failure is
  genuinely irrelevant; say why in a comment.
- **ERR-2 (MUST)** Add context at module and I/O boundaries:
  `.with_context(|| format!("... {path}"))` or `.context("...")`. Context names
  the operation and the object (host, path, proxy), not just "failed".
- **ERR-3 (MUST)** No `unwrap()` or `expect()` in production code. When an
  invariant truly makes failure impossible, use `expect("invariant: ...")`
  and a local `#[expect(clippy::expect_used, reason = "...")]`. Prefer
  restructuring the code over asserting.
- **ERR-4 (MUST)** Preserve error chains. Log with `{err:#}` or iterate
  `err.chain()`; never convert an error to a string and drop the source.
- **ERR-5 (MUST)** Lock poisoning is handled explicitly, for example
  `lock().unwrap_or_else(PoisonError::into_inner)`. `lock().unwrap()` in
  production code is a review finding.
- **ERR-6 (SHOULD)** Library public APIs expose typed errors that implement
  `std::error::Error`; `anyhow` is for the binary/daemon edge and internal
  plumbing. A new public API should not add a new `anyhow::Error` to its
  signature without a reason in the review.
- **ERR-7 (MUST)** Do not `panic!` for recoverable conditions and do not call
  `std::process::exit` outside the CLI command layer.

## 6. Async and concurrency (`ASYNC`)

- **ASYNC-1 (MUST)** Never block the async runtime: filesystem work,
  `getaddrinfo`, and process/socket scans run in `spawn_blocking`.
- **ASYNC-2 (MUST)** Do not hold a `std::sync` guard across `.await`. Use
  `tokio::sync` locks when the guard must live across an await point, and keep
  the critical section short.
- **ASYNC-3 (MUST)** Bound every external I/O with a timeout: connect, TLS
  handshake, and inbound protocol handshake budgets live in
  `crates/proxy/src/timeout.rs`; first-byte, relay-idle, and half-close
  budgets live in `src/retry.rs`.
- **ASYNC-4 (MUST)** `select!` branches must be cancellation-safe or document
  why they are not. Dropping a future must not lose buffered protocol bytes.
- **ASYNC-5 (MUST)** Spawned tasks are `Send + 'static`, handle their own
  errors, and never discard a `JoinHandle` that can panic silently without a
  log.
- **ASYNC-6 (SHOULD)** Prefer ownership over `Arc<Mutex<_>>`. Shared state is
  limited to what outlives a single task (daemon state, caches, pools).
- **ASYNC-7 (MUST)** No `block_on` inside an async context; block only at the
  process entry point.

## 7. Logging and CLI output (`LOG`)

- **LOG-1 (MUST)** Libraries use `tracing` only; the daemon uses `tracing`
  except for its foreground lifecycle messages. `println!` / `eprintln!` are
  allowed only for user-facing CLI output in `src/main.rs`, `src/client.rs`,
  and `src/latency.rs`; the Linux sysproxy helper whose documented contract is
  to print shell `export`/`unset` lines; the daemon's foreground lifecycle
  messages (startup readiness, shutdown, and startup warnings that must reach
  the interactive console because daemon logs go to the rolling file); and
  fatal shutdown diagnostics that must reach stderr even when the log filter
  is silent (print, do not log).
- **LOG-2 (MUST)** Use structured fields for key values (`host = %host`,
  `err = %e`) and a lowercase message without a trailing period. A
  human-readable error chain may be interpolated into the message
  (`failed to set system proxy: {e}`); never interpolate secrets or hide key
  identifiers inside the format string.
- **LOG-3 (MUST)** Levels: `error` = a human must act; `warn` = degraded but
  working; `info` = lifecycle; `debug` = per-connection detail; `trace` =
  per-byte detail. Startup and shutdown are `info`.
- **LOG-4 (MUST)** Never log secrets: passwords, tokens, subscription URLs
  with credentials, or full config dumps. Redact before logging.
- **LOG-5 (MUST)** Throttle repeated warnings per object and interval; reuse
  `OverloadLog` / `should_warn_stalled` rather than inventing a counter.
- **LOG-6 (MUST)** Log messages describe the event, not the code path:
  "upstream stalled", not "in first_byte_window branch 2".

## 8. Unsafe code (`UNS`)

- **UNS-1 (MUST)** `unsafe` is a last resort. Isolate each block in the
  smallest possible function and keep the safe wrapper adjacent.
- **UNS-2 (MUST)** Every `unsafe` block carries a `// SAFETY:` comment
  immediately above it that states the invariants, the platform assumptions,
  and why the operation is sound. This is enforced by
  `clippy::undocumented_unsafe_blocks`.
- **UNS-3 (MUST)** Check and propagate returned status codes (`rc == 0`,
  null checks) before constructing safe values from raw data.
- **UNS-4 (MUST)** No `mem::transmute`. Use `from_raw`, `cast`, or a checked
  conversion, and document the layout assumption.

## 9. Tests (`TEST`)

- **TEST-1 (MUST)** Unit tests live in `#[cfg(test)] mod tests` at the bottom
  of the file; cross-crate behavior lives in `tests/` or
  `crates/<crate>/tests/`.
- **TEST-2 (MUST)** Test names describe the behavior and the condition, for
  example `half_closed_before_promotion_stays_general`. Do not prefix test
  functions with `test_`; helper functions may be named `make_*`, `fixture_*`,
  or `test_*`.
- **TEST-3 (MUST)** Arrange-act-assert; one behavior per test; assert on
  observable results, not private implementation details.
- **TEST-4 (MUST)** No unbounded sleeps or sleep-polling in unit tests. A
  short bounded sleep used to force a timeout is acceptable; prefer Tokio's
  paused time or explicit timeouts, and keep tests deterministic on a loaded
  machine.
- **TEST-5 (MUST)** Tests may `unwrap`/`expect`/`panic`; production code may
  not. Test builds opt out at the crate root with
  `#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used,
  clippy::panic, clippy::unchecked_time_subtraction))]`; integration-test
  crates keep the same list at the file root.
- **TEST-6 (SHOULD)** Cover error paths and boundaries, not just the happy
  path: empty input, truncated frames, peer reset, timeout.
- **TEST-7 (MUST)** Integration tests use only the crate's public API.

## 10. Public API design (`API`)

- **API-1 (MUST)** Private by default. Use `pub(crate)` for cross-module
  internals; `pub` only when another crate needs the item.
- **API-2 (MUST)** Pure functions and constructors that return a value are
  `#[must_use]`; extensible public enums and structs are `#[non_exhaustive]`.
- **API-3 (MUST)** Take `&str`, `&[T]`, `impl AsRef<Path>` in parameters and
  return owned types. Avoid `&String`, `&Vec<T>`, and `&PathBuf`.
- **API-4 (MUST)** Avoid boolean parameters when the call site is unreadable
  (`enable(true, false)`); use a small enum or a named struct. Boolean flags
  that mirror a config key are acceptable when the name is at the call site.
- **API-5 (SHOULD)** Implement `From`/`TryFrom` instead of ad-hoc conversion
  functions; implement `Default` when a natural default exists.
- **API-6 (MUST)** Fields are private unless the type is a pure data-transfer
  struct (config, control protocol, stats snapshot). Invariants belong behind
  methods.
- **API-7 (SHOULD)** Implement `Debug` for every public type. Derive `Clone`,
  `Copy`, `PartialEq` only when the semantics are real.
- **API-8 (MUST)** Remove `#[allow]`/`#[expect]` attributes that are no longer
  needed. A suppression is not documentation; if the reason is not obvious,
  it belongs in a `reason = "..."` string or a nearby comment.
- **API-9 (MAY)** Numeric `as` casts are acceptable only where the value is
  provably bounded by the wire format or the platform constant at the cast
  site. At trust boundaries and for sizes that cross protocols, use
  `u16::try_from(..)` (or the matching `TryFrom`) and handle the error. The
  workspace lint set allows the pedantic cast lints; reviewers still check
  each new cast against this rule.

## 11. Comments (`CMT`)

- **CMT-1 (MUST)** Comments explain *why*, not *what*. If the code needs a
  "what" comment, rename or restructure instead.
- **CMT-2 (MUST)** `TODO`/`FIXME` comments name an owner and a concrete
  condition: `// TODO(relay): drop this once the pool reports occupancy`.
  Delete commented-out code.
- **CMT-3 (SHOULD)** Section banners (`// ----`) are used sparingly for large
  files, not as a substitute for modules.

## 12. Dependencies and `cfg` (`DEP`)

- **DEP-1 (MUST)** Every new dependency is justified in the change
  description; prefer the workspace dependency table and the standard library.
- **DEP-2 (MUST)** Optional dependencies are feature-gated; default features
  stay minimal.
- **DEP-3 (MUST)** Platform-specific code compiles for its target and keeps a
  non-platform fallback (`#[cfg(not(any(...)))]`) so `cargo check` on another
  OS fails gracefully.

## Enforcement

Configuration lives at the repository root:

- `rustfmt.toml` — formatting (`FMT-*`).
- `Cargo.toml` `[workspace.lints]` — rustc and Clippy lints (`NAME-*`,
  `DOC-*`, `ERR-3`, `UNS-2`, `API-*`, `ASYNC-*` where a lint exists).
- Every crate sets `[lints] workspace = true`.

Required before commit:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test
```

Useful extra checks:

```bash
cargo audit
cargo deny check advisories
```

### Exceptions

- Use `#[expect(lint, reason = "...")]` on the smallest item that needs it.
- Test builds opt out of panic-on-failure lints at the crate root (see
  TEST-5); integration-test crates put the same list at the file root.
- Any exception that survives two review rounds is either promoted to a rule
  amendment or removed; do not accumulate permanent ignores.

## Review checklist

When reviewing a change, check in this order:

1. Does the change preserve routing, TLS, and timeout semantics? (`ASYNC-3`,
   `ORG-8`)
2. Are public items documented and private items private? (`DOC-2`, `API-1`)
3. Are errors contextualized and chains preserved? (`ERR-1`–`ERR-5`)
4. Any new `unsafe` block without `// SAFETY:`? (`UNS-2`)
5. Any lock held across an await, unbounded I/O, or unthrottled log? (`ASYNC-2`,
   `ASYNC-3`, `LOG-5`)
6. Are tests deterministic and named for behavior? (`TEST-2`, `TEST-4`)
7. Does `cargo fmt --check` and
   `cargo clippy --workspace --all-targets -- -D warnings` pass?

## Review outputs

Style review findings are reported with the change (commit message or change
description) and are not retained as dated style review documents. Durable
architecture, security, and performance reviews continue to live in
`docs/reviews/` according to `AGENTS.md`. Rule changes are made in this guide,
not in a review report.
