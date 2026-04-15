# Rule engine expansion

Date: 2026-04-12

## Problem

Auditing the live `WgetCloud.yaml` rule set against what clashx-rs actually
evaluates turns up silent behavioural gaps. Root cause: `RuleEntry::parse`
(`crates/config/src/rule.rs`) only recognises four rule types. Every other
type is dropped on the floor at parse time, with no warning anywhere.

Counts from the current `WgetCloud.yaml` (9,053 lines):

| Rule type       | Count | Fate in clashx-rs                 |
|-----------------|------:|-----------------------------------|
| DOMAIN-SUFFIX   | 8,573 | matched                           |
| IP-CIDR         |   333 | matched                           |
| DOMAIN-KEYWORD  |    59 | **silently dropped**              |
| DOMAIN          |    42 | **silently dropped**              |
| PROCESS-NAME    |    33 | matched                           |
| IP-CIDR6        |    11 | **silently dropped**              |
| GEOIP           |     1 | **silently dropped (high impact)**|
| MATCH           |     1 | matched                           |

## Proposed: rule type coverage

The highest-value single change is a **parser-level `tracing::warn!` for
unrecognised rule types**, emitted at startup and reload. It converts silent
misroutes into visible warnings. ~20 min. Ship first.

Then, in cost-benefit order:

- **A1 DOMAIN** [42 rules] — exact-match variant of DOMAIN-SUFFIX. One enum
  case, one match arm. Recovers Google push and PKI routes
  (`mtalk.google.com`, `crl.pki.goog`, `ocsp.pki.goog`, `dl.google.com`)
  that currently tunnel through Singapore on every TLS revocation check.
- **A2 DOMAIN-KEYWORD** [59 rules] — `host_lower.contains(kw)`. Zero
  marginal cost over DOMAIN-SUFFIX. Recovers CN services (`alipay`,
  `alicdn`, `bilibili`, `xiaomi`, `baidupcs`, `jdpay`) currently proxied
  via SG when they should go direct, plus the intended keyword routes for
  `youtube`, `telegram`, `spotify`, `dropbox`, `onedrive`, `openai`.
- **A3 IP-CIDR6** [11 rules] — `ip_in_cidr` at `crates/rule/src/lib.rs:66`
  already handles v6; this is just a second parse form of the same rule.
  Restores `::1/128` and ULA direct-route intent.
- **A4 GEOIP** [1 rule, largest impact] — `GEOIP,CN,🎯 全球直连` is the
  entire CN-direct policy. Without it, unmatched CN-IP traffic egresses via
  the Singapore Trojan.
  - **A4a warn stub** — recognise at parse, emit a warning, treat as a
    no-op. ~10 min. Stops the silent-drop foot-gun on reload.
  - **A4b real implementation** — `maxminddb` crate + bundled or
    user-supplied `Country.mmdb`. Couples to DNS behaviour (see
    `docs/reviews/2026-04-11-network-proxy-review.md` finding #4), so it
    should be scheduled alongside the DNS subsystem rewrite, not before.

A1 / A2 / A3 are each ~30 min plus tests. First-slice total (parse-warn +
A1 + A2 + A3 + A4a): roughly one day, one PR, no new dependencies.

## Deferred: evaluation efficiency

Profile-gated. Per-connection the engine walks `~8,940` rules under the
state read lock (`crates/rule/src/lib.rs:26`); per-suffix-check lowercasing
is already flagged in `docs/reviews/2026-04-11-performance-evaluation.md`
finding #5. Three candidate follow-ups, pick after profiling:

- **B1** reverse-label trie over DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD —
  collapses O(n) to O(labels); non-trivial first-match-wins correctness
  surface. ~1-2 days.
- **B2** hoist `host.to_lowercase()` out of the inner loop. ~15 min. This
  is the perf-eval #5 recommendation verbatim.
- **B3** bucket rules by type so IP-only inputs don't walk DOMAIN-SUFFIX
  entries. ~2 hours.

## Config hygiene (user action, flagged here so we don't forget)

Not engine changes, but likely to become visible the moment the parse-warn
lands:

- Nine ccTLD-wide DOMAIN-SUFFIX rules (`.us`, `.uk`, `.hk`, `.jp`, `.tw`,
  `.kr`, `.sg`, `.ca`, `.eu` → `🚀 节点选择`) at `WgetCloud.yaml:915-923`
  cause 138 shadowed rules and 656 redundant-child rules — ~9% of the
  list never affects routing. Either delete, or move to just above `MATCH`.
- Five DOMAIN-SUFFIX entries (`google.com`, `claude.ai`, `anthropic.com`,
  `openai.com`, `chatgpt.com`) are duplicated with a second copy that
  tries to override the first — dead because of first-match semantics.

## Open questions

1. **Scope.** Bundle parse-warn + A1/A2/A3 + A4a in one PR, or split A4a
   so the behavioural no-op doesn't ride with the real matchers?
2. **GEOIP timing.** A4a now, A4b with the DNS rewrite — or couple them
   and ship nothing until DNS lands?
3. **Warning surface.** `tracing::warn!` is invisible to daemon users
   unless they run with `RUST_LOG=warn` in view. Do we also add a
   `clashx-rs lint` subcommand that enumerates unrecognised rule types
   (and ideally the duplicate/shadow findings above) on demand?
