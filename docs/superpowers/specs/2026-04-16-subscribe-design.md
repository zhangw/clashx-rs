# Subscription Management Design Spec

## 1. Context

Clash-compatible providers publish proxy configs behind a URL that returns one of two formats depending on the client's `User-Agent`: raw `trojan://`/`vmess://` URIs (base64-encoded) for generic clients, or a full Clash YAML (with `proxies`, `proxy-groups`, `rules`, `dns` sections) for Clash clients. clashx-rs needs the YAML form.

Users also expect subscriptions to auto-refresh on a provider-defined interval — the standard `#!MANAGED-CONFIG <url> interval=<secs>` header at the top of a Clash YAML encodes the refresh cadence.

This feature adds first-class subscription management: a CLI subcommand to add/remove/list/update subscriptions, and a background task in the daemon that refreshes them on their configured interval and triggers an inline reload.

## 2. Architecture

### New crate: `crates/subscribe`

Isolates subscription concerns (HTTP download, state file I/O, update scheduling) from proxy routing. Does **not** depend on `clashx-rs-config` — the subscribe crate treats downloaded bytes as opaque YAML, and leaves parsing/validation to the daemon's existing reload path.

### Dependency diagram

```
src/main.rs   (adds `subscribe` subcommand)
    |
    v
src/daemon.rs (spawns subscription_auto_update task, trigger_inline_reload)
    |
    +---> crates/subscribe
              |
              +---> reqwest      (HTTP download, rustls-tls)
              +---> serde_yaml   (subscriptions.yaml I/O)
              +---> tokio::fs    (atomic write via .tmp + rename)
```

### Files owned by the feature

| Path | Written by | Purpose |
|---|---|---|
| `~/.config/clashx-rs/subscriptions.yaml` | `subscribe add/remove/update` + daemon auto-update | Registry of subscriptions plus `last_updated` timestamps. Atomic `.tmp` + rename; mode 0o600. |
| `<each sub's output path>` | `subscribe update`, daemon auto-update | Downloaded Clash YAML from the provider. Atomic `.tmp` + rename; mode 0o600. |

## 3. Subscriptions registry format

`~/.config/clashx-rs/subscriptions.yaml`:

```yaml
subscriptions:
  - name: wgetcloud
    url: "https://<provider-host>/link/<token>"
    output: "~/.config/clash/wgetcloud.origin.yaml"
    interval: 864000         # seconds; default 86400
    last_updated: 0          # unix timestamp; 0 = never downloaded
```

Fields:
- `name` — unique identifier used by `subscribe remove` / `update --name`
- `url` — subscription URL (the same one in the provider's `#!MANAGED-CONFIG` header)
- `output` — where the downloaded YAML is written; supports `~/` prefix
- `interval` — seconds between auto-downloads
- `last_updated` — set automatically on successful download; user can reset to `0` to force re-download on next check

## 4. CLI

```
clashx-rs subscribe add     --name N --url U --output P [--interval S]
clashx-rs subscribe remove  <name>
clashx-rs subscribe list
clashx-rs subscribe update  [--name <name>]
```

All actions run client-side (direct file I/O + HTTP). The `update` action additionally attempts a best-effort daemon reload via `client::send_command_quiet(Reload, port)` — if the daemon isn't running, it prints "daemon not running — reload skipped" and exits success.

`subscribe list` redacts URL query strings and fragments (see "Security" below).

## 5. Download behavior

- HTTP GET with `User-Agent: clash` so providers return YAML, not URI lists.
- 30-second total timeout; 8 MiB size cap (Content-Length pre-check plus streaming accumulator).
- Response body accumulated via `response.chunk()` so oversized responses abort mid-stream rather than buffering fully.
- Parent directory created if missing (idempotent).
- Atomic write: body → `<output>.yaml.tmp` → `rename` → `<output>`. Partial downloads never clobber a known-good file.
- File created with mode `0o600` (owner-only read/write) and re-chmod'd after rename — subscription YAMLs contain credentials (passwords in `proxies[].password`, session tokens embedded in URLs), so readable-by-other-local-users is a disclosure risk.
- A single `reqwest::Client` is built once per update cycle and reused across all subscriptions in that cycle — connection pool reuse matters when multiple subs hit the same provider host.

## 6. Daemon auto-update

Spawned once at daemon startup, after the proxy listener binds but before `ctrl_c().await`:

```
loop {
    let config = run_subscription_cycle(&state).await;
    let sleep_secs = compute_sleep_secs(config.as_ref());
    tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
}
```

### `run_subscription_cycle`

1. Load `subscriptions.yaml` (empty if absent).
2. If no subscriptions, return the empty config.
3. Call `update_due_subscriptions(&mut config)` — downloads only entries where `last_updated == 0` or `now ≥ last_updated + interval`.
4. Log per-subscription success/failure via `tracing`.
5. If any succeeded: save the config (persisting new `last_updated`) and call `trigger_inline_reload`.
6. Return the (possibly-mutated) in-memory config for reuse by `compute_sleep_secs`.

### `trigger_inline_reload`

Must stay in sync with the `ControlRequest::Reload` handler in `dispatch_control`. Takes a write lock on `DaemonState`, reloads the daemon's `--config` path via `load_config`, rebuilds state via `DaemonState::from_config(new_config, path, mmdb_path)`, reapplies startup `--select` overrides, preserves the cooldown tracker.

### `compute_sleep_secs`

Returns the min remaining time across all subscriptions (or `IDLE_CHECK_SECS` if none), clamped to `[60, 3600]`. Reuses the post-cycle config to avoid a second disk read.

### Error handling

All errors are logged via `tracing::warn!` and swallowed. A failed download, malformed subscriptions.yaml, or failed save never crashes the daemon. Matches the precedent set by the mmdb auto-download task.

## 7. File relationship: subscription output vs. daemon `--config`

This is the single most important thing to get right, because misconfiguration silently defeats auto-reload.

### The three files

| Path | Owner | Content |
|---|---|---|
| `~/.config/clashx-rs/subscriptions.yaml` | subscribe feature | Registry of URLs, output paths, intervals, timestamps. |
| `<each sub's output>` (e.g., `~/.config/clash/wgetcloud.origin.yaml`) | provider (via download) | The actual Clash YAML — proxies, groups, rules, DNS. Overwritten on each update. |
| `<daemon --config>` (default: `~/.config/clashx-rs/config.yaml`) | daemon | Whatever file is passed to `clashx-rs run --config <path>`. The daemon parses this to build its routing table. |

### The coupling

- The **daemon never reads `subscriptions.yaml`.** It only reads its `--config` path.
- The **subscribe feature never touches the daemon's `--config` path directly.** It writes only to each subscription's `output`.
- `trigger_inline_reload` reloads the daemon's `--config` path (stored as `DaemonState::config_path`), not the subscription's output.

Therefore: after a subscription download, an inline reload only has a visible effect when `--config` and the subscription's `--output` resolve to the same file on disk.

### Pattern A: `--config` IS the subscription output (recommended)

```bash
clashx-rs subscribe add \
  --name wgetcloud \
  --url 'https://<provider>/link/<token>' \
  --output ~/.config/clash/wgetcloud.origin.yaml \
  --interval 864000

clashx-rs run --config ~/.config/clash/wgetcloud.origin.yaml
```

Flow:
1. Daemon starts, parses `wgetcloud.origin.yaml`.
2. Background task downloads new content → atomic rename onto `wgetcloud.origin.yaml`.
3. Inline reload reads the same path → new proxies/rules take effect.
4. Proxy selections and cooldowns are preserved across the reload.

This pattern is idiomatic for files bearing the `#!MANAGED-CONFIG` header — the provider already expects to own the file.

### Pattern B: `--config` is a separate file

If you want `~/.config/clashx-rs/config.yaml` (with local customizations) as the daemon config, pointing `--output` at a different path will break auto-reload — `subscribe update` rewrites the subscription output, but the daemon reloads a file that didn't change.

clashx-rs has **no YAML include/merge support**, so there is no way to layer local customizations over a fetched subscription within the daemon itself. Workarounds:

1. **Make them the same file.** Set `--output ~/.config/clashx-rs/config.yaml` so the daemon's default config path *is* the subscription output. Local customizations are lost on each update — only works if you don't have any.
2. **Symlink.** `ln -sf ~/.config/clash/wgetcloud.origin.yaml ~/.config/clashx-rs/config.yaml`. Equivalent to Pattern A with a different nominal path.
3. **External merge step.** Drive your own tool (post-update script, Makefile, etc.) that merges `wgetcloud.origin.yaml` with a customizations file, writes the merged result to `--config`, then calls `clashx-rs reload`. This sits entirely outside clashx-rs.

### Recommended setup

For the wgetcloud case (and any provider using `#!MANAGED-CONFIG`):

```bash
clashx-rs subscribe add \
  --name wgetcloud \
  --url 'https://<provider>/link/<token>' \
  --output ~/.config/clash/wgetcloud.origin.yaml \
  --interval 864000

clashx-rs subscribe update           # first download
clashx-rs run --config ~/.config/clash/wgetcloud.origin.yaml
```

From then on, the daemon refreshes the config automatically on its interval and hot-reloads without intervention.

## 8. Security

Subscription YAMLs contain credentials (Trojan passwords, session tokens embedded in URLs) and subscription URLs themselves are bearer tokens. Accordingly:

- Downloaded files and `subscriptions.yaml` are written with mode `0o600` (owner-only). On save, a `set_permissions(0o600)` call fires after the atomic rename to cover the case where the file already existed with looser permissions.
- On load, `load_subscriptions_from` checks the file's mode and emits a `tracing::warn!` if group/other bits are set — draws attention to a misconfiguration without refusing to operate.
- `subscribe list` redacts URL query strings, fragments, and basic-auth userinfo when printing to stdout, so piping the output to a screenshot or pastebin doesn't leak the bearer token. The token remains intact in `subscriptions.yaml` itself.
- HTTP download has a 30-second timeout and 8 MiB size cap to prevent a hostile or misconfigured endpoint from exhausting memory or hanging the daemon's update task.

## 9. Non-goals

- **YAML include/merge.** Not supported. Users who need layered customization handle it externally (see Pattern B workaround 3).
- **Parallel downloads.** Per-cycle downloads are sequential. N is typically 1–3 for real users; `join_all` adds complexity for marginal savings.
- **Content-diff skip-reload.** After a successful download the daemon always reloads, even if the new YAML is byte-identical to the old. The reload is cheap (one write-lock, one config parse), and the logic to hash/compare before reload isn't worth the branching.
- **Subscription-URL providers other than HTTP GET with User-Agent: clash.** Some forks support `User-Agent: clash-meta`, token headers, or provider-specific auth. Not in scope.
