# Connection resource budget

The daemon reads `RLIMIT_NOFILE` at startup and attempts to raise its soft
limit to 8192, without lowering an existing higher limit or changing the hard
limit. A failed increase is logged; admission uses the limit read back from
the OS. A limit too small for the reserved budget fails startup explicitly.

Data connection capacity is `min(2048, (soft_limit - 128) / 3)`:

- 128 descriptors are reserved for runtime/listeners/logs, DNS, subscription
  updates, ten background probes and up to four control connections (which
  can themselves run latency probes).
- Each data connection has a three-descriptor budget: two tunnel sockets and
  connection-establishment headroom. At a limit of 256, capacity is 42.

Excess connections are accepted and immediately closed without spawning a
handler. Existing tunnels are not evicted. Persistent accept errors back off
250 ms, with resource-pressure logs limited to once per five seconds per
listener. Freed capacity automatically admits new connections. This is not a
guarantee that an exhausted system can serve control requests; it prevents
normal admitted data traffic from consuming the control reserve.

Admission always starts in the `general` class: with the full budget, at most
1536 connections younger than 30 seconds can be admitted at once, and the
remaining 512 global permits are reachable only by promoting a connection to
`streaming`. Both class caps are `min(1536, connection_limit)`, and the global
limit itself is fd-derived (`min(2048, (soft_limit - 128) / 3)`), so a smaller
fd budget shrinks the class caps and the reserved headroom with it.
`general_overload_count` is the signal for this pre-promotion ceiling.

Control clients have a ten-second idle read/write deadline; executing a
command is not subject to that deadline.

## Connection classes and lifetime

Every data connection starts in the `general` class. The two class pools
(`min(1536, connection_limit)` permits each) sit under the fd-derived global
cap (at most 2048), so at the full 2048 budget each class is guaranteed at
least 512 permits. A class cannot exceed its cap even when the other is idle;
at the full budget the remaining headroom is the other class's guarantee. A
connection still open in both directions after 30 seconds is promoted to the
`streaming` class: when a
streaming permit is available the class permit is swapped, and every promotion
attempt changes the half-close inactivity timeout from 60 seconds to 10
minutes. A connection that has already half-closed is not promoted; it stays
in the general class and is reclaimed by the 60-second general drain.
Promotion is attempted once; if the streaming pool is full the connection
keeps its general permit but still receives the streaming timeout, and
`promotion_failure_count` records the sticky failure (it is not retried in
this version). Promotion is based on observed lifetime, not on the destination
host, so short and long requests to the same API domain land in different
classes.

Relay lifetime is activity-based, never a total-duration cap:

- no bytes in either direction for 1 hour → close (idle);
- after the first EOF, no bytes for 60s while general (including connections
  that half-closed before promotion) or 10m once promotion has been attempted
  (even if the permit swap failed) → close (half-closed);
- an immediate RST is surfaced by the copy error and closes both sides;
  a FIN-only cancellation is reclaimed by the half-close timer.

This keeps LLM reasoning streams (long silent gaps, slow token output) alive
while still reclaiming cancelled or dead tunnels. The 10-minute streaming
half-close is aligned with the OpenAI Python SDK's default 10-minute read
timeout; the proxy must not be stricter than the clients it serves.
`TCP_NODELAY` and a 60s/15s/3 TCP keepalive profile are applied to inbound and
outbound sockets;
keepalive is a backstop for vanished peers, not a substitute for the timers.

Configuration reload keeps the same process-wide budget, permits and
counters.

`status.resources` exposes the startup soft/hard FD limits, the global
connection limit, per-class limits and active counts, admissions, promotion
success/failure, relay errors and peer-closed terminations, stalled writes,
the current half-closed gauge, relay completion/idle/half-close/peer-closed
reap counts, the most recent genuine relay error (`last_relay_error`), and
the resource-pressure counters (`overload_count` includes general-class
rejections). Active control
connections include the status request itself. These are connection counts,
not a live enumeration of all process descriptors.

## Diagnostics

- ERROR `all proxies failed` carries target, group, candidate count, last
  proxy and the full error chain.
- WARN `proxy resource pressure` carries the reason and current occupancy;
  global and general-class pressure use independent 5-second throttles.
- WARN `streaming pool saturated` is emitted at most once per 10 minutes with
  occupancy; `promotion_failure_count` carries the exact rate.
- WARN `upstream stopped reading` is emitted at most once per 30 seconds per
  proxy; `stalled_count` carries the exact rate.
- Peer resets, aborts, broken pipes and TLS EOF are classified as
  `PeerClosed` (normal termination) and counted in `peer_closed_count`, not in
  `relay_error_count`.
- A genuine relay error increments `relay_error_count`, updates
  `last_relay_error` (age, target, proxy, message) and emits a WARN at most
  once per minute.
- INFO `hourly connection summary` reports per-hour deltas plus current pool
  occupancy, so a headless daemon has a heartbeat without per-connection logs.
- Per-connection routing and relay-end lines are DEBUG and include peer,
  target, proxy, duration and bytes read.
- Daemon runtime logs roll daily to
  `~/Library/Logs/clashx-rs/clashx-rs.<date>.log` on macOS; other platforms
  keep them under `~/.config/clashx-rs/logs/`. The appender removes files
  beyond 7 on each rotation. `stdout.log`/`stderr.log` only carry launchd
  startup/early output.

Local deployment and package installation set the LaunchAgent soft limit to
8192, preserve higher existing values and respect lower explicit hard limits.
Failed upgrades restore the previous plist together with the binary. Existing
running installations are only affected on deployment/restart.

Validation:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build
python3 -m unittest discover -s tests -p 'test_fd_budget.py'
python3 -m unittest discover -s tests -p 'test_macos_package.py'
```

The resource integration test uses a separate temporary HOME, loopback echo
server and daemon with both soft and hard FD limits set to 256. It checks
overload rejection, existing tunnel traffic, control availability, reload
accounting and recovery without restarting. A Rust child-process test forces
actual EMFILE and checks accept backoff and recovery after releasing FDs.
Package tests simulate launchd and exercise plist changes and rollback.
