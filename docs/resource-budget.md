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

Admission always starts in the `general` class: at most 1536 connections
younger than 30 seconds can be admitted at once. The remaining 512 global
permits are reserved for the `streaming` class and only become reachable via
promotion. `general_overload_count` is the signal for this pre-promotion
ceiling; the overall `connection_limit` in `status.resources` remains 2048.

Control clients have a ten-second idle read/write deadline; executing a
command is not subject to that deadline.

## Connection classes and lifetime

Every data connection starts in the `general` class. The two class pools
(1536 permits each) sit under the 2048 global cap, so each class is always
guaranteed at least 512 permits. A class cannot exceed 1536 even when the
other is idle; the remaining headroom is the other class's guarantee. A
connection still open after 30 seconds is promoted to the `streaming` class:
the class permit is swapped and the half-close inactivity timeout changes
from 60 seconds to 10 minutes. Promotion is attempted once; if the streaming
pool is full the connection keeps its general permit but still receives the
streaming timeout, and `promotion_failure_count` records the sticky failure
(it is not retried in this version). Promotion is based on observed
lifetime, not on the destination host, so short and long requests to the same
API domain land in different classes. If the streaming pool is full, the
connection keeps its general permit but still receives the long timeout; the
failed upgrade is counted in `status.resources`.

Relay lifetime is activity-based, never a total-duration cap:

- no bytes in either direction for 1 hour → close (idle);
- after the first EOF, no bytes for 60s (general) or 10m (streaming) → close
  (half-closed);
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
connection limit, per-class limits and active counts, promotion success and
failure counts, relay completion/idle/half-close reap counts, and the
resource-pressure counters. Active control
connections include the status request itself. These are connection counts,
not a live enumeration of all process descriptors.

Local deployment and package installation set the LaunchAgent soft limit to
8192, preserve higher existing values and respect lower explicit hard limits.
Failed upgrades restore the previous plist together with the binary. Existing
running installations are only affected on deployment/restart.

Validation:

```sh
cargo test --workspace
cargo clippy --all-targets -- -D warnings
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
