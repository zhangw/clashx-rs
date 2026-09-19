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

Control clients have a ten-second idle read/write deadline; executing a
command is not subject to that deadline. Data tunnels retain their existing
long-lived and half-close semantics. Configuration reload keeps the same
process-wide budget, permits and counters.

`status.resources` exposes the startup soft/hard FD limits, effective data
connection limit, active data/control connections and resource-pressure
count. Active control connections include the status request itself. These
are connection counts, not a live enumeration of all process descriptors.

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
