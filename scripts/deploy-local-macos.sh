#!/bin/bash
# Update the existing per-user LaunchAgent installation.
set -Eeuo pipefail

[[ "$(uname -s)" == Darwin ]] || { echo 'macOS is required' >&2; exit 1; }
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
install_dir="$HOME/Library/Application Support/clashx-rs/bin"
binary="$install_dir/clashx-rs"
config="$HOME/.config/clashx-rs/config.yaml"
plist="$HOME/Library/LaunchAgents/com.vincent.clashx-rs.plist"
service="gui/$(id -u)/com.vincent.clashx-rs"
[[ -x "$binary" && -f "$plist" && -f "$config" ]] || {
    echo 'Existing clashx-rs LaunchAgent installation is required' >&2; exit 1;
}
[[ "$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$plist")" == "$binary" ]] || {
    echo 'LaunchAgent binary path does not match installation' >&2; exit 1;
}
launchctl print "$service" >/dev/null

cd "$repo_dir"
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
deploy_tmp="$(mktemp -d)"
trap 'rm -rf "$deploy_tmp"' EXIT
cargo build --locked --release --message-format=json-render-diagnostics > "$deploy_tmp/build.jsonl"
artifact="$(python3 - "$deploy_tmp/build.jsonl" <<'PYTHON'
import json
import sys

with open(sys.argv[1]) as stream:
    artifacts = [item['executable'] for line in stream
                 if (item := json.loads(line)).get('reason') == 'compiler-artifact'
                 and item['target']['name'] == 'clashx-rs'
                 and 'bin' in item['target']['kind'] and item.get('executable')]
if len(artifacts) != 1:
    raise SystemExit('Expected exactly one clashx-rs executable from Cargo')
print(artifacts[0])
PYTHON
)"
"$artifact" --version

# Stage on the same filesystem; never overwrite an executable in use.
install -m 755 "$artifact" "$binary.new"
cp -p "$binary" "$binary.previous"
cp -p "$plist" "$deploy_tmp/previous.plist"
# Capture immediately before stopping, after the potentially lengthy build.
"$binary" --config "$config" status > "$deploy_tmp/status.json"
python3 - "$deploy_tmp/status.json" <<'PYTHON'
import json
import sys

with open(sys.argv[1]) as stream:
    selections = json.load(stream)['selections']
if not isinstance(selections, dict) or not all(
    isinstance(k, str) and isinstance(v, str) for k, v in selections.items()
):
    raise SystemExit('Invalid runtime selections; leaving service running')
PYTHON

wait_ready() {
    for ((attempt = 0; attempt < 30; attempt++)); do
        if "$binary" --config "$config" status >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_stopped() {
    for ((attempt = 0; attempt < 30; attempt++)); do
        if ! launchctl print "$service" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

restore_selections() {
    python3 - "$binary" "$config" "$deploy_tmp/status.json" <<'PYTHON'
import json
import subprocess
import sys

binary, config, snapshot = sys.argv[1:]
with open(snapshot) as stream:
    selections = json.load(stream)['selections']
command = [binary, '--config', config]
for group, proxy in selections.items():
    subprocess.run(command + ['switch', '--', group, proxy], check=True)
actual = json.loads(subprocess.check_output(command + ['status']))['selections']
if actual != selections:
    raise SystemExit('Runtime selections differ after restoration')
PYTHON
}

rollback() {
    trap - ERR
    echo 'Deployment failed; restoring previous binary and selections' >&2
    launchctl bootout "$service" >/dev/null 2>&1 || true
    wait_stopped || true
    cp -p "$deploy_tmp/previous.plist" "$plist"
    if mv -f "$binary.previous" "$binary" &&
        launchctl bootstrap "gui/$(id -u)" "$plist" &&
        wait_ready && restore_selections; then
        echo 'Previous binary and selections restored' >&2
    else
        echo 'Rollback failed; check service state and logs' >&2
    fi
    exit 1
}
trap rollback ERR
launchctl bootout "$service"
wait_stopped
fd_soft=$(/usr/libexec/PlistBuddy -c 'Print :SoftResourceLimits:NumberOfFiles' "$plist" 2>/dev/null || echo 0)
fd_hard=$(/usr/libexec/PlistBuddy -c 'Print :HardResourceLimits:NumberOfFiles' "$plist" 2>/dev/null || echo 8192)
fd_target=8192
if [[ "$fd_hard" -ge 0 && "$fd_hard" -lt "$fd_target" ]]; then fd_target=$fd_hard; fi
if [[ "$fd_soft" -ge 0 && "$fd_soft" -lt "$fd_target" ]]; then
    /usr/libexec/PlistBuddy -c "Set :SoftResourceLimits:NumberOfFiles $fd_target" "$plist" 2>/dev/null ||
        /usr/libexec/PlistBuddy -c "Add :SoftResourceLimits:NumberOfFiles integer $fd_target" "$plist"
fi
mv -f "$binary.new" "$binary"
launchctl bootstrap "gui/$(id -u)" "$plist"
wait_ready
restore_selections
"$binary" --config "$config" status
"$binary" --config "$config" sysproxy status
trap - ERR

# Remove only clashx-rs links to this checkout's build output, or broken
# clashx-rs links. Preserve regular files and links to other installations.
python3 - "$repo_dir" <<'PY'
import os
import sys
from pathlib import Path

repo = Path(sys.argv[1])
roots = {Path(p) for p in os.environ.get('PATH', '').split(':') if p}
roots.update(Path.home() / p for p in ('bin', '.local/bin', '.cargo/bin'))
roots.update((Path('/usr/local/bin'), Path('/opt/homebrew/bin')))
for root in sorted(roots):
    link = root / 'clashx-rs'
    if not link.is_symlink():
        continue
    target = link.resolve()
    if link.exists() and target not in (
        repo / 'target/release/clashx-rs', repo / 'target/debug/clashx-rs'
    ):
        continue
    try:
        link.unlink()
        print(f'Removed stale link: {link} -> {target}')
    except PermissionError:
        print(f'Permission denied removing stale link: {link}', file=sys.stderr)
        sys.exit(1)
PY
printf 'Deployment complete. Previous binary: %s\n' "$binary.previous"
