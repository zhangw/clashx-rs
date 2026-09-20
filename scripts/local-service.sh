#!/bin/bash
# Temporarily stop or resume the installed per-user service.
set -euo pipefail

service="gui/$(id -u)/org.clashx-rs.agent"
plist="$HOME/Library/LaunchAgents/org.clashx-rs.agent.plist"
binary="$HOME/Library/Application Support/clashx-rs/bin/clashx-rs"
config="$HOME/.config/clashx-rs/config.yaml"
# Discover older service labels by executable path, without assuming an account name.
matched_plist=''
for candidate in "$HOME/Library/LaunchAgents/"*.plist; do
    [[ -f "$candidate" ]] || continue
    candidate_binary=$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$candidate" 2>/dev/null) || continue
    [[ "$candidate_binary" == "$binary" ]] || continue
    [[ -z "$matched_plist" ]] || { echo 'Multiple clashx-rs LaunchAgents found; inspect them before continuing.' >&2; exit 1; }
    matched_plist="$candidate"
done
if [[ -n "$matched_plist" ]]; then
    plist="$matched_plist"
    label=$(/usr/libexec/PlistBuddy -c 'Print :Label' "$plist")
    [[ -n "$label" ]] || { echo 'LaunchAgent label is empty.' >&2; exit 1; }
    service="gui/$(id -u)/$label"
fi
case "${1:-}" in
    stop)
        if launchctl print "$service" >/dev/null 2>&1; then
            launchctl bootout "$service"
        fi
        "$binary" --config "$config" sysproxy off
        echo 'Service stopped; automatic startup at next login remains enabled.'
        ;;
    start)
        if ! launchctl print "$service" >/dev/null 2>&1; then
            launchctl bootstrap "gui/$(id -u)" "$plist"
        fi
        for ((attempt = 0; attempt < 30; attempt++)); do
            if "$binary" --config "$config" status; then
                "$binary" --config "$config" sysproxy status
                exit 0
            fi
            sleep 1
        done
        echo 'Service did not become ready; check ~/Library/Logs/clashx-rs/' >&2
        exit 1
        ;;
    *)
        echo "Usage: $0 {stop|start}" >&2
        exit 2
        ;;
esac
