#!/bin/bash
# Temporarily stop or resume the installed per-user service.
set -euo pipefail

service="gui/$(id -u)/com.vincent.clashx-rs"
plist="$HOME/Library/LaunchAgents/com.vincent.clashx-rs.plist"
binary="$HOME/Library/Application Support/clashx-rs/bin/clashx-rs"
config="$HOME/.config/clashx-rs/config.yaml"
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
