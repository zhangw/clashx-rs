#!/bin/bash
# Runs only after postinstall has dropped root privileges.
set -Eeuo pipefail
umask 077
scripts_dir="$(cd "$(dirname "$0")" && pwd)"
payload="$scripts_dir/payload"
app_dir="$HOME/Library/Application Support/clashx-rs"
binary="$app_dir/bin/clashx-rs"
helper="$app_dir/local-service.sh"
config_dir="$HOME/.config/clashx-rs"
config="$config_dir/config.yaml"
plist="$HOME/Library/LaunchAgents/org.clashx-rs.agent.plist"
service="gui/$(id -u)/org.clashx-rs.agent"
transaction="$app_dir/.pkg-install"
fresh=true
preserve_config=false
was_loaded=false
keep_backup=false

fail() { echo "clashx-rs installer: $*" >&2; exit 1; }
[[ "$(id -u)" != 0 && "$HOME" == /* && "$HOME" != / && -d "$HOME" ]] || fail 'Run as the target desktop user with a valid home directory.'
(cd "$payload" && shasum -a 256 -c SHA256SUMS) || fail 'Package checksum verification failed.'
"$payload/clashx-rs" --version
plutil -lint "$payload/launchagent.plist"
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

# Do not follow a prior installation's links when replacing files.
for path in "$HOME/.config" "$config_dir" "$config" "$app_dir" "$app_dir/bin" \
    "$binary" "$helper" "$app_dir/package-info.txt" "$app_dir/bin/clashx-rs.previous" \
    "$HOME/Library/LaunchAgents" "$plist"; do
    [[ ! -L "$path" ]] || fail "Symlink installation paths are unsupported: $path"
done
if [[ -e "$binary" || -e "$plist" ]]; then
    fresh=false
    [[ -x "$binary" && -f "$config" && -f "$plist" ]] || fail 'Incomplete existing installation; repair it before upgrading.'
    [[ "$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$plist")" == "$binary" &&
       "$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:1' "$plist")" == --config &&
       "$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:2' "$plist")" == "$config" &&
       "$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:3' "$plist")" == run ]] ||
        fail 'Existing LaunchAgent does not match the supported installation.'
else
    [[ ! -e "$app_dir" ]] || fail 'Existing application directory needs manual inspection.'
    if [[ -e "$config_dir" ]]; then
        [[ -d "$config_dir" && -f "$config" ]] || fail 'Existing configuration directory must contain config.yaml.'
        preserve_config=true
    fi
fi
if launchctl print "$service" >/dev/null 2>&1; then
    $fresh && fail 'A service is already loaded without a complete installation.'
    was_loaded=true
elif ! $fresh && "$binary" --config "$config" status >/dev/null 2>&1; then
    fail 'A daemon is running outside this LaunchAgent; stop it before upgrading.'
elif $preserve_config && "$payload/clashx-rs" --config "$config" status >/dev/null 2>&1; then
    fail 'A daemon is using the existing configuration; stop it before installing.'
fi

mkdir -p "$app_dir/bin"
mkdir "$transaction" || fail 'An installation is already in progress, or a failed rollback needs inspection.'
cleanup() {
    if ! $keep_backup; then
        rm -rf "$transaction"
        if $fresh; then
            rmdir "$app_dir/bin" "$app_dir" 2>/dev/null || true
            $preserve_config || rmdir "$config_dir" 2>/dev/null || true
        fi
    fi
}
trap cleanup EXIT
install -m 755 "$payload/clashx-rs" "$transaction/new-binary"
if ! $fresh; then
    cp -p "$binary" "$transaction/old-binary"
    cp -p "$plist" "$transaction/old-plist"
    [[ ! -f "$helper" ]] || cp -p "$helper" "$transaction/old-helper"
    [[ ! -f "$app_dir/package-info.txt" ]] || cp -p "$app_dir/package-info.txt" "$transaction/old-info"
fi
if $was_loaded; then
    "$binary" --config "$config" status > "$transaction/status.json"
    osascript -l JavaScript "$scripts_dir/selections.js" commands \
        "$transaction/status.json" "$binary" "$config" > "$transaction/restore.sh"
fi

wait_ready() {
    for ((attempt = 0; attempt < 30; attempt++)); do
        if "$binary" --config "$config" status >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    return 1
}

wait_stopped() {
    for ((attempt = 0; attempt < 30; attempt++)); do
        if ! launchctl print "$service" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    return 1
}
restore_selections() {
    $was_loaded || return 0
    /bin/bash "$transaction/restore.sh" || return 1
    "$binary" --config "$config" status > "$transaction/restored.json" || return 1
    osascript -l JavaScript "$scripts_dir/selections.js" verify \
        "$transaction/status.json" "$transaction/restored.json"
}
rollback() {
    trap - ERR INT TERM
    set +e
    echo 'Installation failed; restoring the previous installation.' >&2
    local failed=false
    if launchctl print "$service" >/dev/null 2>&1; then
        launchctl bootout "$service" || failed=true
        wait_stopped || failed=true
    fi
    if $fresh; then
        if ! $failed && [[ -x "$binary" ]]; then
            "$binary" --config "$config" sysproxy restore || failed=true
            # A mismatched or unreadable snapshot must survive for manual recovery.
            [[ ! -e "$config_dir/sysproxy-snapshot.json" ]] || failed=true
        fi
        if ! $failed; then
            rm -f "$binary" "$helper" "$app_dir/package-info.txt" "$plist" || failed=true
            if ! $preserve_config; then
                for name in config.yaml Country.mmdb subscriptions.yaml wgetcloud.origin.yaml; do
                    rm -f "$config_dir/$name" || failed=true
                done
                # A startup error before the daemon's shutdown handler can leave these.
                rm -f "$config_dir"/clashx-rs-*.sock "$config_dir"/clashx-rs-*.pid || failed=true
            fi
        fi
    else
        cp -p "$transaction/old-plist" "$plist" || failed=true
        cp -p "$transaction/old-binary" "$transaction/rollback-binary" &&
            mv -f "$transaction/rollback-binary" "$binary" || failed=true
        if [[ -f "$transaction/old-helper" ]]; then
            cp -p "$transaction/old-helper" "$helper" || failed=true
        else
            rm -f "$helper" || failed=true
        fi
        if [[ -f "$transaction/old-info" ]]; then
            cp -p "$transaction/old-info" "$app_dir/package-info.txt" || failed=true
        else
            rm -f "$app_dir/package-info.txt" || failed=true
        fi
        if $was_loaded; then
            launchctl bootstrap "gui/$(id -u)" "$plist" && wait_ready && restore_selections || failed=true
        fi
    fi
    if $failed; then
        keep_backup=true
        echo "Rollback incomplete. Backups retained at: $transaction; inspect the service and logs." >&2
    else
        echo 'Previous installation state restored.' >&2
    fi
    exit 1
}
trap rollback ERR INT TERM

if $was_loaded; then launchctl bootout "$service"; wait_stopped; fi
if $fresh; then
    mkdir -p "$config_dir" "$HOME/Library/LaunchAgents" "$HOME/Library/Logs/clashx-rs"
    if ! $preserve_config; then
        chmod 700 "$config_dir"
        for name in config.yaml Country.mmdb subscriptions.yaml wgetcloud.origin.yaml; do
            if [[ -f "$payload/config/$name" ]]; then
                install -m 600 "$payload/config/$name" "$config_dir/$name"
            fi
        done
    fi
    install -m 644 "$payload/launchagent.plist" "$plist"
    plutil -remove ProgramArguments.0 "$plist"
    plutil -insert ProgramArguments.0 -string "$binary" "$plist"
    plutil -remove ProgramArguments.2 "$plist"
    plutil -insert ProgramArguments.2 -string "$config" "$plist"
    plutil -replace EnvironmentVariables -json '{}' "$plist"
    plutil -replace EnvironmentVariables.HOME -string "$HOME" "$plist"
    plutil -replace WorkingDirectory -string "$HOME" "$plist"
    plutil -replace StandardOutPath -string "$HOME/Library/Logs/clashx-rs/stdout.log" "$plist"
    plutil -replace StandardErrorPath -string "$HOME/Library/Logs/clashx-rs/stderr.log" "$plist"
fi
mv -f "$transaction/new-binary" "$binary"
fd_soft=$(/usr/libexec/PlistBuddy -c 'Print :SoftResourceLimits:NumberOfFiles' "$plist" 2>/dev/null || echo 0)
fd_hard=$(/usr/libexec/PlistBuddy -c 'Print :HardResourceLimits:NumberOfFiles' "$plist" 2>/dev/null || echo 8192)
fd_target=8192
if [[ "$fd_hard" -ge 0 && "$fd_hard" -lt "$fd_target" ]]; then fd_target=$fd_hard; fi
if [[ "$fd_soft" -ge 0 && "$fd_soft" -lt "$fd_target" ]]; then
    /usr/libexec/PlistBuddy -c "Set :SoftResourceLimits:NumberOfFiles $fd_target" "$plist" 2>/dev/null ||
        /usr/libexec/PlistBuddy -c "Add :SoftResourceLimits:NumberOfFiles integer $fd_target" "$plist"
fi
install -m 755 "$payload/local-service.sh" "$helper"
install -m 600 "$payload/package-info.txt" "$app_dir/package-info.txt"
if $fresh; then launchctl enable "$service"; fi
if $fresh || $was_loaded; then
    launchctl bootstrap "gui/$(id -u)" "$plist"
    wait_ready
    restore_selections
    "$binary" --config "$config" sysproxy status
fi
if ! $fresh; then
    cp -p "$transaction/old-binary" "$transaction/previous"
    mv -f "$transaction/previous" "$app_dir/bin/clashx-rs.previous"
fi
trap - ERR INT TERM
echo 'clashx-rs installed. Existing configuration and startup settings were preserved on upgrade.'
