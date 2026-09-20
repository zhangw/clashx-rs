#!/bin/bash
# Build a private installer from the source machine's existing deployment.
set -euo pipefail
umask 077
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
artifact=''
case "$#" in
    0) ;;
    2) [[ "$1" == --binary ]] || { echo "Usage: $0 [--binary PATH]" >&2; exit 2; }
       artifact="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")" ;;
    *) echo "Usage: $0 [--binary PATH]" >&2; exit 2 ;;
esac
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || {
    echo 'Build on an Apple Silicon Mac.' >&2; exit 1;
}
source_config="$HOME/.config/clashx-rs"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/scripts/payload/config" "$repo_dir/dist"
printf '*\n' > "$repo_dir/dist/.gitignore"
payload="$work/scripts/payload"
cd "$repo_dir"

if [[ -z "$artifact" ]]; then
    python3 -m unittest discover -s tests -p 'test_*package*.py'
    cargo test --locked
    cargo clippy --locked --all-targets -- -D warnings
    cargo build --locked --release --message-format=json-render-diagnostics > "$work/build.jsonl"
    artifact="$(python3 - "$work/build.jsonl" <<'PY'
import json
import sys
with open(sys.argv[1]) as stream:
    artifacts = [item['executable'] for line in stream
                 if (item := json.loads(line)).get('reason') == 'compiler-artifact'
                 and item['target']['name'] == 'clashx-rs'
                 and 'bin' in item['target']['kind'] and item.get('executable')]
if len(artifacts) != 1:
    raise SystemExit('Expected one clashx-rs executable from Cargo')
print(artifacts[0])
PY
)"
else
    echo 'Packaging an existing binary; compilation and code checks are skipped.'
fi
lipo -verify_arch arm64 "$artifact"
"$artifact" --version
"$artifact" sysproxy restore --help >/dev/null || {
    echo 'The binary must support sysproxy restore for safe installation rollback.' >&2; exit 1;
}
install -m 755 "$artifact" "$payload/clashx-rs"
install -m 755 scripts/local-service.sh "$payload/local-service.sh"
install -m 644 "$source_config/config.yaml" "$payload/config/config.yaml"
install -m 644 "$source_config/Country.mmdb" "$payload/config/Country.mmdb"
for name in subscriptions.yaml wgetcloud.origin.yaml; do
    if [[ -f "$source_config/$name" ]]; then
        install -m 644 "$source_config/$name" "$payload/config/$name"
    fi
done
install -m 644 scripts/macos-pkg/launchagent.plist "$payload/launchagent.plist"
macos_version="$(sw_vers -productVersion)"
macos_major="${macos_version%%.*}"
printf '%s\n' "$macos_major" > "$payload/macos-major"
package_version="$(date -u +%Y%m%d.%H%M%S)"
binary_version="$("$artifact" --version | awk '{print $2}')"
package_name="clashx-rs-$binary_version-$package_version-macos$macos_major-arm64.pkg"
{
    printf 'Package version: %s\nBinary version: %s\nmacOS major: %s\n' "$package_version" "$binary_version" "$macos_major"
    printf 'Packaging checkout: %s\n' "$(git rev-parse HEAD)"
    printf 'Binary SHA-256: %s\n' "$(shasum -a 256 "$payload/clashx-rs" | awk '{print $1}')"
} > "$payload/package-info.txt"
(
    cd "$payload"
    shasum -a 256 clashx-rs local-service.sh launchagent.plist config/* macos-major package-info.txt > SHA256SUMS
)
install -m 755 scripts/macos-pkg/postinstall "$work/scripts/postinstall"
install -m 644 scripts/macos-pkg/install-user.sh scripts/macos-pkg/selections.js "$work/scripts/"
pkgbuild --nopayload --scripts "$work/scripts" --identifier org.clashx-rs.agent \
    --version "$package_version" "$work/component.pkg"
cat > "$work/distribution.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>clashx-rs</title>
  <options customize="never" hostArchitectures="arm64"/>
  <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
  <volume-check><allowed-os-versions><os-version min="$macos_major" before="$((macos_major + 1))"/></allowed-os-versions></volume-check>
  <welcome file="welcome.txt" mime-type="text/plain"/>
  <conclusion file="conclusion.txt" mime-type="text/plain"/>
  <choices-outline><line choice="default"/></choices-outline>
  <choice id="default" visible="false"><pkg-ref id="org.clashx-rs.agent"/></choice>
  <pkg-ref id="org.clashx-rs.agent" version="$package_version" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
XML
mkdir "$work/resources"
cat > "$work/resources/welcome.txt" <<TEXT
clashx-rs $binary_version — macOS $macos_major / Apple Silicon

请登录需要安装的用户桌面后安装，需要管理员授权；程序归属于当前桌面用户。
首次安装保留目标机已有配置；没有配置时采用包内初始配置，并启用登录自启动和系统代理。
初始配置来自构建机器，可能开放局域网代理；本安装包含私密代理配置。
升级保留现有配置、启动参数和停止/禁用状态；运行中的服务会短暂重启。
安装期间请勿手动部署或切换节点。
TEXT
cat > "$work/resources/conclusion.txt" <<'TEXT'
程序：~/Library/Application Support/clashx-rs/bin/clashx-rs
服务管理：~/Library/Application Support/clashx-rs/local-service.sh start|stop
日志：~/Library/Logs/clashx-rs/

安装成功表示文件安装及必要的控制接口检查通过，不代表所有远端节点可用。
请验证浏览器和代理网络。如果升级前服务已停止，新版也保持停止。
TEXT
productbuild --distribution "$work/distribution.xml" --package-path "$work" \
    --resources "$work/resources" "$work/$package_name"
pkgutil --expand-full "$work/$package_name" "$work/expanded"
(cd "$work/expanded/component.pkg/Scripts/payload" && shasum -a 256 -c SHA256SUMS)
install -m 600 "$work/$package_name" "$repo_dir/dist/$package_name"
(cd "$repo_dir/dist" && shasum -a 256 "$package_name" > "$package_name.sha256")
python3 "$repo_dir/scripts/prune-macos-packages.py" "$repo_dir/dist"
printf 'Installer: %s/dist/%s\nThis private package is unsigned and contains proxy credentials.\n' "$repo_dir" "$package_name"
