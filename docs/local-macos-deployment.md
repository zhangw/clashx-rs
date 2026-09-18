# 本机 macOS 部署与服务管理

适用于已经安装的 Vincent 用户 LaunchAgent（`com.vincent.clashx-rs`）。登录后启动，退出或崩溃后由 launchd 自动拉起；无需运行 `local-run.sh` 或 `local-sysproxy.sh`。

## 更新版本

在仓库根目录执行，无需 sudo：

```bash
./scripts/deploy-local-macos.sh
```

脚本先运行 `cargo test --locked`、Clippy 和 release 构建。从 Cargo 的 JSON 构建结果读取实际二进制路径，兼容 `CARGO_TARGET_DIR` 和 Cargo 配置的输出目录。检查成功后，将新二进制暂存到安装目录，备份旧版本，卸载服务，原子替换二进制，再加载服务并等待控制接口就绪。切换期间现有连接会短暂中断。替换或启动验证失败时，脚本尝试恢复旧二进制并重新加载服务；检查失败输出及日志确认恢复结果。

安装位置：

- 二进制：`~/Library/Application Support/clashx-rs/bin/clashx-rs`
- 上一个版本：同目录下的 `clashx-rs.previous`
- 启动项：`~/Library/LaunchAgents/com.vincent.clashx-rs.plist`
- 配置：`~/.config/clashx-rs/config.yaml`
- 日志：`~/Library/Logs/clashx-rs/stdout.log` 和 `stderr.log`

部署保留现有配置、系统代理 bypass 和启动项，不创建 bin 软链接。停服前读取当前节点选择，启动就绪后逐组恢复并回读核验；失败回滚时也恢复这份选择快照。恢复完成前存在短暂使用启动默认节点的窗口，部署期间请勿同时切换节点。这不会让运行时选择跨后续崩溃或登录持久化；后续启动仍按原启动项配置选择节点。仅清理 PATH 和常见 bin 目录中名为 `clashx-rs`、指向本仓库 `target/release` / `target/debug` 二进制的链接，或已经失效的同名链接。普通文件及其他有效安装的链接不删除。清理权限不足时会报告路径；此时服务更新已经完成。

部署脚本必须在服务已加载时运行；若此前临时停止，先按下文恢复。控制接口就绪不等于所有远端代理节点均可用；部署后可另行验证网络：

```bash
curl --proxy http://127.0.0.1:7890 --max-time 20 -o /dev/null -w '%{http_code}\n' https://www.gstatic.com/generate_204
```

预期 `204`。若修改了 mixed-port，请对应修改端口。

## 临时停止（下次登录仍自动启动）

在仓库根目录执行（卸载服务并明确关闭系统代理，可重复执行）：

```bash
./scripts/local-service.sh stop
```

对应的手动指令：

```bash
launchctl bootout "gui/$(id -u)/com.vincent.clashx-rs"
```

这会卸载本次会话的服务并发送终止信号，阻止 KeepAlive 重新拉起。clashx 正常退出时会尝试恢复原系统代理设置。由于启用前可能已经存在指向 clashx 的代理设置，如需明确关闭系统代理，再执行：

```bash
"$HOME/Library/Application Support/clashx-rs/bin/clashx-rs" sysproxy off
```

已经停止时，再次 bootout 会报告找不到服务。不要用 `clashx-rs stop` 或直接 kill 代替 bootout：服务仍加载时，KeepAlive 会再次启动进程。

## 当前会话恢复运行

在仓库根目录执行（加载服务并等待就绪，可重复执行）：

```bash
./scripts/local-service.sh start
```

对应的手动指令：

```bash
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.vincent.clashx-rs.plist"
```

服务启动后通过 `--sysproxy` 重新开启系统代理。

## 查看状态

```bash
launchctl print "gui/$(id -u)/com.vincent.clashx-rs"
"$HOME/Library/Application Support/clashx-rs/bin/clashx-rs" status
"$HOME/Library/Application Support/clashx-rs/bin/clashx-rs" sysproxy status
```

## 永久禁用 / 重新启用自启动

永久禁用与临时停止不同，需要显式 disable：

```bash
launchctl disable "gui/$(id -u)/com.vincent.clashx-rs"
launchctl bootout "gui/$(id -u)/com.vincent.clashx-rs"
"$HOME/Library/Application Support/clashx-rs/bin/clashx-rs" sysproxy off
```

恢复自启动并立即运行：

```bash
launchctl enable "gui/$(id -u)/com.vincent.clashx-rs"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.vincent.clashx-rs.plist"
```
