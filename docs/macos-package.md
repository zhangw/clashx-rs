# macOS 原生安装包

使用 `.pkg` 完成首次安装和后续升级，目标机无需 Rust、Python、Homebrew 或源码。当前仅支持 **Apple Silicon、与构建机相同的 macOS 主版本**。安装归属于当前登录的桌面用户，主目录从系统账户信息读取；安装时提供管理员授权。

## 构建

在已有 clashx-rs 部署的源机仓库根目录执行：

```bash
./scripts/build-macos-pkg.sh
```

脚本运行安装流程测试、`cargo test --locked`、Clippy 和 release 构建，然后输出：

```text
dist/clashx-rs-<程序版本>-<UTC构建时间>-macos<主版本>-arm64.pkg
dist/clashx-rs-<程序版本>-<UTC构建时间>-macos<主版本>-arm64.pkg.sha256
```

构建需要 Rust/Cargo、Clippy、Python 3 以及 macOS 的 `pkgbuild` / `productbuild`。构建不会停止或更新本机运行中的服务。包名包含构建时间，安装记录还包含程序 SHA-256，避免仅凭 `0.1.0` 判断版本。

如果只需封装当前已安装程序，可跳过编译和代码检查（程序须支持 `sysproxy restore`；旧版本会拒绝打包）：

```bash
./scripts/build-macos-pkg.sh --binary "$HOME/Library/Application Support/clashx-rs/bin/clashx-rs"
```

包内首次安装配置取自构建用户：`~/.config/clashx-rs/config.yaml`、`Country.mmdb`，以及存在时的 `subscriptions.yaml`、`wgetcloud.origin.yaml`。启动项使用仓库模板，安装时生成目标用户路径，不复制构建机的启动参数或个人路径。不包含 socket、PID、日志、系统代理恢复快照或指向其它仓库的软链接。

每次构建先解包成品并验证内部 SHA-256，再发布安装包及校验文件。成功后自动按包名中的 UTC 构建时间保留最近两个安装包，删除更旧的本项目 macOS arm64 包及对应 `.sha256`；其它文件不受影响。

**包内含私密代理配置和可能存在的订阅凭据，只能私下保存和分发，不能提交仓库。** `dist/` 已被 Git 忽略。构建默认产出未签名包；系统可能阻止打开，需核实来源后按系统安全提示处理。需要标准分发体验时，应使用 Developer ID 签名并公证，参阅 [Apple 分发说明](https://developer.apple.com/developer-id/)。

## 安装与升级

1. 登录目标机需要安装的用户桌面。首次安装前关闭其它代理软件及其自动启动，避免端口和系统代理冲突。
2. 将 `.pkg` 与 `.sha256` 放在同一目录，可用 `shasum -a 256 -c <安装包文件名>.sha256` 检查传输完整性。
3. 双击 `.pkg`，按系统安装器完成安装。期间不要切换节点或运行其它部署操作。
4. 按下一节验证服务和网络。

| 场景 | 行为 |
| --- | --- |
| 首次安装 | 写入包内初始配置、程序及 LaunchAgent，开启登录自启动并启动服务 |
| 仅有现有配置，尚无程序和 LaunchAgent | 保留整个配置目录及权限，不补入包内配置或数据库；安装程序及 LaunchAgent，开启登录自启动并启动服务；失败回滚保留原配置 |
| 已有完整安装 | 仅更新程序、服务管理脚本和包版本记录；保留配置、订阅、数据库及 LaunchAgent |
| 升级前服务运行中 | 短暂停服，启动新程序并恢复、核验运行时节点选择 |
| 升级前服务停止或禁用 | 保持停止或禁用，不自行启用 |
| 启动或节点恢复失败 | 尝试恢复旧程序、管理脚本及原运行状态；安装器报告失败 |
| 安装残缺或路径不匹配 | 停止安装，不覆盖原配置；需先检查现有部署 |

同一个包支持首次安装和升级，也支持本仓库原有的完整 LaunchAgent 安装。升级不会将包内初始配置覆盖到目标机；配置调整仍在目标机单独进行。后续登录或崩溃重启时，默认节点仍由 LaunchAgent 决定。

代理以目标桌面用户身份运行，不作为 root 常驻服务。只在该用户登录后自启动。首次安装优先使用目标机已有配置（须包含普通文件 `config.yaml`），否则采用包内配置；LaunchAgent 来自安装包。已有配置引用的数据库等资源须在目标机可用。包内配置可能允许局域网无认证访问，目标机须使用适合其网络的配置。

新安装使用 `org.clashx-rs.agent` 服务标识。已有安装通过 LaunchAgent 的程序路径识别，保留原标识、路径及启动参数；发现多个匹配启动项时停止安装，避免重复服务。

## 验证与管理

安装后检查状态和代理连通性（若修改了 mixed-port，请对应修改端口）：

```bash
"$HOME/Library/Application Support/clashx-rs/bin/clashx-rs" status
"$HOME/Library/Application Support/clashx-rs/bin/clashx-rs" sysproxy status
curl --proxy http://127.0.0.1:7890 --max-time 20 -o /dev/null -w '%{http_code}\n' https://www.gstatic.com/generate_204
```

服务运行时应能查询状态，curl 预期返回 `204`，再验证浏览器。安装器的控制接口检查不代表远端节点均可用；原本停止的服务升级后仍需手动启动才能验证网络。

临时停止并关闭系统代理：

```bash
"$HOME/Library/Application Support/clashx-rs/local-service.sh" stop
```

启动：

```bash
"$HOME/Library/Application Support/clashx-rs/local-service.sh" start
```

日志位于 `~/Library/Logs/clashx-rs/`，安装记录位于 `~/Library/Application Support/clashx-rs/package-info.txt`。永久禁用/重新启用自启动见 [服务管理](local-macos-deployment.md)。

安装失败时查看安装器日志（“窗口 → 安装器日志”）及服务日志。普通失败会自动尝试回滚。首次安装回滚使用 `sysproxy restore` 恢复原代理设置；无快照或 daemon 已恢复时不修改设置，恢复失败则保留快照及程序以便重试。若提示回滚不完整，备份保留在 `~/Library/Application Support/clashx-rs/.pkg-install/`，检查恢复前不要删除该目录或强行重装。断电或强制终止安装也可能留下此目录。

## 实现与验证边界

安装包使用 macOS `pkgbuild` / `productbuild`。系统安装器执行的 root 包装脚本仅做环境检查和临时文件调度，再通过 `launchctl asuser` / `sudo -u "$target_user"` 运行用户级安装事务。文件替换、服务控制、配置读取均在目标用户身份下完成。事务自行管理备份和回滚，不能依赖系统安装器自动撤销脚本修改。

测试使用临时目录和模拟 launchd，覆盖首次安装、升级保留配置和节点、停止/禁用状态、启动及节点恢复失败回滚、残缺安装拒绝和包校验失败。模拟测试不等于第二台 Mac 的真实安装验证；首次分发仍须完成一次实际安装、升级和重新登录验收。
