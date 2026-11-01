# 开发与任务入口

从仓库根目录使用 [just](https://github.com/casey/just) **1.59.0** 执行开发、测试、构建和脚本任务。Go 固定为 **1.27.3**；前端、数据转换和发行元数据任务使用 **Node 26.13.0**。Windows 开发使用 Git Bash，并让 `just`、Go、Node 和 Git Bash 在 PATH 中可用。race 测试还需要 CGO 和平台 C 编译器。

```sh
just
```

默认只列出任务，不构建、不下载依赖、不启动 KONE，也不修改系统网络。参数和当前任务以根 [justfile](../justfile) 为准；添加新入口时同时更新这里。just 调用底层 Go、npm、Node 和平台脚本，不改变其测试或权限要求。

安装包用户直接运行 `kone`、`install.sh` 或 `install.ps1`，不需要安装 just。文档中的 KONE 启动参数、HTTP API、Docker Compose 和操作系统网络设置属于产品使用；不要为了使用发行包安装开发工具。

## 桌面构建与运行

在 Windows 的 Git Bash 中构建包含最新管理页面的桌面程序：

```sh
just web-deps
just web-build
just build dist/kone.exe
```

然后双击 `dist/kone.exe` 或在终端执行 `./dist/kone.exe`，不传 `-config`。也可以在安装前端依赖后用 `just desktop` 一次构建页面、编译并启动管理程序；这个任务会实际启动 KONE。程序打开管理界面并保持接管暂停，使用普通用户的持久配置目录；托盘提供管理、启用、暂停、诊断和退出。启用接管时才按需请求独立 UAC 网络助手。`just build-mixed dist/kone.exe` 另外编入 mixed 协议栈支持，仍需在配置中选择协议栈。

Linux/macOS 使用 `just build` 后运行 `./dist/kone`；macOS 在桌面会话中提供原生菜单栏，并按需授权独立网络助手。已有的管理页面已经内嵌，未修改前端时可直接构建，无需重新安装 Node 依赖。

`just package-local` 构建页面、七个二进制目标，并在 `release-assets/` 生成当前主机平台的本地安装包；它校验原生架构的程序版本，不发布 Release。Windows 便携 ZIP 随附按用户安装的 `install.ps1`。macOS 的便携包和未签名 `.pkg` 安装的是命令行程序及资源，并不是已签名、公证的 `.app`。托盘、菜单、助手和真实 TUN 已有 CI 验收；真实鼠标交互、授权弹窗、干净机器升级/卸载、手机证书信任以及签名/公证仍需目标设备验收。打包范围和信任边界见 [发布说明](releases.md)、[Windows 使用](windows/README.md) 与 [macOS 权限](macos-helper.md)。

## 常用任务

| 任务 | 用途 |
| --- | --- |
| `just build [output]` | 构建 system 栈 CLI；Windows 默认 `dist/kone.exe`，其他平台默认 `dist/kone` |
| `just build-mixed [output]` | 构建包含 `with_gvisor` 的 CLI，允许选择 mixed 栈 |
| `just desktop` | 构建页面及本机程序，然后实际启动默认暂停的管理界面 |
| `just fmt` | 格式化 Go 源码 |
| `just check-config [config]` | 校验 TOML；默认使用完整示例，不启用接管 |
| `just go-deps` / `just go-verify` | 下载依赖 / 核验模块摘要 |
| `just vet` | 静态检查全部 Go 包 |
| `just test` / `just test-mixed` | 普通 / mixed 构建的全包 race 测试 |
| `just test-coverage [directory] [output]` | 被测目录的全包 atomic 语句覆盖率；默认 `.` 与 `coverage.out` |
| `just coverage-check [base] [head]` | 按语句数精确比较覆盖率，默认 `coverage-base.out` 与 `coverage.out` |
| `just test-pe` | Windows 上的 sing-tun PE 加载器回归 |
| `just test-macos-desktop` | macOS 原生菜单和私有助手边界测试 |
| `just quality-check` | 格式与模块文件一致性检查 |
| `just fuzz [duration]` / `just vuln` | 配置 fuzz（默认 15 秒）/ 依赖可达漏洞检查 |

`just test` 同时运行包内单元测试和普通端到端测试。带权限的真实 TUN/DNS 用例单独由 CI 执行，不能把本地跳过算作通过。覆盖率输出路径相对于被测模块；将精确 base SHA 检出到 `.coverage-base` 后可以运行：

```sh
just test-coverage
just test-coverage .coverage-base ../coverage-base.out
just coverage-check
```

第二条复用当前任务定义，旧 base 无需自带 justfile。

## 前端与浏览器

所有前端任务也从仓库根目录执行，无需先进入子目录：

| 任务 | 用途 |
| --- | --- |
| `just web-deps` | 安装锁文件中的前端依赖 |
| `just web-dev` / `just web-preview` | 启动前端开发 / 构建预览服务 |
| `just test-web` | 前端单元测试 |
| `just web-build` / `just web-check` | 更新内嵌离线资产 / 检查资产与源码一致 |
| `just web-browsers` | 安装浏览器和所需系统依赖 |
| `just test-web-e2e` | 三种浏览器的旅程及真实管理闭环检查 |
| `just test-release` / `just test-data` | 发布与任务约束单测 / 数据转换单测 |
| `just test-tasks` | 单独验证 just 入口、脚本边界和历史重放约束 |

### Browser journeys

先完成前端依赖、页面构建和浏览器安装，然后运行：

```sh
just web-deps
just web-build
just web-browsers
just test-web-e2e
```

同一入口适用于 Windows Git Bash。未提供 `KONE_MANAGEMENT_TEST_BINARY` 时，任务自动构建专用管理测试程序并为本次运行设置绝对路径；已有该变量时复用指定程序。CI 通过 `just ci-web-fixture` 在 runner 临时目录构建并传递该路径，这是依赖 `RUNNER_TEMP` 和 `GITHUB_ENV` 的 CI 入口。浏览器仅监听回环并使用临时配置，真实管理始终保持接管暂停，不启用 TUN；用例清单、真实执行报告和跳过检查仍必须通过。

## 基准、数据与构建

| 任务 | 用途 |
| --- | --- |
| `just benchmark-metadata` | 记录提交、硬件、Go 和负载元数据到 `baseline/` |
| `just benchmark` | 核心与 GeoIP 三样本基准、启动检查及匹配画像 |
| `just profile [file] [binary]` | pprof；默认 `baseline/cpu.out` 与 `baseline/kone.test` |
| `just geoip-convert [参数]` | 转换本地 DB-IP 文件；完整参数见 GeoIP 说明，不会自动下载数据 |
| `just build-all` | 构建七个发行目标及对应构建身份；ARMv7 使用 system，其余包含 mixed |
| `just package-local` | 构建并生成本机平台安装包，不发布；会运行原生架构的版本校验 |
| `just source-bundle` | 根据已生成的构建身份打包对应源码和依赖 |
| `just docker-build` / `just docker-check` | 构建 `kone:ci` 镜像 / 无特权配置烟雾检查 |
| `just windows-firewall-check` | Windows 上检查可选 LAN 防火墙规则 |
| `just windows-firewall-update -Program ./dist/kone.exe` | 在已提权的 Windows 终端显式更新可选 LAN 防火墙规则 |

开发机可通过环境变量选择单个交叉目标，例如 `GOOS=linux GOARCH=arm64 just build dist/kone-linux-arm64`；ARMv7 再设置 `GOARCH=arm GOARM=7`。构建成功不代表该架构已通过原生驱动、桌面或设备性能验收。

基准不创建 TUN，不修改系统网络；[性能说明](performance.md) 区分核心合成负载与真实 TUN 采样。[GeoIP 说明](geoip.md) 记录数据来源、许可、摘要与转换参数。

## CI 和发布任务

原生 `ci-linux-build/tun/dns-tools/dns`、`ci-macos-build/tun/session`、`ci-windows-tun` 和 `ci-ss` 只用于临时 GitHub CI runner。入口检查 CI、平台及临时目录；Windows 另要求显式选择 system/mixed，并核对各自六个真实通过的叶子用例。不要在日常开发机设置 CI 标记来绕过这些边界。

`just package`、`just release-plan`、`just release-marker`、`just release-publish` 和 `just release-withdraw` 由发布工作流提供精确 SHA、版本、工件和权限。它们不会因为普通开发构建而自动发布；正式安装/升级与发布操作见 [发布说明](releases.md)。

PR 使用根 justfile。历史 `workflow_call` 将 `github.workflow_sha` 的任务工具检出到 `.ci-tools`，由 `JUST_JUSTFILE` 定位该根文件，`JUST_WORKING_DIRECTORY` 定位被测源目录；测试和应用发布脚本仍来自目标 SHA。11 个执行检查、覆盖率及原生恢复断言保持不变，见 [CI 分组](ci.md)。
