# 开发

日常只使用根 [justfile](../justfile) 的七个入口。工具版本为 just **1.59.0**、Go **1.27.3**、Node **26.13.0**；Windows 使用 Git Bash。安装包用户无需这些开发工具，直接按 [使用说明](usage.md) 运行 KONE。

## 开始开发

在仓库根目录执行：

```sh
just init
just dev
```

`init` 检查 Git、Go、Node/npm、just、Bash 等基本工具，缺失时提示手工安装；只安装项目依赖，不安装系统工具、不运行端到端测试或修改系统网络。`dev` 默认构建所需页面和本机程序，再打开接管暂停的桌面管理；启用接管仍须用户明确操作。仅开发前端时使用 `just dev web` 启动 Vite。

单独执行 `just` 只显示帮助，不下载、构建或启动程序。初始化后，构建和打包复用未变更的依赖及前端资产，只做必要的增量工作。

所有七个日常命令都支持 `-h` / `--help`，显示用法、默认行为、可选参数和示例；帮助不会安装依赖、构建或启动程序。例如：

```sh
just init --help
just dev --help
just quality --help
just build --help
just build-all --help
just package --help
just package-all --help
```

## 日常入口

| 命令 | 用途 |
| --- | --- |
| `just init` | 检查基本工具并安装项目依赖 |
| `just dev [desktop\|web]` | 默认启动桌面管理；`web` 启动前端开发服务 |
| `just quality [quick\|full\|fmt\|vet\|benchmark]` | 默认快速检查；按需选择全面检查、格式化、静态检查或性能基准 |
| `just build` | 只构建本机 OS/架构，包含全部三种运行时协议栈 |
| `just build-all [--include-armv7]` | 默认构建三平台 amd64/arm64 六个目标，按需增加 ARMv7 |
| `just package` | 只生成本机 OS/架构的 ZIP、PKG 或 DEB |
| `just package-all [--include-armv7]` | 生成六个目标的本地便携包及本机原生安装器，按需增加 ARMv7 |

快速迭代使用 `just quality`：检查格式和 Go 静态问题，复用 Go 测试缓存运行不带 race 的应用单元测试，再运行 Web 单测。完整端到端、任务、发布和数据回归留给 CI。`just quality full` 可显式执行 race、全包覆盖率、浏览器、fuzz 和漏洞检查，可能较慢，也可能需要下载浏览器及其平台依赖；race 需要 CGO 和平台 C 编译器。构建与检查统一包含三种协议栈，不重复测试两份只差编译选项的程序。特权原生协议栈及权限恢复验收只在 CI 执行。

格式化使用 `just quality fmt`，提交前运行相关检查及 `just quality vet`。基准使用 `just quality benchmark`，计量边界见 [性能说明](performance.md)。

## 桌面程序和安装包

只需要程序时：

```sh
just init
just build
```

Windows 输出 `dist/kone.exe` 桌面程序和 `dist/kone-cli.exe` 控制台程序；macOS 输出 `dist/Kone.app` 和 `dist/kone-cli`；Linux 保留 `dist/kone` CLI。双击 Windows 程序或打开 macOS app，默认只显示托盘/菜单图标，不弹终端、不自动打开浏览器；通过图标打开管理，接管保持暂停。日常开发可直接用 `just dev`，它会实际启动对应入口。首次接管的设置步骤见 [桌面指南](desktop.md)。

所有构建同时包含 `system`、`gvisor`、`mixed`，通过 `core.stack` 运行时选择，默认 `system`；切换后暂停并重新启用接管。构建任务只生成本机程序，不因为开发 Windows 桌面就同时编译 Linux/macOS。`just build-all` 默认构建三平台的 amd64/arm64；Raspberry Pi 64 位系统使用 Linux arm64，32 位网关使用 `just build-all --include-armv7` 显式追加 Linux ARMv7。ARMv7 同样包含三种协议栈，真机性能仍需部署验收。

```sh
just package
just package-all
# 需要 32 位 Raspberry Pi 网关产物时：
just package-all --include-armv7
```

本机 `just package` 只构建并在 `release-assets/` 生成匹配当前 OS/架构的产物和清单：Windows ZIP、macOS PKG、Linux DEB。`just package-all` 用于本地审核，另外保留六个目标的便携归档以及本机可构建的原生安装器；`--include-armv7` 再追加 32 位 Linux 网关产物。两者均不运行生成的程序（包括 `-version`）、不解包临时安装，也不发布 Release。公开发布只保留六个默认目标的 Windows ZIP、macOS PKG、Linux DEB；其他平台的原生安装器在对应平台 CI 中完成。

本地清单的 `native_version_checked=false`，保守标为实验、未验收。真实版本、解包和临时安装校验保留在 CI 的 `just ci package` 默认模式；生成本地包不表示已经取得这些验收证据。

Windows ZIP 随附按用户安装的 `install.ps1`，同时携带 GUI 和 CLI，打包使用系统 Windows PowerShell 5.1，无需另装 `pwsh`。macOS 的未签名 `.pkg` 安装 `Kone.app`、`kone-cli` 和资源；app 目前未签名、公证。菜单、助手和真实 TUN 已有 CI 验收；新桌面产物的真实双击、权限弹窗、干净机器升级/卸载及系统信任仍需目标设备验收。见 [发布说明](releases.md)、[Windows](windows/README.md) 与 [macOS 权限](macos-helper.md)。

图标源文件及 `just ci icons generate` / `just ci icons check` 的维护流程见 [图标说明](branding.md)。

## CI 与高级维护

细分任务移入 `ci` 模块，不再作为日常顶层入口。需要重现某个明确的检查或维护操作时使用 `just ci <task>`，例如：

```sh
just ci test-coverage
just ci test-coverage .coverage-base ../coverage-base.out
just ci coverage-check
```

第二条要求精确目标 SHA 已检出到 `.coverage-base`，输出路径相对于该被测模块；旧 base 不需要自带 justfile。测试与覆盖率不以缓存结果代替实际测量，KONE 全包语句覆盖率不得低于 PR base。

前端浏览器、数据转换、画像分析、Windows 防火墙维护及发布编排的细分入口也通过 `just ci` 调用；这些高级命令不应成为每次构建的前置步骤。浏览器验收使用回环临时配置并保持接管暂停；涉及系统 TUN/DNS 的原生任务只允许临时 GitHub CI runner，不能在个人开发机伪造 CI 标记绕过检查。Windows 原生 system/gvisor/mixed 在同一临时 runner 顺序执行，每栈核对六个真实通过的叶子用例。

历史 `workflow_call` 将 `github.workflow_sha` 的任务定义检出到 `.ci-tools`，由 `JUST_JUSTFILE` 定位该根文件，`JUST_WORKING_DIRECTORY` 定位被测源目录；应用源码、测试、构建和打包绑定目标 SHA，发布编排使用这份固定的工作流工具。当前检查分组与注明版本的历史测量样本见 [CI 说明](ci.md)，发布操作见 [发行说明](releases.md)。

产品安装后的 `kone` 启动、安装器、HTTP API、Docker Compose 与操作系统网络命令仍直接使用，不依赖开发 justfile。[架构](architecture.md) 解释核心链路，[验收索引](acceptance.md) 区分自动化证据与仍需真机验证的范围。
