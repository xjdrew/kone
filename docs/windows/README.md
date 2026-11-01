# Windows 使用

当前使用 SagerNet/sing-tun 的 Wintun 后端。官方 Wintun DLL 已内嵌到程序中，不需要单独下载 DLL、安装 TAP 或预先创建网卡。
程序在管理员权限下部署驱动并创建自有网卡；这不意味着系统不再需要驱动或管理员权限。退出时关闭并移除自有网卡，驱动包可能保留在系统驱动存储中。

源码开发使用 Go 1.27.3、just 1.59.0，并在 Git Bash 的仓库根目录执行开发任务（见 [开发说明](../development.md)）：

```sh
just init
just build
cp configs/kone.example.toml config.toml
# 修改代理地址；core.tun 可留空自动分配，或指定一个尚不存在的网卡名称。
./dist/kone.exe -check -config config.toml
```

Windows 请使用明确的 `./dist/kone.exe` 路径，避免同目录遗留的无扩展名 `dist/kone` 被其他终端执行。升级旧版本后先按 [配置迁移说明](../configuration.md) 更新配置，再运行 `-check`；不自动兼容旧配置字段。

`-check`、`-version`、`-help` 不请求管理员权限。普通启动先校验配置，再检查当前进程是否已提权；未提权时自动通过 Windows 官方 `runas` 机制请求 UAC。允许后在新的管理员窗口继续运行，配置路径转为绝对路径，保留工作目录与 `-debug`。已在管理员终端启动时直接运行，不重复弹框。

原终端提示交接后退出 0，仅表示启动请求已交接，不代表网络已经就绪；真实启动日志与错误在管理员窗口查看。请在该窗口按 `Ctrl+C` 正常停止并恢复网络；原窗口退出不停止管理员实例。取消 UAC 时明确报错并退出 3，不重试弹窗；无效配置在弹框前退出 2。

服务、CI 或无交互会话使用 `-no-elevate` 禁止自动提权；此时需要调用方已具备管理员权限，否则创建网卡前返回明确提示。该选项不授予权限，也不关闭系统保护。已提权后仍出现 `Access is denied` 时保留原始错误，进一步检查驱动和系统策略。

Windows `runas` 不保证复制当前终端临时设置的代理环境。若规则引用的 `http_proxy`、`https_proxy` 或 `socks_proxy` 出站正在被环境变量定义/覆盖，自动交接会明确拒绝，避免提权后切换到不同代理。请将所需出站写入 TOML 并移除该环境覆盖，或在已提权且正确配置环境的终端使用 `-no-elevate`。程序不会把含凭据的代理 URL 放进提权命令行。

## 智能应用控制与后续构建

如果 Windows 在程序运行前就提示“应用程序控制策略已阻止此文件”，应先查看 Windows 安全中心和 `CodeIntegrity/Operational` 事件，确认是否为智能应用控制（Smart App Control）或其他策略。这一阶段连 `-check` 和请求 UAC 的代码都可能无法执行；UAC 只授予运行身份，不授予应用控制策略许可。

微软当前没有为智能应用控制提供“只允许某个 exe”的例外。相同文件名、目录、一次 UAC 同意或 Defender 排除项都不等于以后新构建得到信任。保留保护的长期交付方案是在**每次构建完成后，为最终 exe 使用受信任提供方的有效代码签名并验证**；重编译会改变文件，须重新签名，不能沿用旧 exe 的签名。签名流程需要真实证书/签名服务，编译选项或自签名不能替代受信任发布者。参见微软 [SAC 常见问题](https://support.microsoft.com/en-us/windows/security/threat-malware-protection/smart-app-control-frequently-asked-questions) 和 [SAC 代码签名要求](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control)。

Let’s Encrypt 的免费证书用于 TLS，不签发代码签名证书，不能用于签 `kone.exe`；见其 [官方 FAQ](https://letsencrypt.org/docs/faq/)。开源项目可评估申请 [SignPath Foundation 免费代码签名](https://signpath.org/)，但须通过审核并遵守其 [当前条款](https://signpath.org/terms)，包括源码/产物可验证、成员安全要求和发布签名批准。它通过托管服务保护私钥，不等于给本机任意开发构建提供可自由使用的证书。KONE 的依赖、内嵌 Wintun 和发布方式仍需在申请时如实说明，不能仅因使用开源许可证就断言一定获批。

若设备所有者决定在自己的开发机上调整此保护，请自行打开“Windows 安全中心 → 应用和浏览器控制 → 智能应用控制设置”查看当前状态和系统说明。关闭智能应用控制会影响全机程序的这项检查，并非只放行 KONE；程序不会替用户关闭它，也不需要关闭 Defender 实时保护或防火墙。是否以及如何重新启用以当前系统版本的界面和微软说明为准。

## 启动与停止

KONE 自动维护限定于当前程序和自有 TUN 地址的 TCP 防火墙例外，退出时清理。本机使用无需先运行额外防火墙脚本。
普通 PowerShell、Windows Terminal 或 Git Bash 中启动会按需请求 UAC；需要额外对 LAN 放行 DNS 等流量时，可按部署需要运行辅助脚本：

```powershell
# 可选：为受信任 LAN 额外配置规则
# just ci windows-firewall-update -Program ./dist/kone.exe
./dist/kone.exe -config config.toml
# 已提权的服务/自动化环境：
# ./dist/kone.exe -no-elevate -config config.toml
```

脚本默认只放行 Domain 和 Private 配置文件，需要 Public 时显式传 `-Profiles Public`。
源码开发者可用 `just ci windows-firewall-check` 检查规则，以上两个维护任务均不随构建或启动自动执行。
卸载本项目脚本创建的防火墙规则：`Remove-NetFirewallRule -Name Kone-TCP,Kone-UDP`。

配置迁移见 [TOML 配置说明](../configuration.md)。管理接口默认仅绑定回环地址。

全局 IPv4 接管需要设置 `core.auto-route = true` 和真实的 `core.outbound-interface`（例如 `Ethernet`）。接口名可用 `Get-NetAdapter` 查看，名称允许空格。上游代理传输和 DNS 查询绑定该接口，避免进入 TUN 循环。
`stack = "system"` 使用 `just build`；`mixed` 使用 `just build mixed`，后者启用 `with_gvisor`。
现有 TAP 名称不能直接复用；旧版本启动时被 panic 掩盖的驱动错误现在会正常返回。
