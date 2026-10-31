# Windows 使用

当前使用 SagerNet/sing-tun 的 Wintun 后端。官方 Wintun DLL 已内嵌到程序中，不需要单独下载 DLL、安装 TAP 或预先创建网卡。
程序在管理员权限下部署驱动并创建自有网卡；这不意味着系统不再需要驱动或管理员权限。退出时关闭并移除自有网卡，驱动包可能保留在系统驱动存储中。

在仓库根目录使用 Go 1.27.3 构建：

```powershell
go build -o dist/kone.exe ./cmd/kone
Copy-Item configs/kone.example.toml config.toml
# 修改代理地址；core.tun 可留空自动分配，或指定一个尚不存在的网卡名称。
./dist/kone.exe -check -config config.toml
```

KONE 自动维护限定于当前程序和自有 TUN 地址的 TCP 防火墙例外，退出时清理。本机使用无需先运行额外防火墙脚本。
管理员 PowerShell 中启动；需要额外对 LAN 放行 DNS 等流量时，可按部署需要运行辅助脚本：

```powershell
# 可选：为受信任 LAN 额外配置规则
# ./scripts/windows/update-firewall-rules.ps1 -Program (Resolve-Path ./dist/kone.exe).Path
./dist/kone.exe -config config.toml
```

脚本默认只放行 Domain 和 Private 配置文件，需要 Public 时显式传 `-Profiles Public`。
检查规则：`./scripts/windows/check-firewall-rules.ps1`。
卸载本项目脚本创建的防火墙规则：`Remove-NetFirewallRule -Name Kone-TCP,Kone-UDP`。

配置迁移见 [TOML 配置说明](../configuration.md)。管理接口默认仅绑定回环地址。

全局 IPv4 接管需要设置 `core.auto-route = true` 和真实的 `core.outbound-interface`（例如 `Ethernet`）。接口名可用 `Get-NetAdapter` 查看，名称允许空格。上游代理传输和 DNS 查询绑定该接口，避免进入 TUN 循环。
`stack = "system"` 可直接构建；`mixed` 需要 `go build -tags with_gvisor -o dist/kone.exe ./cmd/kone`。
现有 TAP 名称不能直接复用；旧版本启动时被 panic 掩盖的驱动错误现在会正常返回。
