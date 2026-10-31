# Windows 使用

当前使用 `water` 的 TAP-Windows 后端。先安装 [TAP-Windows 驱动](https://github.com/OpenVPN/tap-windows6)，并确认系统中存在对应适配器。
本轮不包含自动驱动安装或 Wintun 迁移。Windows arm64 编译通过仍需要单独验证驱动兼容性。

在仓库根目录使用 Go 1.27.3 构建：

```powershell
go build -o dist/kone.exe ./cmd/kone
Copy-Item configs/kone.example.toml config.toml
# 修改 config.toml 中的代理地址；如有多个适配器，设置 core.tun 为适配器名称。
./dist/kone.exe -check -config config.toml
```

管理员 PowerShell 中配置防火墙并启动：

```powershell
./scripts/windows/update-firewall-rules.ps1 -Program (Resolve-Path ./dist/kone.exe).Path
./dist/kone.exe -config config.toml
```

脚本默认只放行 Domain 和 Private 配置文件，需要 Public 时显式传 `-Profiles Public`。
检查规则：`./scripts/windows/check-firewall-rules.ps1`。
卸载本项目脚本创建的防火墙规则：`Remove-NetFirewallRule -Name Kone-TCP,Kone-UDP`。

配置迁移见 [TOML 配置说明](../configuration.md)。管理接口默认仅绑定回环地址。
