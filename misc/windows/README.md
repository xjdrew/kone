# use kone in Windows

## 预设条件
1. 安装 tap-windows (NDIS 6)

* [tap-windows](https://community.openvpn.net/openvpn/wiki/GettingTapWindows)
* [直接下载](https://build.openvpn.net/downloads/releases/tap-windows-9.21.0.exe)

2. 配置防火墙，允许kone重定向连接
使用管理员权限启动 PowerShell，执行`update-firewall-rules.ps1`。

> 请注意修改 `update-firewall-rules.ps1` 脚本中 Program 参数为kone实际路径。
> 关于Windows防火墙的更多信息，参考:
> * [Manage Windows Firewall with the command line](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-with-command-line?tabs=powershell)
> * [NetSecurity](https://learn.microsoft.com/en-us/powershell/module/netsecurity/?view=windowsserver2022-ps)

3. 编译&运行kone方式同linux