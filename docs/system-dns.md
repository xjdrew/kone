# 系统 DNS 引导

`dns.system` 将“运行一个 DNS 服务”和“引导本机系统查询该服务”分开。CLI/TOML 默认 `false`；Linux 管理模式首次初始化会选择 `true`，但仍需预检通过并由用户显式启用接管。该设置不改变 HTTP/SOCKS 代理、DHCP、路由器或其他机器的 DNS。网关上的 LAN 客户端仍需由管理员配置 DNS/网关。

## Linux：只管理本次创建的 TUN link

当前引导支持 systemd-resolved。系统应用必须已经使用 `127.0.0.53` 或 `127.0.0.54` stub，KONE 不改写 `/etc/resolv.conf`。`busctl` 与运行中的 resolver 必须可用；服务进程必须能验证为与 KONE 处于同一网络命名空间，避免容器或网络命名空间中的程序误改宿主 DNS。无法验证时预检失败，用户可以明确关闭此选项并采用手工 DNS 方案。

```toml
[dns]
system = true
# servers = []  # 从启动前的系统解析范围读取真实上游
```

KONE 在创建独占 TUN、配置路由并确认所有 IPv4/IPv6 UDP/TCP DNS 监听就绪后，才为该 link 设置 DNS、根路由域 `~.` 和 DNS 默认路由。现有更具体的 VPN/内网解析域仍按系统的最长匹配规则优先，不把根路由域当作强制截获所有 DNS。系统调用方式及域路由语义以 [resolvectl](https://www.freedesktop.org/software/systemd/man/latest/resolvectl.html) 和 [systemd-resolved D-Bus API](https://www.freedesktop.org/software/systemd/man/255/org.freedesktop.resolve1.html) 为依据。

启用系统引导时，KONE 使用在修改前发现的真实上游/系统范围，不再把会转回 KONE 的 resolved stub 当作自身上游。不能安全发现真实上游、存在无法复制的加密/严格解析策略时会阻断或按所属范围拒绝，不自动改用公共 DNS。显式手工解析规则仍优先。系统/企业 VPN 的全部应用级策略并非一个后缀列表所能完整替代，运行状态会保留来源、搜索域、接口与不可安全复制的警示。

本地 Fake-IP DNS 不是签名的公网权威答案，也不是本地 DoT 服务。全局严格 DNSSEC/DoT 设置无法透明保持时，系统引导明确拒绝；不会为了启用而降低系统全局安全策略。仅在自己新建 link 上配置必要的本地解析模式，物理/VPN link 不被重写。

退出或启动后段失败时，先恢复 DNS 引导，再关闭 DNS 监听。清理前检查 open TUN 的身份、接口 index、resolver 的唯一 owner/PID，以及自己管理的 link 配置快照。只逐项恢复修改过的 DNS、域、默认路由和本地安全模式，保留既有 LLMNR/mDNS/NTA；不使用会重置所有 link 属性的无条件 `revert`。其他程序已经改写或替换对象时保留其新状态并报告。TUN link 被移除后，resolved 的相应临时 link 配置也随之消失；这不需要清空全机 DNS 缓存。[官方说明](https://www.freedesktop.org/software/systemd/man/latest/resolvectl.html)

## Windows 与 macOS

当前 `system = true` 在 Windows/macOS 明确拒绝，界面不会提供可启用的系统引导开关。Windows 仍保留原有的自有 Wintun 适配器 DNS/metric 配置与恢复；这不等同覆盖 NRPT、所有 VPN、应用自带解析器或全部系统 DNS。macOS 可以配置 KONE 入站/上游并手动选择 DNS；尚未提供可验证所有权的系统 DNS 写入方案。

应用内部缓存、已缓存 Fake-IP、DoH/DoT 或其他旁路解析有各自的生存期。暂停接管与恢复系统 DNS 不会神奇地清除所有应用缓存，也不声称观察到绕开 KONE 的查询。

## 验收隔离

确定性测试覆盖每个设置阶段失败、命令超时前已生效、外部 DNS/LLMNR 改动、设备复用、resolver 换代与命名空间不匹配。Linux 原生 CI 另起 network/mount namespace，私有 `/run`、resolver 配置、D-Bus 和 systemd-resolved，执行真实 OS stub → KONE Fake-IP → 停止恢复，以及 DNS 配置后的晚启动故障；system/mixed 分别运行。测试程序在任何写入前再次验证 namespace/resolver，不能借宿主 D-Bus 做假验收。

原生任务缺少工具或隔离失败会明确失败；mock 测试不会被称为系统 DNS 已验收。实际结果以对应 SHA 的 CI 为准。本轮没有在用户主机执行系统 DNS 设置命令。
