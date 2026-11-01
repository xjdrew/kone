# 系统 DNS 引导

`dns.system` 将“运行一个 DNS 服务”和“引导本机系统查询该服务”分开。CLI/TOML 默认 `false`；Linux/macOS/Windows 管理模式首次初始化会选择 `true`，但仍需预检通过并由用户显式启用接管。既有配置的选择不会被重置。该设置不改变 HTTP/SOCKS 代理、DHCP、路由器或其他机器的 DNS。网关上的 LAN 客户端仍需由管理员配置 DNS/网关。

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

## macOS：自有临时解析服务

macOS 实现使用独立 `scutil` 会话，以随机 UUID 创建 `State:/Network/Service/<UUID>/DNS` 临时值。它使用 `add key temporary`，键已存在就失败；不覆盖物理/VPN 服务、不调用 `networksetup`，也不持久改写全机 DNS。空的 `SupplementalMatchDomains` 配合优先级表示默认解析范围，更具体的原生 VPN/内网域仍优先。`ServerPort` 支持独立监听端口，相关字段见 [Apple DNS schema](https://developer.apple.com/documentation/systemconfiguration/dns-entity-keys)。

优先级使用 `SupplementalMatchOrders` 的 CFNumber 数组：`scutil` 的 `* #` 组合明确创建数字数组，避免标量 `SearchOrder` 被 configd 按服务顺序重写。验收检查实际系统配置中的顺序值，再验证真实解析，不只确认动态存储中存在一个字典。[scutil 字典类型处理](https://github.com/apple-oss-distributions/configd/blob/main/scutil.tproj/dictionary.c)

Darwin utun 是点对点设备，自有 DNS 的系统入口使用已独占监听的 `127.0.0.1:<端口>`；不会把系统查询重新发进虚拟地址路由。上游必须在引导前读取，不能把同端口的自身 loopback 服务当作上游。创建后还要确认系统解析配置已选中该服务，才能报告接管就绪；无法保留的特殊应用/VPN 解析语义不被宣称透明兼容。

临时值的所有权属于 configd 会话。正常停止先关闭该会话并确认键已移除，再关闭 DNS；scutil 崩溃或持有 stdin 的父进程退出，也会使会话结束并自动撤销其临时值。其他会话接管该键后，configd 不再由旧会话删除它，KONE 保留外部值并报告。原生实现依据 [scutil add temporary](https://github.com/apple-oss-distributions/configd/blob/main/scutil.tproj/cache.c)、[configd 会话关闭](https://github.com/apple-oss-distributions/configd/blob/main/configd.tproj/_configclose.c) 与 [跨会话替换](https://github.com/apple-oss-distributions/configd/blob/main/configd.tproj/_configset.c) 的所有权检查。

生命周期同时监测会话死亡、自有键变化与 utun 身份变化；异常会触发统一停止，避免系统引导已消失而界面继续表示正常。一次性 macOS runner 对同一程序的 system/gvisor/mixed 逐栈验收临时原始解析器、实际系统顺序与查询、DNS 就绪后的故障恢复，以及运行中第二实例的原始上游发现；另有独立的精确子进程句柄终止和会话恢复验收，前后核对物理 DNS 与默认路由。结果以对应 SHA 的实际执行为准。特殊 VPN、应用自带解析器及部署环境仍需单独验收，不能从这些用例推断全部兼容。

## Windows：独占的本地 NRPT 引导

Windows 支持 `system = true`，要求 `listen-port = 53`。DNS 监听就绪后，KONE 为本次 Wintun 地址创建一条本地 NRPT 根规则 `.`，并确认它在有效策略中被选中。Windows DNS API 优先查询 NRPT；单纯降低适配器 metric 不能保证所有系统查询都选择该适配器。[Windows 名称解析顺序](https://learn.microsoft.com/windows/security/operating-system-security/network-security/vpn/vpn-name-resolution)

物理/VPN 适配器的 DNS、metric 和默认路由不会被该引导改写，更具体的内网/VPN NRPT 规则保持优先。已有根规则、域策略使本地规则无效、要求加密 DNS 的全局策略，或无法验证的旧租约会阻止启动；KONE 不替换这些策略。启动前发现真实上游，并排除已有 KONE 根规则和 Wintun DNS 地址，避免第二实例把查询递归送回 KONE。企业 VPN、DoH/DoT 和应用自带解析器仍需按实际部署验收。

根规则是持久的 Windows 配置。KONE 先在 `HKLM\SOFTWARE\Kone\DNSLeases` 写入最小所有权记录，再创建含随机标识的 NRPT 规则；记录只允许管理员/SYSTEM 修改，不含代理配置或凭据。全局互斥量防止不同管理配置或 CLI 同时接管根规则。正常退出、启动失败或父进程退出时，持有租约的进程先核对并撤销自己的规则，再关闭 DNS。系统 DNS 缓存不会被全机清空。[NRPT 规则接口](https://learn.microsoft.com/powershell/module/dnsclient/add-dnsclientnrptrule)

如果租约进程也被强制终止，规则可能在 Wintun 消失后仍然存在。重新打开本机 Web 管理，在恢复区域检查并显式执行恢复，Windows 会请求管理员授权。恢复重新验证机器记录及完整规则，只删除仍与本次租约相符的规则；即使崩溃发生在 Windows 生成规则 GUID 与回写 GUID 之间，也可依据随机标识找回。仍在运行的其他实例、被外部更改或无法证实的规则均保留并提示人工检查，不能通过清除管理记录掩盖尚未恢复的 DNS。

一次性 Windows CI runner 对 system/gvisor/mixed 分别验证系统 API → KONE Fake-IP、内网规则保留、正常恢复、根规则冲突、外部改动保留，以及强杀租约进程/接管进程后的完整与未回写 GUID 两种恢复。测试使用 `Resolve-DnsName`，不使用会绕过 NRPT 的 `nslookup` 或显式 DNS 服务器参数；前后比较物理适配器 DNS、metric 和默认路由。实际结果以对应 SHA 的 CI 为准。[Microsoft 对 NRPT 验证工具的说明](https://learn.microsoft.com/windows/client-management/mdm/vpnv2-csp)

应用内部缓存、已缓存 Fake-IP、DoH/DoT 或其他旁路解析有各自的生存期。暂停接管与恢复系统 DNS 不会神奇地清除所有应用缓存，也不声称观察到绕开 KONE 的查询。

## 验收隔离

确定性测试覆盖每个设置阶段失败、命令超时前已生效、外部 DNS/LLMNR 改动、设备复用、resolver 换代与命名空间不匹配。Linux 原生 CI 另起 network/mount namespace，私有 `/run`、resolver 配置、D-Bus 和 systemd-resolved，执行真实 OS stub → KONE Fake-IP → 停止恢复，以及 DNS 就绪后的服务故障；system/gvisor/mixed 分别运行。测试程序在任何写入前再次验证 namespace/resolver，不能借宿主 D-Bus 做假验收。

原生任务缺少工具或隔离失败会明确失败；mock 测试不会被称为系统 DNS 已验收。实际结果以对应 SHA 的 CI 为准。本轮没有在用户主机执行系统 DNS 设置命令。
