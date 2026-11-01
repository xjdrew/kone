# 系统 DNS 引导

`dns.system` 将“运行一个 DNS 服务”和“引导本机系统查询该服务”分开。CLI/TOML 默认 `false`；Linux/macOS 管理模式首次初始化会选择 `true`，但仍需预检通过并由用户显式启用接管。既有配置的选择不会被重置。该设置不改变 HTTP/SOCKS 代理、DHCP、路由器或其他机器的 DNS。网关上的 LAN 客户端仍需由管理员配置 DNS/网关。

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

## Windows

当前 `system = true` 在 Windows 明确拒绝，界面不会提供可启用的系统引导开关。Windows 保留自有 Wintun 适配器 DNS/metric 配置与恢复；这不等同覆盖 NRPT、所有 VPN、应用自带解析器或全部系统 DNS。

应用内部缓存、已缓存 Fake-IP、DoH/DoT 或其他旁路解析有各自的生存期。暂停接管与恢复系统 DNS 不会神奇地清除所有应用缓存，也不声称观察到绕开 KONE 的查询。

## 验收隔离

确定性测试覆盖每个设置阶段失败、命令超时前已生效、外部 DNS/LLMNR 改动、设备复用、resolver 换代与命名空间不匹配。Linux 原生 CI 另起 network/mount namespace，私有 `/run`、resolver 配置、D-Bus 和 systemd-resolved，执行真实 OS stub → KONE Fake-IP → 停止恢复，以及 DNS 就绪后的服务故障；system/gvisor/mixed 分别运行。测试程序在任何写入前再次验证 namespace/resolver，不能借宿主 D-Bus 做假验收。

原生任务缺少工具或隔离失败会明确失败；mock 测试不会被称为系统 DNS 已验收。实际结果以对应 SHA 的 CI 为准。本轮没有在用户主机执行系统 DNS 设置命令。
