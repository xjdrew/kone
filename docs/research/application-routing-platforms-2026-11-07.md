# Windows 与 macOS 应用规则：系统边界与实现方向

日期：2026-11-07。KONE 代码基线：[8d018cd](https://github.com/xjdrew/kone/tree/8d018cd729f7417b7202a652c65a486ae0e2f33f)。本文补充[产品方向研究](product-direction-2026-11-07.md)，仅研究方案，未实现新的应用规则、驱动或系统扩展。

产品前提已经明确：全局模式为 Standalone、Global、Smart、Custom；应用与域名、IP 一样属于规则条件，由 Smart 和 Custom 按需使用。本文讨论这些规则如何取得可信的应用身份、如何执行，以及两个系统允许产品承诺到什么程度。

**结论：两个平台都能实现实用的应用分流，但不能用同一种进程查询方案承诺相同的覆盖范围。Windows 可以先补强现有 TUN + 系统 owner table；macOS 应同时验证原生查询与 Network Extension 透明代理两条路径。若要保证指定应用不能绕过代理，需要另设系统级执行与故障验收，不能沿用“尽力识别”模式的承诺。**

## 1 系统能力与当前实现缺口

| 问题 | Windows | macOS |
| --- | --- | --- |
| 系统有没有应用身份能力 | 有，socket owner table 和 WFP ALE 提供不同层次的能力 | 有，进程/socket 查询与 Network Extension 流元数据是不同入口 |
| KONE 当前怎样识别 | 读取 IPv4 TCP/UDP 表，查询进程路径及创建时间，两次复验 | 运行 `lsof` 与 `ps`，两次复验 socket、路径和粗粒度启动时间 |
| 当前数据能直接决定出口吗 | 不能，现有调用在转发路径上异步补充观察记录 | 同样不能；逐流启动多个外部命令也不适合决策热路径 |
| IPv6 是系统不支持吗 | 不是，官方接口支持 IPv6，KONE 尚未接入 | 不能由 KONE 当前返回 unknown 推断系统不支持；不同实现路线需分别验证 |
| 普通应用分流的首选探索 | 补 IPv6、原始连接元组匹配、缓存和首包前有界查询 | 比较原生 socket 查询与 `NETransparentProxyProvider`，避免继续扩大逐流 `lsof` 依赖 |
| “指定应用不能旁路” | 评估 WFP 的身份条件、过滤或重定向，另做停机/故障验证 | 评估流接管及系统过滤能力，另验扩展停用/崩溃行为，不能默认会阻断 |

KONE 证据：[Windows 查询](../../pkg/process/lookup_windows.go)、[macOS 查询](../../pkg/process/lookup_darwin.go)、[共同解析器](../../pkg/process/resolver.go)、[异步观察调用](../../pkg/kone/flow.go)。系统能力的官方来源见下文各路线。

需要分清三件事：**能展示进程名、能在新连接选择出口前识别应用、能阻止应用绕开选定出口**。后两者分别需要决策时序和执行机制；显示出一个进程名不能证明它们都已满足。

## 2 共同边界：先拿到应用身份 再执行规则

普通 IP/TCP/UDP 报文不携带应用名。当前 KONE 从 TUN 接收到连接后，需要拿原始源/目标地址、端口和协议去系统中关联 socket；应使用应用连接时的原始目标，包括它实际连接的 Fake-IP，不能把远端解析后的目标替换进查询元组。

建议把“应用身份解析”放到规则决策之前，并区分 `matched`、`unknown`、`remote`。身份结果带来源、观察时间和可用于失效的身份依据；缓存按网络代次、地址族、连接元组和进程生命周期失效，不仅以 PID 或本地端口为键。应用规则未启用时，不应强迫所有连接等待身份查询。

系统代理设置通常只有愿意使用该设置的应用才会遵循；单独给支持代理设置的应用配置专用 HTTP/SOCKS 入口可以做一个可选入口，但不能覆盖所有应用。KONE 要实现普通用户选择应用后统一分流，仍需 TUN 或系统流接管等机制。

应用规则也不能天然区分同一浏览器进程中的两个标签页、共享服务代发的两项业务、另一个本地代理背后的原始应用，或网关后设备中的应用。选应用时应明确覆盖哪些可执行文件、helper 和服务；系统只能报告其可观察到的网络主体，不能恢复已经丢失的业务身份。

## 3 Windows：先补现有路线 将 WFP 按能力拆开

### 3.1 系统 owner table 足以支持第一版实用分流

微软的 `GetExtendedTcpTable` 对 `AF_INET6` 提供 `TCP_TABLE_OWNER_PID_*` 表；`GetExtendedUdpTable` 也有 IPv6 owner 表。因此，KONE 当前强制使用 `AF_INET`、共同解析器拒绝非 IPv4，是实现缺口。[TCP 表](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)、[IPv6 UDP owner 结构](https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udp6row_owner_pid)

建议保留现有创建时间和二次复验思路，补齐 IPv6 表布局、scope ID、双栈地址规范化及取消处理。对未缓存身份进行短时间、有预算的查询；缓存命中不能绕过生命周期校验。进程路径权限不足、进程已退出或元组被重用时，继续返回 unknown。

UDP 的约束更强：owner 表记录本地端点及绑定者 PID，不提供完整的远端连接元组。共享端口、通配地址和 socket 共享会造成歧义；有多个候选时不能随便挑一个。TCP 查询也只是快照，不能因查询成功就忽略查询期间发生的退出、重用和并发连接。

Mihomo 的 Windows 进程实现同样使用 IP Helper API，并分别解析 IPv4/IPv6 的 TCP/UDP 表，证明这是可用的工程路线；它并不意味着同一匹配算法在所有接管时序下都满足 KONE 的身份验证要求。[Mihomo Windows 实现，固定提交](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/component/process/process_windows.go)

第一版可承诺的范围应是经过验证的本机普通应用、协议和地址族。WSL/虚拟机内部进程、系统服务代发流量和无法查询的受保护进程不能自动算入已支持范围；“源地址是本机地址”也不足以证明识别到用户期望的那个应用。

### 3.2 WFP 标准过滤与重定向不是同一个工作量

WFP 的 ALE 层能够基于应用身份和用户身份执行策略。标准应用条件使用规范化的可执行文件路径；这比连接事后按 PID 查找更接近系统建立连接时的身份，但仍需要对应用升级路径、helper 和共享服务定义覆盖范围。[ALE](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-)、[条件标识](https://learn.microsoft.com/windows/win32/fwp/filtering-condition-identifiers-)

| WFP 用法 | 解决的问题 | 工程含义 |
| --- | --- | --- |
| 通过用户态管理 API 添加 permit/block 过滤器 | 按应用允许或禁止某类连接，可作为更强的执行约束 | 不必因此自研内核 callout；但过滤器不是 HTTP/SOCKS 代理，也不会自动转发流量 |
| ALE connect/bind redirection | 在连接路径上将流量重定向给本地代理，再由代理建立出站 | 涉及 callout 驱动、本地服务、原始目标关联和防重复重定向，维护成本明显增加 |

微软提供了用户态按应用添加允许/阻断规则的示例，并建议能用标准过滤功能解决时优先用用户态管理程序。连接重定向文档则明确讨论 callout 驱动和本地代理的协作。不能把这两类能力合并成“使用 WFP 就必须写驱动”或“用一个过滤器就能代理应用”。[允许/阻断示例](https://learn.microsoft.com/en-us/windows/win32/fwp/permitting-and-blocking-applications-and-users)、[Callout 使用建议](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/callout-driver-programming-considerations)、[重定向机制](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)

若选择驱动路线，生产分发还需处理微软驱动签名、目标系统安全配置兼容、升级卸载和驱动故障恢复，不能只验证开发环境可以加载。[驱动签名要求](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)

**Windows 方向：先交付现有 TUN 路线的可靠应用规则；确有禁止旁路需求时，再验证 WFP 约束。** WFP 规则必须与 TUN、代理自身出站及系统其他过滤器共同测试；不能简单阻断应用的所有外连，否则进入 TUN 前就可能被一并阻断。只有需要直接重定向而现有路线无法满足时，再评估 callout 驱动。

## 4 macOS：原生查询与透明代理扩展两条路线

### 4.1 短期原生查询：减少开销 仍承认快照边界

当前一次正常归属识别会经历两轮 `lsof` 和 `ps`。`ps` 启动时间只有秒级，代码还会拒绝无法在这个精度下验证的过新进程。由此推断，应用刚启动时的短连接和高并发连接都值得优先测量；不能直接把这套异步观察改为所有连接同步等待。

Apple 发布的 `libproc` 接口包含 `proc_listpids`、`proc_pidinfo`、`proc_pidfdinfo` 和 `proc_pidpath`，相关结构包含 socket 信息及更细粒度的进程启动时间。它们可作为取代外部命令的候选，但读取其他进程的权限、枚举成本、兼容性和身份复验仍需实机验证；接口存在不等于能无条件查看所有应用。[Apple libproc 接口，固定提交](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/wrappers/libproc/libproc.h)、[进程/socket 结构](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info.h)

另一个工程参照是 Mihomo：其 macOS 实现读取 TCP/UDP PCB 表，再获取进程路径；解析结构大小随内核版本调整，并包含 IPv6 分支。这说明不启动 `lsof` 也能做应用匹配，同时说明结构解析有平台维护负担，不能把源码中的固定偏移当成永久稳定的产品契约。[Mihomo macOS 实现，固定提交](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/component/process/process_darwin.go)

这条路线适合先保留 KONE 当前捕获与打包方式、验证应用规则价值。仍要显示 unknown，且不能将“查到路径”提升为“能禁止应用绕过代理”。

### 4.2 流级透明代理：从系统直接取得来源应用

`NETransparentProxyProvider` 是更值得做长期原型验证的路线。它处理系统交付的应用流；`NEAppProxyFlow.metaData` 提供来源应用信息，其中包括签名标识和可选的 audit token。身份随流交付，比收到 IP 包之后再全局枚举进程更适合首包前的应用规则。[流元数据](https://developer.apple.com/documentation/networkextension/neappproxyflow/metadata)、[签名标识](https://developer.apple.com/documentation/networkextension/neflowmetadata/sourceappsigningidentifier)、[audit token](https://developer.apple.com/documentation/networkextension/neflowmetadata/sourceappaudittoken)

这一接口仍有需要明确处理的语义：拒绝接管流时，它可以让流按系统路径直接连接；它不会应用透明代理网络设置中的 DNS/代理设置，使用系统已有配置。应用身份也不自动等于完整域名证据。[透明代理行为](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider)

由此带来两个设计要求：

- **Smart 的候选流必须在放行前决定是否接管。** 将流交还系统直连之后，不能再假设 KONE 可以观察失败并接回同一条连接。若要自动回退，需先接管候选流，再在允许的出口间选择；这时直连路径如何保留 VPN 路由也要验证。
- **DNS 要独立设计。** 不能把现有 TUN/Fake-IP 设置原样复制进透明代理配置就认为已经接管 DNS。官方还对包含规则的 DNS 端口匹配作出限制；需核对系统解析、私有域名、命名连接、DoH 及直接 IP 的实际行为。[包含规则限制](https://developer.apple.com/documentation/networkextension/netransparentproxynetworksettings/includednetworkrules)

采用扩展也不自动带来“禁止旁路”：扩展未获授权、被停用、升级或崩溃时的行为需要分别验收。普通模式与严格模式必须有不同且可验证的故障处理定义。

### 4.3 分发和授权是方案的一部分

Apple 的部署矩阵区分 app extension 与 system extension：macOS 透明代理的 app extension 路径有 App Store 分发限制；system extension 可使用 Developer ID 直接分发。该矩阵不将 macOS 透明代理列为仅受管设备可用，不能把 iOS 的 MDM 限制直接套到它身上。`NETransparentProxyProvider` 类从 macOS 11 开始提供；API 的最低版本不等于 KONE 应承诺的最低支持版本。[部署矩阵 TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)

直接分发需要匹配的 Network Extension entitlement、Developer ID 签名及 provisioning profile。系统扩展还涉及宿主应用打包、系统授权状态、激活、替换和移除；现有 Go helper 取得 root 权限并不能替代这些要求。[Network Extension entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)、[系统扩展安装与生命周期](https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers)

这是支持普通用户应用分流的可行路线，不要求用户先手工配置每个应用的代理；但首次启用仍可能需要用户完成系统授权。“开箱即用”应当覆盖引导、失败解释和恢复，而不是假设可以绕开系统许可。签名、分发和兼容维护应计入产品成本。

### 4.4 不把所有 Network Extension 当成同一种 TUN

Apple 的 `NEPacketTunnelProvider` 与当前 KONE 的直接 utun 接管不是同一个接口。TN3120 对 packet tunnel 的预期用途作出限制，并针对选择性代理场景指向 macOS 透明代理。因此，若决定迁移到 Network Extension，应先选适合的 provider，不能只把当前 packet-to-proxy 代码包进 packet tunnel 就结束评估。[TN3120](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers)

per-app VPN、透明代理、内容过滤也应分别评估：前者有专门的应用配置及受管设备场景；透明代理面向流转发；内容过滤用于允许/拒绝流量，不能自动完成代理出站。KONE 面向普通 Mac 用户的首选原型应是透明代理，而不是假设所有用户都有 MDM。[VPN 路由与 per-app 配置](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)、[Network Extension 能力配置](https://developer.apple.com/documentation/xcode/configuring-network-extensions)

**macOS 方向：短期验证原生查询，长期重点验证透明代理扩展。** 两者共享规则和出站模型，但身份来源、流入口与生命周期可以不同。若仍保留网关功能，需要单独保留合适的报文接管路径，不能把本机应用流代理当成任意网关转发的替代品。

## 5 与四种模式的结合

应用身份是规则证据，不是第五种全局模式：

| 模式 | 应用规则建议行为 |
| --- | --- |
| Standalone | 保存规则但不启用会改变“不代理”承诺的业务分流；应用观察可按需保留 |
| Global | 所有非局域网业务流量遵循全局出口，不因应用识别失败而偷偷直连 |
| Smart | 先执行明确的应用/域名/IP 规则，未命中时自动判断；自动学习不覆盖应用的强制动作 |
| Custom | 按统一规则顺序处理应用/域名/IP 条件，未匹配时使用显式兜底 |

Smart 和 Custom 不应各自维护一套应用解析实现。平台适配器提供身份与能力，公共规则层产生决定；观察界面使用同一个决定，记录身份是否已验证、规则是否命中和实际出口。应用规则尚不可用的平台应明确显示能力限制，不能保存后静默忽略。

unknown 的处理必须与用户选择的保障等级一致。一般分流可按显式兜底处理并记录原因；要求某应用禁止旁路时，仅靠未知身份回退到直连不成立，而把全机 unknown 全部阻断又会影响其他应用。应先证明系统级约束能够定位和控制目标应用，再开放这种保障承诺。

## 6 建议的验证顺序与决策门槛

| 阶段 | 验证内容 | 作出什么决定 |
| --- | --- | --- |
| A：当前能力基线 | 在 Windows/macOS 真机测现有查询的正确率、unknown 原因和 P95/P99 延迟；覆盖刚启动的应用 | 分清查询开销、权限和身份缺失；不用平均值掩盖某类应用完全不可用 |
| B：Windows 应用规则原型 | IPv4/IPv6、TCP/UDP、原始元组、短连接与缓存；规则决策先于应用数据发送 | 能否用现有 TUN 路线满足普通分流，无需新增 callout 驱动 |
| C：macOS 路线对照 | 原生查询与签名的透明代理扩展，使用同一批应用和目标 | 对比身份可靠性、延迟、授权/升级成本与 DNS/VPN 兼容，确定首发路线 |
| D：严格执行单独验证 | Windows WFP 约束；macOS 接管/过滤及故障处理；停止、崩溃、升级与授权撤销 | 只有验证成立，才提供“指定应用禁止旁路”的选项 |

原型测试至少包含以下场景：

- **身份真值：** 可控应用与回环测试服务记录已知 PID、启动代次、socket 和目标，验证正确命中及 unknown；同名不同路径、PID/端口重用、socket 共享不能误认。
- **真实应用：** 浏览器及其 helper、Electron 应用、命令行、IDE、通信应用、游戏与启动器、Windows 打包应用、macOS 应用包及后台服务；分别记录实际联网主体。
- **协议与时序：** TCP、连接型/非连接型 UDP、QUIC、IPv4/IPv6、双栈竞争、首次启动的短连接、并发突发；进程查询不能无限阻塞数据面。
- **权限与网络：** 普通用户、无法查询的进程、授权拒绝/撤销、企业 VPN、系统代理、私有 DNS、换网、休眠、其他网络过滤软件共存。
- **生命周期：** 规则热改不迁移旧会话；应用升级和路径变化可解释；KONE、helper、扩展异常退出后按承诺恢复或阻断，卸载不留下失控的过滤规则。

建议将“错误归属”与“未识别”分别统计，不能为了提高展示命中率而把歧义算成成功。平台可达性和强制执行测试要在正常系统安全设置下完成；开发专用的放宽配置不能代表普通用户安装结果。

本轮依据官方 API、部署资料及固定提交的源码完成研究，未在 Linux 主机上冒称验证 Windows WFP 或 macOS Network Extension。上面的阶段是后续原型方向；本轮没有安装驱动、系统扩展，也没有更改系统网络设置。
