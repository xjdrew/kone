# 新特性实现与验收索引

本索引将 [产品需求](features.md) 和 [管理页面需求](management-ui-requirements.md) 关联到实现、自动化证据和仍需人工验收的边界。实现代码、用例存在、CI 通过及真机验收是四个不同状态；最终结果以 [本轮 PR 的最新检查](https://github.com/xjdrew/kone/pull/40/checks) 为准，不以编译成功或界面显示推断网络已经成功。

开发验证只运行合成/回环服务及隔离浏览器 API，没有启动本机 KONE，也没有修改用户正在使用的代理、DNS、路由或防火墙。需要真实 TUN 的测试只在 CI 的 Linux 临时网络命名空间或 Windows 专用 runner 中执行。

| 需求 | 本轮落点 | 自动化证据/入口 | 验收边界 |
| --- | --- | --- | --- |
| SAFE-01 | 只读预检、平台/权限/端口/出口/地址冲突、失败启动回滚 | [预检](../pkg/kone/control_api_test.go)、[Linux 生命周期](../test/integration/lifecycle_linux_test.go)、[IPv6 故障](../test/integration/ipv6_linux_test.go) | 系统 DNS/VPN 组合仍需部署环境确认 |
| SAFE-02 | 代理端点与上游 DNS 绑定真实出口、内网解析路径排他、规则保护例外 | [端点解析](../pkg/kone/dns_endpoint_test.go)、[网关](../test/integration/gateway_linux_test.go)、[UDP 与 SS](../test/integration/shadowsocks_test.go) | 不自动接管运营方的 DHCP/防火墙配置 |
| SAFE-03 | 控制层持续存在，启用/暂停/恢复与数据面生命周期分离，操作有界/可查询 | [控制层](../pkg/control/controller_test.go)、[管理链路](../test/integration/control_test.go) | 浏览器断开不代表数据面已经停用 |
| SAFE-04 | 最小所有权日志、运行代次、遗留检测与保守恢复，外部网络变化暂停接管 | [恢复](../pkg/control/recovery_test.go)、[网络变化](../pkg/control/network_watch_test.go)、[运行说明](runtime.md) | 无法确认所有权时要求本机处理，不按网卡名称猜测后删除 |
| RULE-01/02 | 稳定规则标识/来源/顺序、解释决策、协议/端口、精确域名/单地址规则草稿 | [规则](../pkg/kone/routing_explain.go)、[控制 API](../pkg/control/server_test.go)、[浏览器链路](../web/e2e/console.spec.js) | 规则模拟和 TCP 探测均不表示应用请求成功 |
| RULE-03 | 保存/应用/重启分开，运行版本分歧可见，撤销与并发版本检查；域名规则可设绝对到期时间 | [配置存储](../pkg/control/tasks_test.go)、[控制层](../pkg/control/controller_test.go)、[浏览器冲突/临时规则](../web/e2e/console.spec.js) | 到期后仅影响新连接，旧连接/Fake-IP 映射保留；临时 CIDR/FINAL/GEOIP 明确拒绝 |
| DNS-01 | IPv4/可选 IPv6 DNS UDP/TCP、截断回退、上游发现；Linux resolved 自有 link 引导与退出前恢复 | [DNS 协议](../test/integration/dns_linux_test.go)、[私有 resolver 验收](../test/integration/dns_system_linux_test.go)、[Windows TUN](../test/integration/lifecycle_windows_test.go)、[范围](system-dns.md) | macOS/Windows 的 system=true 明确拒绝；Windows 保留自有适配器 DNS，不推定任意 VPN/应用都经过 KONE |
| DNS-02 | 最长后缀排他解析器，内部名称失败不回退公网，系统上游按运行发现 | [DNS 端点](../pkg/kone/dns_endpoint_test.go)、[配置](../pkg/kone/config_model_test.go)、[DNS 说明](configuration.md) | 原生多接口搜索域/企业 VPN 的全部解析语义仍需各平台验证 |
| DNS-03 | 查询事件/缓存/负响应/真实与虚拟地址分离、容量/过期、活动映射 pin | [缓存与映射](../pkg/kone/dns_cache_test.go)、[查询界面](../web/src/app.js) | DoH/DoT 绕开不可观察；不解密 TLS，不永久保留全部查询 |
| OBS-01/02/03 | TCP/UDP 统一载荷计数、零字节失败、独立整体计数、有界明细和快照游标 | [观察回归](../pkg/kone/observation_test.go)、[真实数据链路](../test/integration/observability_linux_test.go) | 已淘汰明细不由新连接补位；速率与累计、业务与控制分开 |
| OBS-04 | Windows IPHelper、Linux proc、macOS lsof/ps 尽力关联，验证时间/标识，异步有界队列 | [进程采集](../pkg/process)、[本机真实连接](../pkg/process/native_test.go) | 远端 LAN、权限不足、复用或尚不支持的元组均标未知/远端，不伪归属 |
| DIAG-01/02/03 | 用户明确目标、独立 TCP/可选 TLS、直连/代理对比、限并发/超时/去重/取消 | [诊断任务](../pkg/control/tasks_test.go)、[浏览器诊断](../web/e2e/console.spec.js) | 不重放业务；独立 UDP 探测暂不支持，界面明确禁用；内部名称使用其解析范围 |
| CFG-01/02/03/04 | 无参数先打开管理，用户目录持久化，单 TUN 元数据，命名出站及稳定 ID/启停，凭据保留/替换/清除，严格 TOML 导入/默认恢复 | [存储与导入](../pkg/control/tasks_test.go)、[CLI](../test/integration/cli_test.go)、[管理端到端](../test/integration/control_test.go) | 禁用代理后新连接明确拒绝，不执行直连/UDP 回退；损坏原件保留，现有连接保留其原快照 |
| UI-01/02/03 | 八页面离线 Web、状态/错误/权限、显式副作用、Host/Origin/会话/CSRF 保护 | [API 安全](../pkg/control/server_test.go)、[前端单元](../web/test)、[浏览器](../web/e2e/console.spec.js) | 前端禁用按钮之外还有服务端权限检查；请求成功不代替运行结果 |
| UI-04 | 原生采样路径桑基、守恒、其他合并、固定窗口/anchor/实际 flow IDs 分块钻取、等价路径列表 | [图形单测](../web/test/graph.test.mjs)、[观察](../pkg/kone/observation_test.go)、[高基数钻取](../web/e2e/console.spec.js) | 明细有展示/保留上限并提示；无流量不放生产演示数据；代理端点不当最终目的 |
| UI-05 | 320px 八页面；360/390/430/768/1024px 首页；Chromium 全套及 WebKit/Firefox 关键页面、触控钻取、只读与弱网恢复项目 | [浏览器布局/截图](../web/e2e/console.spec.js)、[引擎与视口](../web/playwright.config.js)、[构建目标](../web/vite.config.js) | 按 engine/viewport 留存报告；自动化引擎不等于真实 iOS/Android，横竖屏/锁屏/软键盘仍需设备验收 |
| UI-06 | 默认回环；主机显式私网 HTTPS、本地 CA、短期配对、只读/管理与撤销 | [LAN/TLS](../pkg/control/lan_test.go)、[会话](../pkg/control/server_test.go)、[访问说明](../README.md) | 不自动安装根证书、修改防火墙或开放路由器；手机证书信任/网络隔离需真机检查 |
| DESK-01/02 | 默认管理、单实例和受控停机，三平台应用/安装包链路 | [CLI 与管理](../test/integration/control_test.go)、[打包工作流](../.github/workflows/go.yml)、[发布矩阵](releases.md) | 平台托盘、权限窗口与干净机器升级/卸载以具体平台验收为准；未签名/未公证不冒充完整发行体验 |
| PERF-01/02 | 规则、DNS、GeoIP、观察开关/会话/并发管理查询与高基数容量基线，system/mixed 构建留档 | [基线说明](performance.md)、[核心基准](../pkg/kone/core_benchmark_test.go)、[观察基准](../pkg/kone/observation_benchmark_test.go) | 这是核心 CPU/分配及合成计数，不是 TUN 带宽或 RTT；真实硬件/长时转发需独立实验 |
| DATA-01 | 有界本地文件、可信 SHA-256、来源许可版本、原子保存、回退与明确下次加载 | [GeoIP 数据](../pkg/geoip/database_test.go)、[控制 API](../pkg/control/geoip_test.go)、[端到端](../test/integration/geoip_test.go)、[界面校验](../web/e2e/console.spec.js) | 不根据输入 URL 自动下载；保存前需暂停，不替换旧流持有的数据快照 |
| PROTO-01 | SOCKS5 原生 UDP、保留 direct/reject/显式回退；Linux/Windows 可选 IPv6 A/AAAA、规则、TCP/UDP、清理 | [Linux IPv6](../test/integration/ipv6_linux_test.go)、[Windows IPv6](../test/integration/ipv6_windows_test.go)、[IPv6 范围](ipv6.md)、[UDP 传输](../pkg/proxy) | macOS IPv6 启用明确拒绝；ICMP、任意分片/扩展头不在未验收时承诺 |
| PROTO-02 | 三种 Shadowsocks AEAD2017 方法，TCP/原生 UDP、认证与篡改拒绝 | [独立协议互操作](../test/integration/shadowsocks_test.go)、[出站说明](configuration.md) | 不支持旧流密码、AEAD-2022、插件；实际第三方服务端版本仍需部署互操作 |
| REL-01/02/03 | 每 first-parent master SHA 独立全门禁，版本/源码/工件绑定，开发唯一预发布、稳定升格、撤回与回退 | [发布逻辑单测](../test/release/release.test.mjs)、[发布流程](../.github/workflows/release.yml)、[操作说明](releases.md) | PR 只验证打包，不产生生产 Release；签名/公证和真实发布由合并后授权流程验收 |

## 评审时按这条路径验证

先检查最新 SHA 的 Go 三平台 race/覆盖率、Web、包安装、漏洞/模糊、Linux namespace 与 Windows 驱动任务结果，再从运行行为验收：

1. 在独立配置目录打开无参数管理；确认未接管，纯直连可配置，坏代理不影响管理。
2. 编辑入站/出站/规则/DNS；确认草稿、已保存、运行版本分开，重名/引用/凭据/并发冲突不会静默覆盖。
3. 在隔离网络启用，制造端口或路由失败；确认失败后管理仍可用、资源清理及遗留说明真实。
4. 产生 TCP/UDP、零字节失败与长连接；比较桑基分母/各层总量，钻取后新连接不混入旧样本，缺失明细明确提示。
5. 对明确目标独立诊断，按证据保存精确规则，应用后用新业务连接验证；再验证撤销及原连接历史不被改写。
6. 用真实手机在私网 HTTPS 配对，测试只读/管理、撤销、锁屏/换网恢复和证书信任。自动化布局成功不能替代这一步。
7. 使用对应架构包安装、运行、暂停、退出、升级和回退；检查版本/校验和/源码及无自有网络残留。

本机既有全局代理与故意不可达的用户代理配置不属于测试夹具，不得为验收修改它们。需要在真实主机接管时，应另选获准的隔离环境和明确的恢复路径。
