# IPv6 接管

IPv6 默认关闭，不改变现有 IPv4 客户端或 Raspberry Pi 网关配置。Linux/Windows 可显式启用 IPv6 TUN、AAAA Fake-IP、IPv6 TCP/UDP 转发与 IPv6 规则；同一程序包含的 system/gvisor/mixed 使用相同出站策略，`core.stack` 默认 system。macOS 在对应地址、路由恢复和驱动链路完成验收前，启动时明确拒绝非空 `ipv6-network`，不会悄悄忽略它。

```toml
[core]
network = "10.192.0.1/16"
ipv6-network = "fd7a:203::1/120"
outbound-interface = "eth0"
# auto-route6 = false
```

`ipv6-network` 是独占 TUN 的 ULA 主机地址和前缀，接受 `/64` 至 `/120`，不能与现有网络重叠。该地址和后一个协议栈地址不分配给域名；地址池最多保留 262143 个候选地址并排除保留地址。IPv6 没有 IPv4 广播地址，不使用 IPv4 广播判断分配边界。

默认只接管 IPv6 Fake-IP 子网和显式 `IP-CIDR6` 规则。`auto-route6 = true` 添加 `::/1`、`8000::/1` 两条路由，要求非空 `outbound-interface`；原默认路由及更具体路由保留。IPv4 的 `auto-route` 与 IPv6 的 `auto-route6` 相互独立。IPv6 地址、路由与 DNS 监听均由同一个引擎生命周期管理，启动失败逆序回滚，退出恢复自己的变更。

Windows 使用同一个新建、独占的 Wintun 适配器承载双栈。配置前读取 IPv6 的 GUID/接口索引、MTU、路由度量、DAD 与自动配置状态；仅在自有适配器设置所需参数和 ULA 地址，system/mixed 另为系统 TCP 监听创建受限防火墙例外，完整 gvisor 无需该例外。恢复检查适配器身份与当前属性，不覆盖其他程序的不同修改。路由使用 IPv6 地址族与 `::` on-link 下一跳；不会把这些参数应用到原物理网卡。

```toml
[[rules]]
type = "IP-CIDR6"
pattern = "2001:db8:1234::/48"
outbound = "reject"
```

示例 CIDR 是文档地址，应替换为实际目标。规则顺序、协议/端口条件、`direct`/`reject` 和代理名称语义与 IPv4 相同；GEOIP 数据仍为 IPv4 范围，不会为 IPv6 地址虚构归属。修改 IPv6 地址、全局路由开关或 CIDR 捕获范围需要重启。

## DNS 与核心链路

启用后，同一个域名的 A 和 AAAA 使用独立地址映射，均保留稳定 Fake-IP 和活动会话 pin。AAAA 请求通过 IPv4 或 IPv6 DNS 传输都能得到相同策略结果；DNS 服务同时在 IPv4/IPv6 TUN 地址监听 UDP/TCP。上游 DNS 可走任意可用地址家族，不等于业务目标被转换为该家族。

客户端连接 AAAA Fake-IP 后，sing-tun 把 IPv6 TCP/UDP 会话交给 KONE。KONE 还原域名、匹配规则并检查出站能力；直连只使用真实 AAAA 地址，缺少真实 IPv6 地址时失败，不拿 A 地址伪装成 IPv6 目标。代理保留域名交由远端解析，实际目标地址不可得时记录未知。代理外层连接可以是 IPv4 或 IPv6，仍绑定指定真实出口；回环代理与 DNS stub 保留回环路径。

SOCKS5/SS 使用原生 UDP，HTTP/HTTPS 没有 UDP 实现时按显式回退规则处理；代理认证或连接失败不会改为直连。IPv6 TCP/UDP 业务字节与 IPv4 使用相同观察口径，IPv6 DNS 事件独立记录。进程归属暂未覆盖 IPv6 时会显示未知。

## 网关与验收边界

原 IPv4 网关能力保持独立。LAN 客户端使用 IPv6 时，还需要管理员配置 LAN IPv6 地址、路由、转发和适用的防火墙规则，使客户端到 Fake-IP 子网的流量进入 KONE 主机，并使响应能回到客户端；KONE 不自动发布 RA/DHCPv6、不自动建立 NAT66，也不修改 LAN 接口配置。真实出口和上游代理必须支持所需流量。

测试包含地址池/AAAA 双家族映射、规则和能力检查、活动映射保留、UDP6、IPv6 DNS UDP/TCP、地址与路由故障回滚；Linux CI 在临时网络命名空间运行实际 TUN 的 AAAA → TCP/UDP → 直连/加密代理链路和占端口/路由冲突验收。实际执行结果以对应 PR 的 CI 为准，编译不等于通过驱动或特权网络验收。

历史 [Wintun 原生验收](https://github.com/xjdrew/kone/actions/runs/41230440840/job/124623356690)在临时管理员 runner 对当时的 system/mixed 分别执行 Fake-AAAA → HTTP/SOCKS5/SS TCP、SOCKS5/SS UDP、真实 AAAA 的 IPv6 TCP/UDP 直连、IPv6 DNS UDP/TCP，以及监听端口占用和自有连接路由冲突后的退出清理。当前 CI 将同一组用例扩展到 system/gvisor/mixed，需按对应 SHA 的三栈结果判断，不能把历史两栈通过记为 gvisor 已通过。用例仅创建独有 ULA 接管范围和回环测试端点；`auto-route6` 的两条全局路由保留命令/冲突回归，不在联网 runner 改写外网路径。这些结果不能代替实际 ISP/VPN IPv6 出口、LAN IPv6 路由和真实终端部署验收。

这项能力接管受支持的 IPv6 TCP/UDP 流。ICMP、扩展首部和分片依赖所选协议栈的支持范围；没有通过对应场景验收时，不把一次 ping 或 TCP 成功当作全部 IPv6 协议已可用。客户端绕过 KONE 使用加密 DNS 时，也不能保证按域名选择性接管。
