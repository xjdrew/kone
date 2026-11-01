# IPv6 接管

IPv6 默认关闭，不改变现有 IPv4 客户端或 Raspberry Pi 网关配置。Linux、Windows、macOS 均可显式启用 IPv6 TUN、AAAA Fake-IP、IPv6 TCP/UDP 转发与 IPv6 规则；同一程序包含的 system/gvisor/mixed 使用相同出站策略，`core.stack` 默认 system。配置修改后需要暂停并重新启用接管；平台的真实流量与恢复验收以对应提交的 CI 为准。

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

macOS 同样只配置本次新建的独占 utun：添加 IPv4 和 ULA IPv6 地址，保留自动生成的链路本地地址。NODAD 仅用于这个点到点虚拟地址，不修改物理接口或全机 IPv6 策略。IPv6 路由通过 PF_ROUTE 内核确认应答建立所有权，清理重新核对前缀、网关与接口索引；已有外部路由、接口复用或外部替换不会被删除。暂停/失败时逆序移除本次地址和路由，再关闭设备；网络助手退出仍由统一生命周期负责。

```toml
[[rules]]
type = "IP-CIDR6"
pattern = "2001:db8:1234::/48"
outbound = "reject"
```

示例 CIDR 是文档地址，应替换为实际目标。规则顺序、协议/端口条件、`direct`/`reject` 和代理名称语义与 IPv4 相同；内置和 JSON GeoIP 只有 IPv4 范围，IPv6 国家规则需导入包含 IPv6 记录的 [MMDB 数据源](geoip.md)，未知地址不猜测归属。修改 IPv6 地址、全局路由开关或 CIDR 捕获范围需要重启。

## DNS 与核心链路

未启用 IPv6 接管时，需要走代理或按高级条件接入的域名不会返回真实 AAAA，而是返回 `NOERROR` 空结果，使客户端使用 IPv4 Fake-IP 后执行对应规则；明确拒绝仍返回 `REFUSED`。直连域名和受保护代理端点保持真实 AAAA 解析。该策略只作用于经过 KONE 的客户端 DNS 查询，不关闭主机 IPv6，也不清除客户端已有缓存；显式启用 IPv6 后会使用 Fake-AAAA 完成双栈接管。

客户端 HTTPS/SVCB 记录可能包含真实 IPv4/IPv6 地址提示和替代端点。需要接管的域名对此返回空结果，使客户端继续使用受控的 A/AAAA 路径；拒绝规则返回 `REFUSED`。直连与受保护代理端点保持原记录，内部解析不受过滤影响。

启用后，同一个域名的 A 和 AAAA 使用独立地址映射，均保留稳定 Fake-IP 和活动会话 pin。AAAA 请求通过 IPv4 或 IPv6 DNS 传输都能得到相同策略结果。Linux/Windows 在 IPv4/IPv6 TUN 地址监听 DNS UDP/TCP；macOS 因点到点设备语义，使用独立 IPv4 监听与 `::1` IPv6 入口，本机通过 `127.0.0.1` / `::1` 查询。两族使用同一端口，私有 DNS 后缀仍独占其原解析器；指向本机同端口的上游会明确拒绝，避免自环。上游 DNS 可走任意可用地址家族，不等于业务目标被转换为该家族。

客户端连接 AAAA Fake-IP 后，sing-tun 把 IPv6 TCP/UDP 会话交给 KONE。KONE 还原域名、匹配规则并检查出站能力；直连只使用真实 AAAA 地址，缺少真实 IPv6 地址时失败，不拿 A 地址伪装成 IPv6 目标。代理保留域名交由远端解析，实际目标地址不可得时记录未知。代理外层连接可以是 IPv4 或 IPv6，仍绑定指定真实出口；回环代理与 DNS stub 保留回环路径。

SOCKS5/SS 使用原生 UDP，HTTP/HTTPS 没有 UDP 实现时按显式回退规则处理；代理认证或连接失败不会改为直连。IPv6 TCP/UDP 业务字节与 IPv4 使用相同观察口径，IPv6 DNS 事件独立记录。进程归属暂未覆盖 IPv6 时会显示未知。

## 网关与验收边界

原 IPv4 网关能力保持独立。LAN 客户端使用 IPv6 时，还需要管理员配置 LAN IPv6 地址、路由、转发和适用的防火墙规则，使客户端到 Fake-IP 子网的流量进入 KONE 主机，并使响应能回到客户端；KONE 不自动发布 RA/DHCPv6、不自动建立 NAT66，也不修改 LAN 接口配置。真实出口和上游代理必须支持所需流量。

测试包含地址池/AAAA 双家族映射、规则和能力检查、活动映射保留、UDP6、IPv6 DNS UDP/TCP、地址与路由故障回滚；Linux CI 在临时网络命名空间运行实际 TUN 的 AAAA → TCP/UDP → 直连/加密代理链路和占端口/路由冲突验收。实际执行结果以对应 PR 的 CI 为准，编译不等于通过驱动或特权网络验收。

历史 [Wintun 原生验收](https://github.com/xjdrew/kone/actions/runs/41230440840/job/124623356690)在临时管理员 runner 对当时的 system/mixed 分别执行 Fake-AAAA → HTTP/SOCKS5/SS TCP、SOCKS5/SS UDP、真实 AAAA 的 IPv6 TCP/UDP 直连、IPv6 DNS UDP/TCP，以及监听端口占用和自有连接路由冲突后的退出清理。当前 CI 将同一组用例扩展到 system/gvisor/mixed，需按对应 SHA 的三栈结果判断，不能把历史两栈通过记为 gvisor 已通过。用例仅创建独有 ULA 接管范围和回环测试端点；`auto-route6` 的两条全局路由保留命令/冲突回归，不在联网 runner 改写外网路径。这些结果不能代替实际 ISP/VPN IPv6 出口、LAN IPv6 路由和真实终端部署验收。

macOS 的 `TestSystemDarwinIPv6` 在临时管理员 runner 对每栈检查六个必过叶子：代理 TCP/UDP、真实 AAAA 直连与私有 DNS、UDP6/TCP6 端口占用回滚、外部 IPv6 路由冲突保护，以及自有路由和监听恢复。代理用例包括 HTTP、SOCKS5 和 Shadowsocks，并核对 Fake-AAAA 不向本机上游泄漏代理业务域名。前后检查原 DNS、IPv4/IPv6 默认路由；不会在联网 runner 开启 `auto-route6` 或改写物理接口。实际 ISP/VPN、LAN IPv6 和用户设备的性能仍需部署验收。

这项能力接管受支持的 IPv6 TCP/UDP 流。ICMP、扩展首部和分片依赖所选协议栈的支持范围；没有通过对应场景验收时，不把一次 ping 或 TCP 成功当作全部 IPv6 协议已可用。客户端绕过 KONE 使用加密 DNS 时，也不能保证按域名选择性接管。
