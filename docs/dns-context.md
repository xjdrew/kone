# DNS 系统上下文与私有解析

不配置 `[dns].servers` 时，KONE 在创建引擎、接管系统网络之前读取当前解析器及可见作用域。这个快照服务于正常解析和代理服务器主机名解析，不使用 Fake-IP 再解析代理服务器，也不会因专用解析器失败去查询公共 DNS。配置固定到本次引擎实例，换网或修改 DNS 后需要重新创建实例。

| 平台 | 只读来源 | 可以表达的部分 |
| --- | --- | --- |
| Windows | `Get-DnsClientNrptPolicy -Effective`、DNS 客户端/服务器/搜索域、接口路由 | NRPT 的精确名称和后缀；网卡专用后缀、服务器与可确定的出口 |
| Linux | `resolvectl domain/dns/dnsovertls/default-route` | systemd-resolved 的 per-link 路由域、搜索域、默认上游与传输边界 |
| macOS | `scutil --dns` | 默认与 scoped resolver 的域名、搜索域、接口、地址和端口 |

Windows NRPT 有超出普通 UDP/TCP DNS 的安全、IPsec、DirectAccess 和查询策略；这些不能仅靠复制服务器 IP 保证语义。Linux 的加密 DNS 及 macOS 的多播/特殊 resolver 也不直接改成普通 UDP。已知不能安全表达的 scope 保持不可用并显示原因，匹配请求失败；它不会改走默认公共 DNS。来源文档：[Microsoft NRPT](https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientnrptpolicy)、[systemd resolvectl](https://www.freedesktop.org/software/systemd/man/261/resolvectl.html)、[Apple scutil](https://github.com/apple-oss-distributions/configd/blob/main/scutil.tproj/scutil.8)。

普通模式保留既有 systemd-resolved 本机 stub 时，可以继续由系统服务处理它原有的 VPN 路由与安全策略。启用 KONE 的系统 DNS 引导后，stub 可能指回 KONE，因此必须使用发现的真实上游；无法确定真实上游时阻止启用，不猜测一个公共服务器作为替代。

所有发现命令只读取本机状态，总预算四秒、标准输出最多 1 MiB，错误输出不写入日志。最多接收 64 条自动/手工规则及每条 16 个服务器；超出可表达范围时拒绝不确定的自动解析并要求显式配置。原始操作系统快照不写入 TOML，也不会被伪装成用户配置。

## 手工覆盖

```toml
[[dns.rules]]
suffix = "corp.example"
servers = ["10.0.0.53"]
interface = "VPN"
```

使用实际网卡名称，留空沿用核心出口。手工规则优先于自动 scope；手工规则之间最长后缀优先。域名后缀使用 ASCII，国际化域名应填写 IDNA 的 punycode。匹配规则后只使用该组服务器，连不上、返回否定回答或接口失效都不会向公共默认上游回退。反向解析名称也可配置独立后缀。

搜索域作为观察到的系统上下文展示，不由 KONE任意添加到查询名称；客户端发送展开后的完整名称。自动发现不涵盖全部按应用、VPN 厂商插件、DNS 代理或加密 DNS 配置。需要这些语义的环境应核对实际系统策略、状态警示和查询记录，再明确配置；不要把发现成功当作所有企业网络行为都已经复制。

DNS 查询和失败是解析事件，不证明业务连接已经进入 TUN。解析接口、查询传输、实际使用的上游和缓存分别记录；本地 stub 的实际网络接口标为 loopback，不把其内部可能使用的公网解析器伪装成 KONE 直接访问的上游。

真实 DNS 响应和 Fake-IP 映射分别过期。IP/CNAME 规则依赖的真实响应到期后，新查询或新连接重新解析和判定；访问虚拟地址不会续期真实 DNS 数据。刷新保留同一域名的 Fake-IP 和活动会话引用，已建立连接继续使用原先选定的目标；刷新失败不会改用已过期地址或其他解析器。
