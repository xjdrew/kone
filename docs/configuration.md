# TOML 配置与迁移

Go 版本统一为 1.27.3。原 INI 文件不再加载，默认配置文件名为 `config.toml`。
请从 [完整示例](../configs/kone.example.toml) 开始迁移；`kone -check -config config.toml` 只校验，不修改系统网络。

## INI 到 TOML

配置由 `[general]`、`[core]`、可选的 `[dns]`、`[[outbounds]]` 与 `[[rules]]` 组成。
旧 `[proxies]` 字典改为代理出站数组，只使用自定义 `name` 和 `url` 声明代理，不再配置出站 `type`；代理协议由 URL 的 scheme 决定。规则使用 `outbound` 引用代理名，或直接引用内置的 `direct`、`reject`。
`direct` 和 `reject` 始终可用，不需要配置条目；只使用它们时，整个 `[[outbounds]]` 数组都可以省略。已有 `type = "direct" / "reject"` 条目应删除，并将规则中的别名替换为 `direct` / `reject`。
旧 `core.dns-*` 参数移动到 `[dns]` 并去掉 `dns-` 前缀；`dns-server` 改为 `dns.servers`。
旧 INI、`[proxies]`、规则的 `proxy` 字段和 `core.dns-*` 都会被严格校验拒绝，不会静默忽略。

```toml
[general]
manager-addr = "127.0.0.1:9200"
log-level = "info"
log-format = "json"

[core]
network = "10.192.0.1/16"
stack = "system"

[[outbounds]]
name = "office"
url = "http://127.0.0.1:8080"

[[rules]]
type = "DOMAIN-SUFFIX"
pattern = "example.com"
outbound = "office"

[[rules]]
type = "DOMAIN-SUFFIX"
pattern = "blocked.example"
outbound = "reject"

[[rules]]
type = "FINAL"
outbound = "direct"
```

## 可选的 DNS 配置

`[dns]` 整段可以省略。未设置 `servers` 或设置为 `[]` 时，启动前读取系统当前 DNS 服务器用于真实解析，不硬编码公共 DNS 回退。读取失败、没有可用服务器或上游指向虚拟网段时，启动返回错误。`-check` 校验静态配置，不探测运行环境中的 DNS 可用性。

```toml
[dns]
servers = ["1.1.1.1", "8.8.8.8:53", "[2001:4860:4860::8888]:53"]
listen-port = 53
ttl = 600
packet-size = 4096
read-timeout = 5
write-timeout = 5
history-limit = 512
history-retention = 3600
cache-limit = 1024

[[dns.rules]]
suffix = "corp.example"
servers = ["192.168.1.53"]

[[dns.rules]]
suffix = "168.192.in-addr.arpa"
servers = ["192.168.1.53"]
```

上面的参数均为可选项，含义及全部默认值见完整示例。`listen-port` 是 TUN 地址上的 KONE DNS 服务端口，同时监听 UDP/TCP；`servers` 是实际解析使用的上游，两者不同。上游 UDP 响应截断时，使用同一上游和出口重试 TCP。支持 IPv6 上游 DNS 和 AAAA 查询；Linux 可另外显式启用 IPv6 接管，默认只接管 IPv4。
自动上游仅在创建 engine 时发现一次，生效服务器保存在运行实例中，配置仍保留“自动”状态。规则热更新不会重新读取已经被 KONE 改写的 Windows 网卡 DNS；改变 DNS 设置或系统网络需要重启。

`[[dns.rules]]` 使用最长域名后缀匹配，自身和子域名均匹配，`suffix = "."` 为显式兜底。匹配后只查询该条规则中的服务器；超时或 NXDOMAIN 不会触发默认/公共 DNS 回退。反向解析域名也使用相同机制。同组上游并发解析，等待其他上游结果后才接受否定响应，避免较快的 NXDOMAIN 掩盖另一台服务器的有效回答。每组最多 16 台上游，最多 64 条分流规则。

默认解析器自动发现会同时读取可见的系统上下文：Windows NRPT、网卡 DNS 后缀/搜索域和路由；Linux systemd-resolved 的 per-link DNS/路由域；macOS 的 scoped resolver。手工 `dns.rules` 优先于自动 scope，手工规则内部仍按最长后缀匹配。规则可设置 `interface = "VPN"` 指定专用出口；省略时使用核心出口。查询事件记录使用的解析接口、自动发现来源与警示，搜索域仅作为上下文展示，仍由客户端完成短名称展开。

自动发现不是完整复制所有 VPN、按应用或安全 DNS 策略。已知 scope 缺失服务器、接口不可用、接口归属歧义，或需要尚不能复制的 NRPT 安全/IPsec/DNSSEC、加密或多播解析行为时，该 scope 失败，不向公共默认上游回退；请按实际环境补充手工规则。无法可靠读取上下文时明确警示。系统 DNS 引导关闭且原 systemd-resolved stub 可用时，可继续委托它维护原作用域与加密策略；开启系统 DNS 引导时必须改用验证后的真实上游，防止 stub 回到 KONE 形成环路。自动读取使用四秒总预算与 1 MiB 输出上限，不执行网络配置命令。具体发现边界见 [DNS 系统上下文](dns-context.md)。

查询历史独立记录客户端 UDP/TCP 请求和内部控制解析，包含名称/类型、状态/错误、实际上游和传输、缓存、真实/虚拟地址、延迟与版本；DNS 查询不代表建立了业务连接。默认最多 512 条、保留一小时，`history-limit = 0` 关闭记录；上限 10000 条和 86400 秒。可在管理页清空历史。响应缓存默认最多 1024 条，报文编码大小累计最多 8 MiB，遵守正响应及 SOA 否定响应 TTL，最长一小时；`cache-limit = 0` 关闭。带 EDNS 扩展等特殊语义的请求绕过该缓存。清空响应缓存不会回收活动连接使用的 Fake-IP 映射。

## 校验规则

- 未知配置键、错误类型、重复 TOML 键都会报错；解析错误包含位置且不会回显配置中的密码。
- `network` 必须是 IPv4 单播主机地址加 `/8` 至 `/30` 前缀，不能使用网段地址或广播地址。
- DNS 监听端口非零；管理监听地址必须包含合法端口。协议栈内部端口与会话映射由 sing-tun 管理。
- DNS 上游必须是 IP 地址，可带有效端口，不能指向虚拟网段。DNS TTL 必须在 1..4294967295 秒内，报文大小至少 512 字节，超时在 1..300 秒内。
- 支持 `http://host:port`、`https://host:port`、`socks5://host:port`、`ss://method:password@host:port`，端口必须显式提供；前三种 URL 不允许路径、查询或 fragment。SS 允许 SIP002 的可选末尾 `/` 和标签，支持 Base64URL 编码的用户信息；不支持插件查询参数。IPv6 主机使用方括号。
- 代理出站使用 `name`、`url` 和可选的 `udp-fallback`；旧的出站 `type` 字段应删除，否则会报未知配置键。名称必须非空、唯一，不含控制字符或首尾空白，URL 必须合法；内置出站不能通过配置声明或覆盖。
- 规则引用已配置的代理名或内置小写 `direct` / `reject`，引用区分大小写。`direct`、`reject` 及其大小写变体均不能用作代理名称。没有规则匹配时使用内置 `direct`。
- 支持 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`GEOIP`、`FINAL`；`FINAL` 必须最后出现且没有 `pattern`。`IP-CIDR6` 需要配置 `core.ipv6-network`，当前只允许 Linux 启动 IPv6 接管。
- `DOMAIN-SUFFIX = example.com` 匹配自身和子域名，不匹配 `1example.com`。`DIRECT` CIDR 例外会保留规则优先级。

`http_proxy`、`https_proxy`、`socks_proxy` 环境变量会定义或覆盖同名的 proxy 出站。未设置小写变量时读取大写形式；Windows 环境变量本身不区分大小写。文件中的重复定义或无效 URL 不会被环境变量掩盖；内置出站不受这些环境变量影响。

## 日志与管理接口

`log-level` 支持 `debug`、`info`、`warn`、`error`；`log-format` 支持 `text` 和 `json`。
`-debug` 优先于配置。日志包含独立的 `proxy`、`destination`、`error` 等字段，字节数保留数字类型。

管理接口默认仅监听 `127.0.0.1:9200`；空字符串关闭。配置页面展示脱敏后的生效配置。
修改配置文件后用 `POST /reload/` 更新规则；GET 不触发修改。

热更新会重建代理端点的域名绕过，重新计算已有 DNS 映射的域名、CNAME、IP 策略，清除直连域名缓存，并保留虚拟 IP。
新的 TCP 连接与 UDP 会话采用新策略；已建立的连接和 UDP 会话保留创建时的快照，包括 UDP 回退设置。
代理出站定义与规则作为同一版本快照原子更新；新的连接使用新定义，已建立连接保留原出站。域名/最终规则可在代理名、`direct` 和 `reject` 之间热更新；若更新改变 CIDR 捕获，则要求重启。内置出站始终存在，不会作为配置条目写入快照的配置或管理页 TOML。
端口、TUN、DNS、日志、管理地址及 CIDR 路由变化要求重启，失败更新保留原配置和版本。

## TUN backend and stack

设备与透明流量处理改用 SagerNet/sing-tun，Windows 使用内嵌 Wintun，Linux 使用 TUN，macOS 使用 utun。`core.tun` 留空时自动分配名称，指定时必须尚不存在；macOS 名称必须为 utunN。

- 在 `[core]` 下设置 `stack = "system"` 或 `stack = "mixed"`；示例显式选择默认的 `system`，使用系统 TCP 和 sing-tun UDP，适用于普通构建。`mixed` 使用系统 TCP 和 gVisor UDP，必须用 `go build -tags with_gvisor` 构建。缺少构建能力时会返回明确错误，不静默切换协议栈；修改协议栈需要重启。
- `core.auto-route = false` 保留原来的 Fake-IP 子网和显式 CIDR 接管；`true` 添加 `0.0.0.0/1` 与 `128.0.0.0/1` 路由，实现 IPv4 全局接管，同时保留原默认路由供退出后使用。已有更具体路由仍按系统路由优先级处理。
- 全局接管必须指定 `core.outbound-interface`，代理连接、直连连接和上游 DNS 查询使用这个真实接口。回环地址上的本地代理和 DNS stub 使用原回环路径。出口不能与 TUN 同名；IP-CIDR 默认捕获路由同样要求指定出口。接口切换需要修改配置并重启。
- `core.network` 的接口地址之后一个地址供协议栈使用，两者均不会分配为 Fake-IP。该地址必须保留至少一个后继主机地址。
- 旧 `tcp-listen-port`、`udp-listen-port`、`tcp-nat-port-start/end`、`udp-nat-port-start/end` 已移除，旧配置必须删除这些键，严格校验会明确报错。内部监听和会话映射由 sing-tun 分配。

IPv6 默认关闭，Linux 可通过 `core.ipv6-network` 显式启用；`core.auto-route6` 独立控制 IPv6 全局路由，需要指定真实出口。Windows/macOS 在 IPv6 后端未完成平台验收前明确拒绝启用。采用 `mixed` 不改变出站协议能力。IPv6 细节见 [IPv6 配置与边界](ipv6.md)，LAN 网关部署参见 [Raspberry Pi 指南](guides/how-to-use-with-raspberry-pi.md)。

## UDP 策略与显式回退

`direct` 规则直连 UDP，`reject` 规则始终拒绝且不回退。SOCKS5 使用原生 UDP ASSOCIATE；Shadowsocks 使用原生加密 UDP。两者保留域名供代理端解析，不先向本机解析器查询业务目标。代理外层 TCP/UDP 均通过指定真实出口；SOCKS5 的 TCP 控制连接关闭时，同时关闭 UDP 关联。不支持 SOCKS5 UDP 分片，收到非零 FRAG 时明确拒绝。

HTTP/HTTPS CONNECT 只支持 TCP，选中它们时默认拒绝 UDP，并记录出站名和不支持 UDP 的原因；拒绝不会把 UDP 转换为 TCP。

只有确实允许绕过代理发送 UDP 时，才为该代理显式设置：

```toml
[[outbounds]]
name = "office"
url = "http://127.0.0.1:8080"
udp-fallback = "direct"
```

对没有 UDP 实现的协议，省略 `udp-fallback` 或设为空字符串表示默认拒绝；`"reject"` 表示明确拒绝。只允许内置 `direct`、`reject`，不接受未知名称、代理名称、自引用或回退链。SOCKS5/SS 优先使用原生 UDP，其连接、认证或转发失败不会执行直连回退；回退不是代理故障时的自动切换。回退不改变 TCP 和其他规则。环境变量覆盖代理 URL 时保留文件声明的回退策略；纯环境变量代理没有隐式回退。

检查能力先于目标真实 DNS 解析和 UDP 拨号。热更新影响新会话，已有会话保留原快照。TCP/UDP 业务字节与 DNS 查询事件分开统计，不能把 DNS 记录数或 UDP 会话数当作字节流量。

## Shadowsocks 出站

使用 `ss://method:password@host:port` 或 SIP002 Base64URL 用户信息声明，密码中的 URL 特殊字符必须进行百分号编码。支持 AEAD2017 的 `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`，TCP 和原生 UDP 共用服务端端口；不启用未加密模式、旧流密码、AEAD-2022、插件、复用或 UDP-over-TCP。

```toml
[[outbounds]]
name = "encrypted"
url = "ss://aes-128-gcm:replace-with-your-password@proxy.example:8388"
```

实现使用与官方 sing-box 相同版本的 [sing-shadowsocks2](https://github.com/SagerNet/sing-shadowsocks2)，遵守其 GPL-3.0-or-later 许可；协议范围依据 [Shadowsocks AEAD 文档](https://shadowsocks.org/doc/aead.html) 与 [SIP002](https://shadowsocks.org/doc/sip002.html)。互操作测试使用独立的本地 SIP004/SIP007 测试对端验证三种方法的 TCP/UDP 加密链路及篡改拒绝；这不替代各实际服务端版本的部署验收。

## API 与目录迁移

`github.com/xjdrew/kone` 改为 `github.com/xjdrew/kone/pkg/kone`；其他原子包也移动到 `pkg/`。
`KoneConfig.Validate()` 可独立校验；`FromConfig` 在任何设备创建前再次校验。
`FromConfig` 只构造对象，不修改系统网络。用 `Run(ctx)` 启动并管理资源，`Close()` 可并发、重复调用并等待清理结束。
`Snapshot()` 返回版本与独立配置副本，`DNSSnapshot()` 返回同一规则版本下的域名状态。
网络操作由 `Network` 接口管理，并保留每项变更的逆操作；参见 [运行可靠性](runtime.md)。
