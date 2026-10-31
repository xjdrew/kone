# TOML 配置与迁移

Go 版本统一为 1.27.3。原 INI 文件不再加载，默认配置文件名为 `config.toml`。
请从 [完整示例](../configs/kone.example.toml) 开始迁移；`kone -check -config config.toml` 只校验，不修改系统网络。

## INI 到 TOML

配置由 `[general]`、`[core]`、可选的 `[dns]`、`[[outbounds]]` 与 `[[rules]]` 组成。
旧 `[proxies]` 字典改为代理出站数组，使用自定义名字、`type = "proxy"` 和 URL 声明代理。规则使用 `outbound` 引用代理名，或直接引用内置的 `direct`、`reject`。
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

[[outbounds]]
name = "office"
type = "proxy"
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
```

上面的参数均为可选项，含义及全部默认值见完整示例。`listen-port` 是 TUN 地址上的 KONE DNS 服务端口；`servers` 是实际解析使用的上游，两者不同。支持 IPv6 上游 DNS 地址，但尚不接管 IPv6 流量。
自动上游仅在创建 engine 时发现一次，生效服务器保存在运行实例中，配置仍保留“自动”状态。规则热更新不会重新读取已经被 KONE 改写的 Windows 网卡 DNS；改变 DNS 设置或系统网络需要重启。

## 校验规则

- 未知配置键、错误类型、重复 TOML 键都会报错；解析错误包含位置且不会回显配置中的密码。
- `network` 必须是 IPv4 单播主机地址加 `/8` 至 `/30` 前缀，不能使用网段地址或广播地址。
- 监听端口非零；NAT 范围为 `[start, end)`，必须有效，且不能包含对应 relay 的监听端口。
- DNS 上游必须是 IP 地址，可带有效端口，不能指向虚拟网段。DNS TTL 必须在 1..4294967295 秒内，报文大小至少 512 字节，超时在 1..300 秒内。
- 支持 `http://host:port`、`https://host:port`、`socks5://host:port`，端口必须显式提供；URL 不允许路径、查询或 fragment。IPv6 主机使用方括号。
- 代理出站名必须非空、唯一，不含控制字符或首尾空白。配置类型只允许 `proxy`，必须有合法 URL；内置出站不能通过配置声明或覆盖。
- 规则引用已配置的代理名或内置小写 `direct` / `reject`，引用区分大小写。`direct`、`reject` 及其大小写变体均不能用作代理名称。没有规则匹配时使用内置 `direct`。
- 支持 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`GEOIP`、`FINAL`；`FINAL` 必须最后出现且没有 `pattern`。`IP-CIDR6` 当前会报不支持。
- `DOMAIN-SUFFIX = example.com` 匹配自身和子域名，不匹配 `1example.com`。`DIRECT` CIDR 例外会保留规则优先级。

`http_proxy`、`https_proxy`、`socks_proxy` 环境变量会定义或覆盖同名的 proxy 出站。未设置小写变量时读取大写形式；Windows 环境变量本身不区分大小写。文件中的重复定义或无效 URL 不会被环境变量掩盖；内置出站不受这些环境变量影响。

## 日志与管理接口

`log-level` 支持 `debug`、`info`、`warn`、`error`；`log-format` 支持 `text` 和 `json`。
`-debug` 优先于配置。日志包含独立的 `proxy`、`destination`、`error` 等字段，字节数保留数字类型。

管理接口默认仅监听 `127.0.0.1:9200`；空字符串关闭。配置页面展示脱敏后的生效配置。
修改配置文件后用 `POST /reload/` 更新规则；GET 不触发修改。

热更新会重建代理端点的域名绕过，重新计算已有 DNS 映射的域名、CNAME、IP 策略，清除直连域名缓存，并保留虚拟 IP。
新的 TCP 连接采用新策略；已建立连接和已有 UDP tunnel 按当前会话继续工作。
代理出站定义与规则作为同一版本快照原子更新；新的连接使用新定义，已建立连接保留原出站。域名/最终规则可在代理名、`direct` 和 `reject` 之间热更新；若更新改变 CIDR 捕获，则要求重启。内置出站始终存在，不会作为配置条目写入快照的配置或管理页 TOML。
端口、TUN、DNS、日志、管理地址及 CIDR 路由变化要求重启，失败更新保留原配置和版本。

## TUN backend and stack

设备与透明流量处理改用 SagerNet/sing-tun，Windows 使用内嵌 Wintun，Linux 使用 TUN，macOS 使用 utun。`core.tun` 留空时自动分配名称，指定时必须尚不存在；macOS 名称必须为 utunN。

- `core.stack = "system"` 为默认值，适用于普通构建；`"mixed"` 使用系统 TCP 和 gVisor UDP，必须用 `go build -tags with_gvisor` 构建。缺少构建能力时会返回明确错误，不静默切换协议栈。
- `core.auto-route = false` 保留原来的 Fake-IP 子网和显式 CIDR 接管；`true` 添加 `0.0.0.0/1` 与 `128.0.0.0/1` 路由，实现 IPv4 全局接管，同时保留原默认路由供退出后使用。已有更具体路由仍按系统路由优先级处理。
- 全局接管必须指定 `core.outbound-interface`，代理连接、直连连接和上游 DNS 查询使用这个真实接口。回环地址上的本地代理和 DNS stub 使用原回环路径。出口不能与 TUN 同名；IP-CIDR 默认捕获路由同样要求指定出口。接口切换需要修改配置并重启。
- `core.network` 的接口地址之后一个地址供协议栈使用，两者均不会分配为 Fake-IP。该地址必须保留至少一个后继主机地址。
- 原 `tcp/udp-listen-port` 与 NAT 端口范围仍接受并校验，方便旧配置迁移，但生产数据面的监听和会话现在由 sing-tun 分配。

本轮保留 IPv4、现有规则与 UDP 直连行为；IPv6 拦截和 SOCKS5 UDP 出站仍未启用。采用 `mixed` 也不会改变出站协议能力。LAN 网关部署参见 [Raspberry Pi 指南](guides/how-to-use-with-raspberry-pi.md)。

## API 与目录迁移

`github.com/xjdrew/kone` 改为 `github.com/xjdrew/kone/pkg/kone`；其他原子包也移动到 `pkg/`。
`KoneConfig.Validate()` 可独立校验；`FromConfig` 在任何设备创建前再次校验。
`FromConfig` 只构造对象，不修改系统网络。用 `Run(ctx)` 启动并管理资源，`Close()` 可并发、重复调用并等待清理结束。
`Snapshot()` 返回版本与独立配置副本，`DNSSnapshot()` 返回同一规则版本下的域名状态。
网络操作由 `Network` 接口管理，并保留每项变更的逆操作；参见 [运行可靠性](runtime.md)。
