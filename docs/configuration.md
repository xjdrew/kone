# TOML 配置与迁移

Go 版本统一为 1.27.3。原 INI 文件不再加载，默认配置文件名为 `config.toml`。
请从 [完整示例](../configs/kone.example.toml) 开始迁移；`kone -check -config config.toml` 只校验，不修改系统网络。

## INI 到 TOML

旧配置段 `[General]`、`[Core]`、`[Proxy]` 分别改为 `[general]`、`[core]`、`[proxies]`。
保留 `tcp-listen-port` 等原选项的连字符命名；字符串必须加引号，DNS 列表使用 TOML 数组。
原 `[Rule]` 中的逗号规则改为有序的 `[[rules]]` 表：

```toml
[general]
manager-addr = "127.0.0.1:9200"
log-level = "info"
log-format = "json"

[core]
network = "10.192.0.1/16"
dns-server = ["1.1.1.1", "8.8.8.8:53", "[2001:4860:4860::8888]:53"]

[proxies]
Office = "http://127.0.0.1:8080"

[[rules]]
type = "DOMAIN-SUFFIX"
pattern = "example.com"
proxy = "Office"

[[rules]]
type = "FINAL"
proxy = "DIRECT"
```

未配置 `dns-server` 时读取系统 DNS。读取失败或不存在可用服务器时返回错误，需显式指定上游。
支持 IPv6 上游 DNS 地址，但这不代表支持 IPv6 流量接管。

## 校验规则

- 未知配置键、错误类型、重复 TOML 键都会报错；解析错误包含位置且不会回显配置中的密码。
- `network` 必须是 IPv4 单播主机地址加 `/8` 至 `/30` 前缀，不能使用网段地址或广播地址。
- 监听端口非零；NAT 范围为 `[start, end)`，必须有效，且不能包含对应 relay 的监听端口。
- DNS 上游必须是 IP 地址，可带有效端口，不能指向虚拟网段。DNS TTL 必须在 1..4294967295 秒内，报文大小至少 512 字节，超时在 1..300 秒内。
- 支持 `http://host:port`、`https://host:port`、`socks5://host:port`，端口必须显式提供；URL 不允许路径、查询或 fragment。IPv6 主机使用方括号。
- 规则必须引用已定义的代理或 `DIRECT` / `REJECT`。代理名不能占用这两个保留名称。
- 支持 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`GEOIP`、`FINAL`；`FINAL` 必须最后出现且没有 `pattern`。`IP-CIDR6` 当前会报不支持。
- `DOMAIN-SUFFIX = example.com` 匹配自身和子域名，不匹配 `1example.com`。`DIRECT` CIDR 例外会保留规则优先级。

`http_proxy`、`https_proxy`、`socks_proxy` 环境变量会定义或覆盖同名代理。未设置小写变量时读取大写形式；Windows 环境变量本身不区分大小写。未写 `[proxies]` 段也可使用这些变量。

## 日志与管理接口

`log-level` 支持 `debug`、`info`、`warn`、`error`；`log-format` 支持 `text` 和 `json`。
`-debug` 优先于配置。日志包含独立的 `proxy`、`destination`、`error` 等字段，字节数保留数字类型。

管理接口默认仅监听 `127.0.0.1:9200`；空字符串关闭。配置页面展示脱敏后的生效配置。
修改配置文件后用 `POST /reload/` 更新规则；GET 不触发修改。

热更新会重建代理端点的域名绕过，重新计算已有 DNS 映射的域名、CNAME、IP 策略，清除直连域名缓存，并保留虚拟 IP。
新的 TCP 连接采用新策略；已建立连接和已有 UDP tunnel 按当前会话继续工作。
端口、TUN、DNS、代理定义、日志、管理地址及 CIDR 路由变化要求重启，失败更新保留原配置。

## API 与目录迁移

`github.com/xjdrew/kone` 改为 `github.com/xjdrew/kone/pkg/kone`；其他原子包也移动到 `pkg/`。
`KoneConfig.Validate()` 可独立校验；`FromConfig` 在任何设备创建前再次校验。
`NewProxies` 现在只接收代理定义，代理绕过由 engine 构建；`NewTunDriver` 接收接口名，路由操作返回真实错误。
