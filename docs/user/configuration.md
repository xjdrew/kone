# 配置指南

面向维护规则、DNS、IPv6 和 GeoIP 的用户。普通操作优先使用管理界面；文件模式与迁移以 [带注释的 TOML 示例](../../configs/kone.example.toml) 为字段依据。

## 1. 配置对象与生效范围

| 对象 | 用途 | 管理模式修改方式 |
| --- | --- | --- |
| `[policy]` | 基础模式及明确接受的 IPv4/UDP 范围 | 切换基础模式先暂停、预览，再保存；保留用户规则 |
| `[general]` | 日志级别与格式 | 暂停后保存，重新启用 |
| `[core]` | TUN 地址、栈、捕获路由与出口 | 暂停后保存，重新启用 |
| `[dns]`、`[[dns.rules]]` | 系统引导、上游、缓存、私有解析 | 暂停后保存，重新启用 |
| `[geoip]` | 文件模式的数据来源 | 修改后重启；管理界面使用独立上传仓库 |
| `[[outbounds]]` | 代理地址、凭据、启停、UDP 回退和后台检查 | 兼容修改自动应用到新连接 |
| `[[rules]]` | 有序匹配与出站选择 | 包括 IPv4/IPv6 CIDR 在内的增删改与排序可在线应用到新连接 |

后端校验结果决定能否在线保存；运行中不允许保存需重启的配置。保存失败保留原配置；保存成功而应用失败时显示版本分歧。CIDR 路由先更新成功，再发布新策略；已有连接所需的旧路由保留到连接结束。路由操作失败时回滚；回滚无法完成则停止代理并报告错误。文件模式没有热更新管理接口，编辑后重启。

TOML 严格拒绝未知字段。管理 profile 不读取工作目录 TOML；导入、导出和恢复默认均是显式操作。密码、代理凭据不会通过普通配置快照回显，编辑时选择保留、替换或清除。

## 2. 最小文件配置

```toml
[core]
network = "10.192.0.1/16"
stack = "system"

[[outbounds]]
name = "office"
url = "socks5://127.0.0.1:1080"

[[rules]]
type = "DOMAIN-SUFFIX"
pattern = "example.com"
outbound = "office"

[[rules]]
type = "FINAL"
outbound = "direct"
```

替换为真实代理地址，先执行 `kone -check -config config.toml`。`direct`、`reject` 是内置出站，无需声明；纯直连可省略整个出站数组。网段必须与现有 LAN/VPN 不冲突。

### 基础策略

新管理配置采用 `direct-first`，启动保持暂停。在“路由策略”切换为 `proxy-first` 时，需要可用的默认出站与真实物理出口；预览显示保留规则、IPv4/IPv6 接管、保护和 UDP 行为。HTTP/HTTPS 无原生 UDP：保留直连回退必须明确同意，或改为拒绝 UDP；后一动作会影响引用同一出站的其他规则。

```toml
[policy]
mode = "proxy-first"
ipv4-only = true # 明确仅接管 IPv4；完整 IPv6 需 core 对应网段和 auto-route6
udp-exception = false # HTTP 的 UDP 直连回退必须显式同意
```

此片段还需要 `core.auto-route = true`、真实 `outbound-interface`、已启用的代理出站和指向该出站的无条件 FINAL。`direct-first` 的 FINAL 为 `direct`。已有文件省略 `[policy]` 时保持旧行为；有条件 FINAL 或无法无损识别的配置显示高级兜底，须先显式编辑原兜底条件。旧程序会严格拒绝不认识的新字段，回退需恢复旧备份。

回环 `127.0.0.0/8`、`::1` 和本机真实单地址保留防回环保护。首次采用全局策略时，在已有用户规则之后、FINAL 之前生成局域网 `direct` 默认规则（私网、直连子网与本地发现范围）；这些是普通规则，可修改、移动或删除，后续保存/重启不会补回。代理远端内网时，在这些默认项之前添加代理规则，或删除对应 direct 项。旧全局 profile 升级时自动补入一次并保留备份，`lan-defaults-initialized` 记录初始化状态。

Fake-IP 先还原业务事实；代理和 DNS 的自身传输通过原生出口绕过 TUN，不把端点 IP 上的其他业务一律直连。直连按启动前的原生路由选择 LAN/VPN 接口；复杂 Linux 策略路由表、特殊 VPN 与物理 IPv6 仍需在部署环境验证，不能把任意 VPN 网段自动当作可信 LAN。换网后暂停并重新预检。

## 3. 出站与规则

| 出站 | TCP | UDP |
| --- | --- | --- |
| `direct` | 直连 | 直连 |
| `reject` | 拒绝 | 拒绝 |
| `http://`、`https://` | CONNECT；后者连接代理时使用 TLS | 无原生能力 |
| `socks5://` | SOCKS5 | UDP ASSOCIATE |
| `ss://` | AEAD2017 | AEAD2017 |

URL 必须带端口。SS 支持 `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`，可用 `ss://方法:密码@主机:端口` 或 SIP002 用户信息编码；不支持旧流密码、AEAD-2022 或插件。

无 UDP 能力时，文件配置省略 `udp-fallback` 默认拒绝；可显式设为 `direct` 或 `reject`。**Web 新建出站当前显式选择 `direct` 回退，已有策略保留。** 回退只用于协议缺少 UDP 实现；认证或连接失败不会回退直连。禁用出站后新连接明确拒绝。

### 出站连通性检查

管理服务默认每分钟自动检查已启用出站；关闭页面、暂停业务代理不停止检查。默认通过所配置的代理协议连接 `example.com:443` 并验证目标 TLS，不下载测速文件、不读取业务内容，也不自动切换路由。

在出站编辑器的“自动连通性检查”中修改目标或关闭。对应字段为 `check-enabled`（默认 true）、`check-target`（默认 `example.com:443`）、`check-tls`（默认 true）。纯 TCP 服务应关闭目标 TLS，例如 Telegram 的 `149.154.167.50:443`。Shadowsocks 仅建立加密传输而没有目标响应时只能报告未知，不能当作目标可达。文件模式没有后台管理检查。

规则池内按顺序匹配；`policy.rule-version = 2` 固定系统保护 → 原始域名/关联 CNAME → IP → FINAL。省略或设置为 1 时保持旧全局顺序。

| `type` | `pattern` |
| --- | --- |
| `DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` | 精确域名 / 自身与子域 / 关键词 |
| `IP-CIDR` / `IP-CIDR6` | IPv4 / IPv6 前缀 |
| `GEOIP` | 两位大写国家代码 |
| `FINAL` | 不填；若存在必须放最后，省略时隐式直连 |

可用 `protocol`、`ports` 限定业务 TCP/UDP 与目标端口；域名解析阶段可能先分配 Fake-IP，实际流量进入后再匹配条件。可选 `id` 保持稳定身份；域名类临时规则可设 RFC3339 `expires-at`，到期只影响新连接，CIDR/GEOIP/FINAL 不支持临时到期。

### 分层版本与 Smart

```toml
[policy]
mode = "direct-first"
rule-version = 2
preferred-proxy-id = "office-id" # 对应 [[outbounds]].id，不是显示名

[policy.smart]
enabled = false

[dns]
persistent-fake-ip = true
# retired-fake-ip-pools = ["10.192.0.0/16"]
```

以上是配置片段，应合并到现有同名段落。Smart 仅提供建议；没有首选代理时仍可观察直连，但不会声称代理可修复。默认代理模式的首选代理必须与 FINAL 出口一致。

新管理配置默认使用分层规则和持久地址归属。旧配置通过“路由策略 → 升级分层规则”预览迁移，先暂停接管：规则 ID 和池内顺序保留，域名规则会先于原本更靠前的 IP 规则；旧内存池换成不重叠的新池，并列入退役池。退役地址仍捕获并拒绝，应用应重新解析。不要手动关闭持久化并复用同一池，也不要仅还原旧归属备份；需要保留完整最新状态或显式使用新池。

## 4. TUN、出口与 IPv6

`core.tun` 留空自动分配，指定时必须是新设备名；macOS 使用 `utunN`。栈可选 `system`、`gvisor`、`mixed`，同一程序均包含，选择栈不改变代理协议能力。

```toml
[core]
network = "10.192.0.1/16"
stack = "system"
auto-route = true
outbound-interface = "eth0" # 改为实际物理出口
ipv6-network = "fd7a:203::1/120" # 可选，使用不冲突的 ULA
# auto-route6 = true
```

IPv4 `auto-route` 与 IPv6 `auto-route6` 独立；全局捕获要求真实出口，不能选自身 TUN。KONE 保留原默认路由和更具体路由，外层代理、直连与上游 DNS 使用真实出口；回环目标保持回环路径。

首次创建或恢复默认管理配置时，支持的平台会检查启用中的非回环接口：存在全局单播 IPv6 地址（含 ULA，排除仅链路本地地址）时，选择不与现有接口网段重叠的 ULA `/120`，优先 `fd7a:203::1/120`。无法检测或无法找到候选网段时留空。已有配置不自动改写；文件模式仍默认关闭。手动启用需 ULA 主机地址与 `/64.. /120` 前缀；留空可关闭。此检测不证明互联网 IPv6 可达，也不自动打开 `auto-route6`，启用前仍需预检真实出口、DNS 与 LAN/VPN 冲突。

未启用时，需代理域名的客户端 AAAA 返回成功空结果；启用后返回 Fake-AAAA。直连域名和受保护代理端点保持真实解析。需代理域名的 HTTPS/SVCB 也返回空结果，防止地址提示绕过规则。以上仅作用于经过 KONE 的查询，不清除客户端缓存或控制旁路 DoH/DoT。

## 5. DNS

在“设置 → 解析”选择模式，再选择上游来源：

| 模式 | 系统 DNS | 监听与部署 |
| --- | --- | --- |
| Host（新管理配置默认） | 启用时接管，暂停时恢复原配置 | 为本机应用服务；先保存原始系统 DNS，再作为上游 |
| Gate | 保持原样 | 在所选局域网地址监听 UDP/TCP 53；管理员配置 DHCP/客户端 DNS，并将 Fake-IP 网段路由到 KONE |

两种模式省略 `servers` 或设为 `[]` 时，都会在启用前读取系统 DNS 并固定到本次运行。获取不到可用默认上游时，界面告警并采用 `8.8.8.8`、`8.8.4.4`、`1.1.1.1`、`1.0.0.1`；这不表示已验证连通性。自定义上游和私有后缀失败不会转向公共 DNS。`-check` 不探测上游是否可达。

```toml
[dns]
mode = "host"
# Gate: mode = "gate", listen-address = "192.168.1.2", listen-port = 53
# servers = ["192.168.1.1"]

[[dns.rules]]
suffix = "corp.example"
servers = ["10.0.0.53"]
interface = "VPN"
```

手工规则优先于自动上下文，手工规则间最长后缀优先；匹配后只用指定解析器，超时或否定回答不回退公网。最多 64 条规则、每组 16 台服务器。搜索域只展示上下文，由客户端展开名称。

| 设置 | 默认与含义 |
| --- | --- |
| `mode` | `host` 或 `gate`；管理模式默认 Host，切换需暂停代理 |
| `listen-address` | Gate 使用的本机网卡地址；`0.0.0.0`/`::` 表示所有相应网卡，可能与本机已有 DNS 服务冲突 |
| `system` | 旧配置兼容字段；显式 `mode` 优先。旧 false 配置不会自动新增 LAN 监听 |
| `listen-port` | 默认 53，UDP/TCP；Host 使用本地入口，Gate 使用所选网卡地址 |
| `ttl` / `packet-size` | 600 秒 / 4096 字节 |
| `read-timeout` / `write-timeout` | 各 5 秒 |
| `history-limit` / `history-retention` | 512 条 / 3600 秒；历史条数 0 关闭记录 |
| `cache-limit` | 1024 条；0 关闭真实响应缓存，活动 Fake-IP 映射独立保留 |

Host 接管：Linux 优先使用 systemd-resolved；非 stub 环境临时替换本机 `/etc/resolv.conf` 入口，暂停后恢复原文件或符号链接，不改写 WSL 共享目标。macOS 创建自有临时解析服务；Windows 使用自有 NRPT 根规则且要求端口 53。已有策略冲突或无法安全复制的解析语义会阻止启用或令该作用域失败。逐平台边界见 [DNS 原理](../technical/dns.md)。

## 6. GeoIP 数据

| 来源 | 输入与能力 |
| --- | --- |
| `builtin` | 内置 DB-IP Country Lite IPv4 离线数据，来源见 [归因](../../licenses/DB-IP.md) |
| `kone-json` | KONE JSON，IPv4，最多 32 MiB / 500000 段 |
| `dbip-lite` / `ipinfo-lite` / `maxmind-geolite2` | 已解压国家 MMDB，最多 64 MiB，可含 IPv4/IPv6 |

1. 从可信来源取得文件并确认许可；计算整个解压文件原始字节的 SHA-256。
2. 停用代理，在管理界面选择来源、文件和预期摘要，完成校验后保存。
3. 查看元数据，重新启用并用规则模拟检查国家匹配。失败保留旧版，可显式回退上一版。

文件模式使用 `[geoip] provider/file/sha256`；路径相对 TOML，摘要为 64 位小写十六进制。管理模式上传文件，不接受浏览器传入主机路径。KONE 不自动下载；校验和证明内容一致，不认证发布者。

自定义 JSON 示例：

```json
{
  "format": 1,
  "version": "example-2026-11-01",
  "source": "https://example.com/geoip",
  "license": "CC0-1.0",
  "license_url": "https://creativecommons.org/publicdomain/zero/1.0/",
  "published_at": "2026-11-01T00:00:00Z",
  "ranges": [{"start": "192.0.2.0", "end": "192.0.2.255", "country": "CN"}]
}
```

示例仅说明格式。实际范围需规范 IPv4、按起点排序且不重叠，国家代码大写；拒绝重复/未知字段及不合法元数据。来源 URL 必须为不含凭据、查询参数或 fragment 的 HTTPS 地址。GeoIP 未知不猜测国家，地理归属不证明连通性。

## 7. 旧配置迁移

旧 INI、`[proxies]`、规则 `proxy`、`core.dns-*`、relay/NAT 端口字段和 `general.manager-addr` 已移除。按示例转换为 TOML、`[[outbounds]]`、规则 `outbound` 与 `[dns]`，不要将旧 `type = "direct"/"reject"` 声明当代理条目。迁移后先静态校验，再在目标环境预检。
