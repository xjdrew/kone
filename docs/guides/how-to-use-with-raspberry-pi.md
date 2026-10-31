# Raspberry Pi / Linux 网关部署

KONE 可以接管 Raspberry Pi 家庭或小企业网关后面的 LAN 客户端流量，迁移到 sing-tun 后保留此部署方式。需要 Linux TUN、`iproute2` 和相应管理权限。下面以 64 位 Linux / arm64 树莓派为例。
先阅读 [当前功能边界](../../README.md#current-boundaries) 和 [配置说明](../configuration.md)。

## 构建与配置

在树莓派上直接构建：

```sh
go build -o dist/kone ./cmd/kone
cp configs/kone.example.toml config.toml
```

也可以在开发机交叉编译：`GOOS=linux GOARCH=arm64 go build -o dist/kone-linux-arm64 ./cmd/kone`。
32 位 ARMv7 可使用 `GOOS=linux GOARCH=arm GOARM=7 go build -o dist/kone-linux-armv7 ./cmd/kone`，使用默认 system 栈；CI 也编译此目标。启用 mixed 栈时，arm64 构建增加 `-tags with_gvisor`。

编辑上游代理与规则，确认 `core.network` 不与现有 LAN/VPN 冲突。
显式设置可达的上游 DNS，避免把已转到 KONE 的路由器 DNS 再作为它自己的上游。

```sh
./dist/kone -check -config config.toml
sudo ./dist/kone -config config.toml
```

## 选择性接管：旁路网关

假设树莓派 LAN 地址为 `192.168.10.101`，虚拟网络使用默认 `10.192.0.1/16`：

1. 网关转发场景需要启用 Linux IPv4 forwarding，并按实际防火墙策略放行流量。
2. 在路由器配置静态路由：`10.192.0.0/16` 的下一跳为 `192.168.10.101`。
3. 将需要使用 KONE 的客户端 DNS 指向 `10.192.0.1`。若通过 DHCP 下发，先对一台客户端验证。
4. 使用 `dig example.com @10.192.0.1` 验证规则命中的域名返回虚拟 IP，再验证对应 TCP 访问。

显式 CIDR 规则同样可以接管 LAN 客户端到指定网段的流量。若捕获网段可能包含上游代理或 DNS，务必设置真实的 `outbound-interface`，避免再次进入 TUN。

## 全局 IPv4 接管：主网关或默认下一跳

客户端的默认网关指向树莓派，或者由上游路由器将这些客户端的默认流量转发给树莓派。树莓派必须事先具备可达的真实上游默认路由；保留该默认路由，不要手动将它删除或指向 KONE。

```toml
[core]
network = "10.192.0.1/16"
stack = "system"
auto-route = true
outbound-interface = "eth0" # 真实上游接口，按设备修改；可与 LAN 接口相同
dns-server = ["1.1.1.1", "8.8.8.8"]

[proxies]
Gateway = "http://your-proxy.example:8080"

[[rules]]
type = "IP-CIDR"
pattern = "192.168.0.0/16"
proxy = "DIRECT"

[[rules]]
type = "FINAL"
proxy = "Gateway"
```

KONE 添加两条半网默认路由捕获 IPv4，退出时删除它们并保留原来的真实默认路由。更具体的 LAN/VPN 路由仍按内核优先级工作；进入 TUN 的流量按 KONE 规则选择直连、代理或拒绝。
代理传输、直连 TCP/UDP 与上游 DNS 绑定真实出口，防止全局捕获导致自循环。上游代理域名也通过指定上游 DNS 解析。

由网关管理员配置以下系统前提，并持久化到自己的发行版网络配置中：

- 开启 IPv4 forwarding，放行 LAN 与 TUN 之间的转发，保留部署已有的 NAT/防火墙策略。需要普通直连流量经上游路由器返回 LAN 时，配置相应回程路由或源 NAT。
- 将客户端 DNS 指向 KONE 的虚拟地址；DHCP 可统一下发 DNS 和网关。KONE 不接管 DHCP 服务，不自动重写客户端网络配置。
- 根据非对称 TUN 路由需要设置 reverse-path filtering，例如相关接口采用 loose 模式 `rp_filter=2`；严格模式可能丢弃来自 LAN 的回注报文。不要直接清空现有防火墙规则。
- 本轮只接管 IPv4。若网络也启用 IPv6，应由部署者明确选择独立 IPv6 路由/过滤策略，不能假定 IPv6 自动经过 KONE。

UDP 保留原来的直连行为，不通过 HTTP/HTTPS/SOCKS5 TCP 代理。全局接管也不会自动增加 UDP 代理协议支持。
当前管理页面只监听树莓派本机回环地址，可用 SSH 端口转发访问。停止或卸载后，管理员仍需撤销自己配置的 DHCP、静态路由、forwarding 和防火墙设置；KONE 只回滚自己拥有的设备和路由。

## 验收

先从一台 LAN 客户端验证 DNS 返回 Fake-IP、域名 TCP、直接 IP TCP、UDP 和 REJECT 规则，再扩展到全网。CI 使用独立 LAN、网关、上游网络命名空间验收这些路径，分别运行 system 和 mixed 栈，同时验证代理/DNS 不被全局路由再次捕获、停止后默认路由保留。
真实 Raspberry Pi 吞吐、长时间负载、接口切换和其他 VPN 共存仍需在目标设备验收。
