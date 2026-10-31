# Raspberry Pi / Linux 网关部署

使用支持 Go 1.27.3 的系统，并安装 `iproute2`。下面以 64 位 Linux / arm64 树莓派为例。
先阅读 [当前功能边界](../../README.md#current-boundaries) 和 [配置说明](../configuration.md)。

## 构建与配置

在树莓派上直接构建：

```sh
go build -o dist/kone ./cmd/kone
cp configs/kone.example.toml config.toml
```

也可以在开发机交叉编译：`GOOS=linux GOARCH=arm64 go build -o dist/kone-linux-arm64 ./cmd/kone`。
32 位旧设备需要另外确认系统和 Go 工具链支持范围；本项目 CI 当前覆盖 amd64/arm64。

编辑上游代理与规则，确认 `core.network` 不与现有 LAN/VPN 冲突。
显式设置可达的上游 DNS，避免把已转到 KONE 的路由器 DNS 再作为它自己的上游。

```sh
./dist/kone -check -config config.toml
sudo ./dist/kone -config config.toml
```

## 客户端与路由器

假设树莓派 LAN 地址为 `192.168.10.101`，虚拟网络使用默认 `10.192.0.1/16`：

1. 网关转发场景需要启用 Linux IPv4 forwarding，并按实际防火墙策略放行流量。
2. 在路由器配置静态路由：`10.192.0.0/16` 的下一跳为 `192.168.10.101`。
3. 将需要使用 KONE 的客户端 DNS 指向 `10.192.0.1`。若通过 DHCP 下发，先对一台客户端验证。
4. 使用 `dig example.com @10.192.0.1` 验证规则命中的域名返回虚拟 IP，再验证对应 TCP 访问。

当前管理页面只监听树莓派本机回环地址，可用 SSH 端口转发访问。
本轮尚未实现完整的系统网络自动恢复；停止或卸载后，需检查并撤销自己配置的 DHCP DNS、静态路由和 forwarding 设置。
