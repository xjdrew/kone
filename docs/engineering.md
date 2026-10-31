# 第一轮工程化与依赖决策

依赖检查日期：2026-10-31。版本通过 `go list -m -json module@latest` 查询，实际版本固定在 `go.mod` / `go.sum`。

## 本轮依赖处理

| 原依赖 | 决策 | 原因 |
| --- | --- | --- |
| `op/go-logging` | 删除，改用 `log/slog` | 标准库结构化日志，统一级别、text/JSON 和 stderr 输出 |
| `ini.v1` | 删除，改用 `pelletier/go-toml/v2 v2.4.3` | TOML 支持、严格未知字段检查和错误位置；配置使用具名结构体 |
| `miekg/dns v1.1.57` | 升级至 `v1.1.73` | 保留 DNS 报文和服务器 API；标准库 resolver 不能替代这部分功能 |
| `xjdrew/dnsconfig` | 升级至 `84960edf9ed4` | 更新包含 Unix 字段访问修复，恢复 Linux/macOS 构建 |
| `songgao/water` | 保留 `2b4b6d7c09d8` | 查询仍为最新版本；本轮隔离为 `tunDevice` 接口，控制驱动迁移范围 |
| `thecodeteam/goodbye` | 保留 `a83968bda2d3` | 查询仍为最新版本；与当前 Windows 路由退出清理绑定，下一轮与生命周期一起替换 |
| `stretchr/testify` | 升级至 `v1.12.1` | 保留已有测试风格并补回归测试；不需要另引测试框架 |
| `x/net` | 升级至 `v0.62.0`，成为直接依赖 | 用其 SOCKS5 实现替代项目内手写握手；包装拨号/握手超时 |
| `x/sys` | 升级至 `v0.49.0` | 平台系统调用依赖；更新旧版 Windows 告警相关代码 |
| `x/mod`、`x/tools`、旧 YAML 等 | `go mod tidy` 清理 | 不保留不再需要的直接或传递依赖；新的 YAML 仅来自测试依赖 |

[go-toml](https://github.com/pelletier/go-toml) 支持严格解码；[x/net/proxy](https://pkg.go.dev/golang.org/x/net/proxy) 提供 SOCKS5 客户端。
`goodbye` 的后续替代建议是标准库 `os/signal.NotifyContext`，由 engine 统一负责关闭与恢复，避免在平台函数内注册进程级退出逻辑。

## Clash / mihomo 的 TUN 方案

当前维护中的 Clash 衍生项目 mihomo 的 [go.mod](https://github.com/MetaCubeX/mihomo/blob/Meta/go.mod) 引用了 `github.com/metacubex/sing-tun v0.4.28`。
它是比 `water` 更高层的 TUN、路由及协议栈方案，不能当作同 API 的设备库直接替换。
其 [LICENSE](https://github.com/MetaCubeX/sing-tun/blob/meta/LICENSE) 声明 GPL-3.0-or-later；当前 KONE 为 MIT，本轮没有引入该依赖或复制其实现。

可以借鉴的设计：设备、路由管理、TCP/UDP 栈与出站适配分层；驱动能力显式声明；批量读写；网络变更可回滚。
如果以后选择整体接入 sing-tun，需要先由维护者决定许可方向与协议栈路线。

更适合继续保持 MIT 路线的设备层候选是 [WireGuard 的 tun 包](https://github.com/WireGuard/wireguard-go/tree/master/tun)，其代码为 MIT，提供批量 I/O、事件和 Windows Wintun 接入。
它仍需要适配批量 API、Wintun 分发、路由/DNS 管理和实际性能验证；本轮新增的 `tunDevice` 边界为后续适配提供入口。

本轮保留 `water` 是迁移范围的选择，不代表它已满足长期产品要求。Windows 仍需 TAP-Windows 驱动，arm64 构建成功不代表已有可用的对应驱动。

## 质量门禁

- 三平台原生 `go test -race`、`go vet`、模块校验。
- Linux/macOS/Windows × amd64/arm64 编译。
- TOML 校验、环境变量、NAT 多目标/耗尽/并发、短包、热更新原子性、DNS 快照、日志脱敏、HTTP/SOCKS5 适配回归。
- CLI 的版本、帮助、示例配置检查、无权限错误路径。
- IPv4 fuzz 和 `govulncheck`；Docker 构建及无特权 `-check` 烟雾测试。
- 原生测试覆盖率和六种二进制作为 CI artifacts 保存。

## 下一轮边界

本轮没有把构建通过当作完整 TUN 运行验收。下一轮应加入特权集成测试与故障注入，验证设备创建、路由安装、DNS 恢复、启动失败回滚、信号退出和网络切换。
现有 `Serve` 的统一取消、错误传播和资源关闭仍需改造，Windows `goodbye` 应在该阶段移除。

数据面仍以 IPv4 TCP 为主；完整 UDP 代理、IPv6、DNS TCP/截断回退、上游 DNS 取消与出站路由绕过属于后续功能与可靠性迭代。
内嵌 GeoIP 数据来自旧生成文件；后续应引入可更新的数据来源、版本/校验和及许可说明，避免仅替换查询库却继续使用旧数据。
