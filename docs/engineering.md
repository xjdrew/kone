# 第一轮工程化与依赖决策

## 后续决策：sing-tun 迁移（2026-10-31）

维护者已接受 GPL-3.0-or-later。当前采用 SagerNet/sing-tun `v0.9.7-0.20261023115432-040db71fcd33`，对应 sing-box v1.14.4 使用的固定版本；移除 water。下文第一轮保留 water、维持 MIT 的决定为历史记录，不再代表现状。
真实 Windows race 验收复现 DLL 加载器的越界巨型数组转换。修补已通过 xjdrew/sing-tun 的 [独立 PR #1](https://github.com/xjdrew/sing-tun/pull/1) 审查并合并，包含精确切片、session 失败清理、独占创建及 HRESULT 错误规范化；KONE 通过远程 replace 固定引用合并提交 `fc4685fee0a3`，不再复制源码。详见 [依赖与修补](sing-tun.md)。指针检查和真实 Wintun/race 验收继续启用。
设备、system/mixed 数据面由 sing-tun 提供；网络变更仍通过 KONE 的 Network 边界执行可回滚操作，使用 external configuration 模式避免双重配置。旧报文/NAT 类型暂留以兼容嵌入 API，生产 Run 不再使用它们。
普通构建默认 system，`with_gvisor` 构建可显式选择 mixed；CI 测试两种构建。网关保留 LAN 转发能力，新增全局 IPv4 捕获与代理/DNS 真实出口绑定，同时补 ARMv7 构建和独立 LAN 客户端验收。IPv6、UDP 代理出站、网络切换和崩溃恢复继续独立迭代。

依赖检查日期：2026-10-31。版本通过 `go list -m -json module@latest` 查询，实际版本固定在 `go.mod` / `go.sum`。

## 本轮依赖处理

| 原依赖 | 决策 | 原因 |
| --- | --- | --- |
| `op/go-logging` | 删除，改用 `log/slog` | 标准库结构化日志，统一级别、text/JSON 和 stderr 输出 |
| `ini.v1` | 删除，改用 `pelletier/go-toml/v2 v2.4.3` | TOML 支持、严格未知字段检查和错误位置；配置使用具名结构体 |
| `miekg/dns v1.1.57` | 升级至 `v1.1.73` | 保留 DNS 报文和服务器 API；标准库 resolver 不能替代这部分功能 |
| `xjdrew/dnsconfig` | 以 `84960edf9ed4` 为源迁入 `pkg/dnsconfig` | 保留源码、测试、测试数据和许可，移除外部模块依赖 |
| `songgao/water` | 保留 `2b4b6d7c09d8` | 查询仍为最新版本；本轮隔离为 `tunDevice` 接口，控制驱动迁移范围 |
| `thecodeteam/goodbye` | 删除 | 改为标准库信号/context，由 engine 统一关闭资源并恢复网络 |
| `stretchr/testify` | 升级至 `v1.12.1` | 保留已有测试风格并补回归测试；不需要另引测试框架 |
| `x/net` | 升级至 `v0.62.0`，成为直接依赖 | 用其 SOCKS5 实现替代项目内手写握手；包装拨号/握手超时 |
| `x/sys` | 升级至 `v0.49.0` | 平台系统调用依赖；更新旧版 Windows 告警相关代码 |
| `x/mod`、`x/tools`、旧 YAML 等 | `go mod tidy` 清理 | 不保留不再需要的直接或传递依赖；新的 YAML 仅来自测试依赖 |

[go-toml](https://github.com/pelletier/go-toml) 支持严格解码；[x/net/proxy](https://pkg.go.dev/golang.org/x/net/proxy) 提供 SOCKS5 客户端。
CLI 使用标准库 `signal.NotifyContext`，由 engine 统一负责关闭与恢复，平台函数不再注册进程级退出逻辑。

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

## PR 覆盖率门禁

`Coverage must not decrease` 检查每次 PR 的全项目语句覆盖率，要求不低于该 PR 目标分支的精确 base SHA。
基线会重新运行测试，不依赖历史 artifact；失败、缺失或无有效语句的覆盖率报告均使门禁失败。
使用 Windows runner 和 PR 的 Go 工具链作为统一口径，避免跨平台语句集合不同，也兼容旧 `master` 的 Unix 构建问题。

三平台通过 `go list ./...` 枚举 KONE 模块的全部包，并将显式列表传给 `-coverpkg`，包含未执行代码的包；按语句数加权并合并重复 block，使用精确分数比较，不以四舍五入后的百分比判定。base 与 PR 使用同一枚举方式。
第三方 sing-tun 作为固定的外部 fork 模块，不进入 KONE 覆盖率分母；其修补由 fork CI 和 KONE 的 Windows 模块 race 回归、真实驱动/网关验收单独验证。覆盖率始终统计 KONE 模块全部包。
单元测试和 `test/integration` 中的 CLI 端到端测试一起执行；覆盖率统计使用 `go test` 生成的 profile，独立子进程的覆盖数据不会自动并入。
本地比较：`go run ./cmd/covercheck -base base.out -head head.out`。工具包含单元测试和实际编译执行的端到端用例，验证下降、持平、提升、重复 block 和无效报告。

## 下一轮边界

生命周期、启动失败回滚、正常退出恢复、快照及故障注入已纳入第二轮，设计和验收方式见 [运行可靠性](runtime.md)。
Linux 的真实 TUN 场景在隔离网络命名空间执行；本轮迁移新增 Windows Wintun 真实流量与回滚验收。macOS 的特权驱动验收、网络切换和进程崩溃后的恢复仍需后续完善。

数据面仍以 IPv4 TCP 为主；上游 DNS 取消和出站接口绑定已实现。完整 UDP 代理、IPv6、DNS TCP/截断回退属于后续功能迭代。
内嵌 GeoIP 数据来自旧生成文件；后续应引入可更新的数据来源、版本/校验和及许可说明，避免仅替换查询库却继续使用旧数据。
