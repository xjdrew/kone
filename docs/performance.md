# 可复现性能基线

CI 的质量任务保留可复现性能基线，不设置未经校准的“最高性能”或延迟阈值。每次 PR 和 master 验证使用固定源 SHA、相同 Go 工具链和确定性数据，保留三个样本以及一组 CPU/内存画像。完整发布资格要求这些步骤成功执行，但不会因为共享 runner 的一次耗时波动拒绝提交。

规则、DNS 响应缓存、观察器和 GeoIP 基准不创建协议栈，也没有按 `with_gvisor` 切换的实现，因此只执行一轮，避免把同一算法分别标成 system/mixed 重复测量。`system` 和 `mixed` 的构建、race 与真实 TUN 验收仍然保留；下文的原生采样也继续逐栈运行。CI 分组及优化前后的耗时记录见 [CI 说明](ci.md)。

`performance-baseline` 工件包含：

- `environment.json`：精确提交、时间、OS/内核、CPU 型号、逻辑核数、内存、并发和数据来源。
- `toolchain.txt`：Go 版本、GOOS、GOARCH、CGO 状态。
- `core.txt`、`geoip.txt`：`ns/op`、`B/op`、`allocs/op` 与各基准声明的附加计数；并发固定为 1、2，`-benchtime=500ms -count=3`。
- `profile.txt`、`cpu.out`、`memory.out`、`kone.test`：观察查询负载的输出、画像及匹配测试程序，可用 `just ci profile` 进入 pprof 分析。
- `geoip-startup.txt`：内置数据初始化的实际内存及一致性检查结果。

## 测量对象

| 基准 | 固定场景 | 能说明什么 |
| --- | --- | --- |
| `BenchmarkRuleDecision` | 精确配置中的域名后缀、GeoIP 与最终规则，包含并行查找 | 决策 CPU/分配，不是代理往返延迟 |
| `BenchmarkDNSResponseCache` | 同一确定性 DNS 响应的缓存命中、ID 更新与拷贝 | 本机缓存代价，不是上游 DNS RTT |
| `BenchmarkObservationIncrement` | TCP/UDP，明细关闭/开启，每 worker 的长流增量 | 业务计数/明细更新代价；明细关闭仍保留独立整体计数 |
| `BenchmarkObservationSession` | TCP/UDP 单流创建、计数和关闭，明细关闭/开启 | 会话观察开销，不代表协议握手或加密开销 |
| `BenchmarkObservationQueries` | 保留 2048 记录、128 活动流，Snapshot/Sankey，附带或不附带两个更新 worker | 查询与数据更新并发时的 CPU/分配；画像只跑此基准 |
| `BenchmarkObservationBoundedLoad` | 4096 目标周转，明细上限 512、路径上限 128 加其他 | 容量/淘汰行为及 `retained_records`、`retained_paths`，不承诺无限保留 |
| `BenchmarkQuery`、`BenchmarkImmutableDatabaseLookup`、`BenchmarkBuiltinDecode` | 内置/可替换 GeoIP 的确定性地址查找与解码 | 地址归属查找及初始化代价，不表示网络连通性 |

观察基准中的载荷字节是合成计数。Go 输出的 `MB/s` 表示该计数操作承载的模拟字节量，**不能称为 TUN 吞吐、实际 TCP/UDP 转发速度或链路带宽**。这些指标描述共用的核心算法，不表示已经测量两种协议栈的报文处理差异。

## 真实 TUN 的有限 runner 采样

Linux 原生生命周期任务还在独立网络命名空间中运行 `TestSystemPerformanceBaseline`，分别验证 `system` 和 `mixed` 的真实 Fake-IP → TUN → direct TCP/UDP → 本地回显服务 → TUN 回程。它先生成虚拟地址，再热更新为直连；准备映射的代理出站不参与实际转发。

每种协议比较三种模式：保留明细、仅独立整体计数，以及保留明细并以目标 200 次/秒并发查询一致的 Snapshot/Sankey。关闭明细不等于关闭整体计数或全部观察开销，输出记录实际完成的查询数。TCP 每轮每方向 16 KiB，UDP 每轮每方向 1200 字节；4 轮预热后计量 128 轮，整个采样有 20 秒上下文上限，每种协议栈的总往返载荷小于 16 MiB。

`native-data-plane-baseline` 工件包含 `environment.txt` 和 `system.log`、`mixed.log`：前者记录精确 SHA、Go、OS/内核、CPU 型号/核数、内存和 race 构建参数；日志中的 `KONE_NATIVE_PERFORMANCE` JSON 记录完整回显验证的实际载荷字节、耗时、载荷吞吐、单轮 RTT 的 p50/p95/p99、同进程用户/内核 CPU 时间和查询数。百分位采用最近秩；TCP 的 RTT 对应一轮完整载荷回显。传输或退出清理失败仍使任务失败，性能数值不设置波动门禁。

这是共享 runner、race 插桩、回环目标和测试夹具共同参与的集成采样。CPU 包括同进程的回显服务和查询负载；每轮校验也有开销。结果可追踪同类环境的变化，不能当作纯内核性能、物理链路上限、不同模式之间的因果结论，或 Raspberry Pi、HTTP/SOCKS5/SS 的实测吞吐。

## 本地复现与比较

在隔离开发/性能环境中运行，不需要创建 TUN 或修改系统网络：

```sh
just quality benchmark
just ci profile baseline/cpu.out baseline/kone.test
```

任务从仓库根目录执行，依赖与完整入口见 [开发说明](development.md)。比较时保留原始样本、SHA、工具链和硬件信息，区分共享 runner 波动与稳定变化。容量满额时整体计数仍须正确，查询不能改变转发策略；这些是正确性约束，由回归测试验证，不能用较快的平均耗时替代。

尚需独立实验室基线：HTTP/SOCKS5/SS 加密转发、MTU/分片、长时间管理负载，及 Raspberry Pi 上的吞吐、CPU、内存、丢弃与 p50/p95/p99 延迟。除上述有明确计量边界的 Linux direct 采样外，原生协议/驱动测试仍是功能与恢复验收；不能把功能通过当作性能目标已测量。得到这些硬件基线后，再制定有依据的回退预算。
