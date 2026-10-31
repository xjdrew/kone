# 可复现性能基线

CI 的 **Reproducible performance baseline** 先记录事实，不设置未经校准的“最高性能”或延迟阈值。每次 PR 和 master 验证使用固定源 SHA、相同 Go 工具链和确定性数据，分别编译 system 与 mixed，保留三个样本以及 CPU/内存画像。完整发布资格要求该任务能成功执行，但不会因为共享 runner 的一次耗时波动拒绝提交。

`performance-baseline` 工件包含：

- `environment.json`：精确提交、时间、OS/内核、CPU 型号、逻辑核数、内存、并发和数据来源。
- `toolchain.txt`：Go 版本、GOOS、GOARCH、CGO 状态。
- `core-{system,mixed}.txt`、`geoip-{system,mixed}.txt`：`ns/op`、`B/op`、`allocs/op` 与各基准声明的附加计数；并发固定为 1、2，`-benchtime=500ms -count=3`。
- `cpu-*.out`、`memory-*.out`、`kone-*.test`：观察查询负载的画像及匹配测试程序，可用 `go tool pprof` 分析。

## 测量对象

| 基准 | 固定场景 | 能说明什么 |
| --- | --- | --- |
| `BenchmarkRuleDecision` | 精确配置中的域名后缀、GeoIP 与最终规则，包含并行查找 | 决策 CPU/分配，不是代理往返延迟 |
| `BenchmarkDNSResponseCache` | 同一确定性 DNS 响应的缓存命中、ID 更新与拷贝 | 本机缓存代价，不是上游 DNS RTT |
| `BenchmarkObservationIncrement` | TCP/UDP，明细关闭/开启，每 worker 的长流增量 | 业务计数/明细更新代价；明细关闭仍保留独立整体计数 |
| `BenchmarkObservationSession` | TCP/UDP 单流创建、计数和关闭，明细关闭/开启 | 会话观察开销，不代表协议握手或加密开销 |
| `BenchmarkObservationQueries` | 保留 2048 记录、128 活动流，Snapshot/Sankey，附带或不附带两个更新 worker | 查询与数据更新并发时的 CPU/分配；画像只跑此基准 |
| `BenchmarkObservationBoundedLoad` | 4096 目标周转，明细上限 512、路径上限 128 加其他 | 容量/淘汰行为及 `retained_records`、`retained_paths`，不承诺无限保留 |
| `BenchmarkQuery`、`BenchmarkImmutableDatabaseLookup` | 内置/可替换 GeoIP 的确定性地址查找 | 地址归属查找代价，不表示网络连通性 |

观察基准中的载荷字节是合成计数。Go 输出的 `MB/s` 表示该计数操作承载的模拟字节量，**不能称为 TUN 吞吐、实际 TCP/UDP 转发速度或链路带宽**。system/mixed 构建都有这些核心指标，也不等于已经覆盖两种协议栈的报文处理差异。

## 本地复现与比较

在隔离开发/性能环境中运行，不需要创建 TUN 或修改系统网络：

```sh
go test ./pkg/kone -run '^$' -bench . -benchmem -benchtime=500ms -count=3 -cpu=1,2
go test -tags with_gvisor ./pkg/kone -run '^$' -bench . -benchmem -benchtime=500ms -count=3 -cpu=1,2
go test ./pkg/geoip -run '^$' -bench . -benchmem -benchtime=500ms -count=3 -cpu=1,2
go tool pprof baseline/kone-system.test baseline/cpu-system.out
```

比较时保留原始样本、SHA、工具链和硬件信息，区分共享 runner 波动与稳定变化。容量满额时整体计数仍须正确，查询不能改变转发策略；这些是正确性约束，由回归测试验证，不能用较快的平均耗时替代。

尚需独立实验室基线：真实 TUN 的 system/mixed TCP/UDP 往返、HTTP/SOCKS5/SS 加密转发、MTU/分片、长时间管理负载，及 Raspberry Pi 上的吞吐、CPU、内存、丢弃与 p50/p95/p99 延迟。CI 的隔离网络命名空间/Windows 驱动测试目前是功能与恢复验收，不能将其成功解释成上述性能目标已测量。得到这些硬件基线后，再制定有依据的回退预算。
