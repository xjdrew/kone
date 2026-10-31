# GeoIP 数据导入与回退

GeoIP 为规则提供 IP 到国家/地区代码的映射，不代表目标可以连接，也不能证明某个目标应该使用代理。KONE 支持显式导入本地数据文件，查看来源、许可、版本、发布时间、SHA256 与条目数量，保留上一版供回退；不会根据数据中的 URL 自动联网下载。

管理界面只在暂停接管时安装或回退数据，随后显式启用接管；保存的数据会在下次启动重新校验。管理配置版本与运行策略代次分开，规则解释和连接记录同时报告它们使用的 GeoIP 版本与 SHA256。已建立会话持有原规则和原数据快照。

## 数据格式

文件是 UTF-8 JSON，使用以下结构；示例地址与数据仅用于说明，不能当作实际地理数据使用。

```json
{
  "format": 1,
  "version": "example-2024-01-01",
  "source": "https://example.com/geoip-data",
  "license": "CC0-1.0",
  "license_url": "https://creativecommons.org/publicdomain/zero/1.0/",
  "published_at": "2024-01-01T00:00:00Z",
  "ranges": [
    {"start": "192.0.2.0", "end": "192.0.2.255", "country": "CN"}
  ]
}
```

`source` 和 `license_url` 必须是无凭据、查询参数或 fragment 的 HTTPS URL，作为来源记录保存，不会被自动访问。`license` 应填写实际数据许可的 SPDX 标识或清楚名称；导入者应确认有权使用和分发该数据。KONE 校验这些字段的格式，不替提供者认证来源或许可声明。

每段范围包括起止 IPv4 地址，边界均包含在内。地址必须规范书写，范围按起始地址升序且互不重叠，`country` 是两个大写英文字母。文件最多 32 MiB、250000 段；不接受 IPv6、重复 JSON 字段、未知字段、倒序/交叠范围、空版本/许可、无发布时间或超过一天的未来发布时间。

导入同时提供**整个文件原始字节**的 SHA256，包含空格、换行和元数据。可使用 PowerShell `Get-FileHash -Algorithm SHA256 ./geoip.json` 或 `sha256sum geoip.json` 计算，并使用小写十六进制摘要。SHA256 检查内容是否与预期一致，不代替发布者签名或可信下载来源。改动文件的任何字节后都需要重新计算摘要。

## 持久化、失败与恢复

管理配置目录的 `geoip` 子目录保存按 SHA256 命名的数据文件及 `manifest.json`。导入先校验完整文件，再写入数据文件并同步到磁盘，最后以同目录原子替换发布清单；清单记录当前和上一版。正常更新只保留这两版，不清理目录中的其他用户文件。请备份整个子目录，不单独复制清单。

校验、写入或清单发布失败时保留原活动版本；没有自动下载，因此断网不影响使用已保存的数据。启动再次校验文件摘要和结构，损坏时阻止接管并保留管理入口，不静默切回另一套规则数据。当前文件损坏且清单、上一版仍有效时，可显式恢复上一版。清单或两版均损坏时，应从可信备份恢复或重新导入，避免手工猜测摘要。

首次运行仍可使用项目原有内嵌表，它的版本标为 `legacy-bundled`。仓库没有完整证明该历史数据的原始来源、发布时间及数据许可，因此这些信息明确标为未知，不把生成工具的代码许可当作数据许可。需要可追溯数据的部署应主动导入有明确授权和来源的数据库。内嵌表的摘要按每段大端序起止边界及原始代码字节计算，仅用于识别这份内嵌内容，不是可导入 JSON 的文件摘要。

## 开发接口与性能基线

`geoip.Load(reader, expectedSHA256)` 返回不可变数据库；`Country(netip.Addr)` 只读查询，`Metadata()` 返回独立元数据值，`Bytes()` 返回原始文件副本。`OpenRepository`、`Install`、`Rollback` 管理本地持久化；`RecoverPrevious` 是损坏后的显式修复操作。

`WithGeoIPDatabase` 在创建引擎前指定数据。`ApplyGeoIP` / `ApplyGeoIPDatabase` 和 `RollbackGeoIP` 使用运行策略代次进行并发检查，在同一原子快照内发布规则与数据；失败保留原快照。管理控制层采用暂停后安装，再启动的新实例，避免把保存成功与运行应用成功混成一个状态。

以下基准不创建 TUN、不改变系统网络，也不连接外部服务：

```sh
go test -run '^$' -bench 'Benchmark(Query|ImmutableDatabaseLookup)' -benchmem -count=5 ./pkg/geoip
go test -run '^$' -bench 'Benchmark(RuleDecision|DNSResponseCache)' -benchmem -count=5 ./pkg/kone
```

每次操作按 Go 基准迭代次数计量，报告分配，并覆盖纯规则决策、GeoIP 查找和真实 DNS 响应缓存副本开销。应在相同设备、构建选项和负载下比较多轮结果；这些微基准不能代替真实 TUN 吞吐、延迟、CPU、内存及长时并发测试。
