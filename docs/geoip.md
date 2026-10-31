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

每段范围包括起止 IPv4 地址，边界均包含在内。地址必须规范书写，范围按起始地址升序且互不重叠，`country` 是两个大写英文字母，`ZZ` 表示未知国家。文件最多 32 MiB、500000 段；不接受 IPv6、重复 JSON 字段、未知字段、倒序/交叠范围、空版本/许可、无发布时间或超过一天的未来发布时间。IPv6 接管可用不表示支持 IPv6 国家识别：当前 GEOIP 规则对 IPv6 返回未知，可另用 `IP-CIDR6` 规则。

导入同时提供**整个文件原始字节**的 SHA256，包含空格、换行和元数据。可使用 PowerShell `Get-FileHash -Algorithm SHA256 ./geoip.json` 或 `sha256sum geoip.json` 计算，并使用小写十六进制摘要。SHA256 检查内容是否与预期一致，不代替发布者签名或可信下载来源。改动文件的任何字节后都需要重新计算摘要。

## 持久化、失败与恢复

管理配置目录的 `geoip` 子目录保存按 SHA256 命名的数据文件及 `manifest.json`。导入先校验完整文件，再写入数据文件并同步到磁盘，最后以同目录原子替换发布清单；清单记录当前和上一版。正常更新只保留这两版，不清理目录中的其他用户文件。请备份整个子目录，不单独复制清单。

校验、写入或清单发布失败时保留原活动版本；没有自动下载，因此断网不影响使用已保存的数据。启动再次校验文件摘要和结构，损坏时阻止接管并保留管理入口，不静默切回另一套规则数据。当前文件损坏且清单、上一版仍有效时，可显式恢复上一版。清单或两版均损坏时，应从可信备份恢复或重新导入，避免手工猜测摘要。

## 可追溯的内置数据库

首次运行使用完整的 **DB-IP Country Lite 2026-10 IPv4**，共 362122 段，发布日期为 2026-10-01。旧未知来源表已经移除，公开查询和规则使用同一个不可变快照。数据采用 [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/)，来源、原始 CSV/压缩包摘要、转换记录及归因见 [licenses/DB-IP.md](../licenses/DB-IP.md)；[IP Geolocation by DB-IP](https://db-ip.com)。GeoIP 数据不是连接可达性或目标归属的证明。

内置版本的 `sha256` 标识解压后的 10 字节定长范围表，`source_sha256` 标识原始官方 CSV.gz。内置紧凑表不是 JSON 导入文件，转换器另行输出的 JSON 有独立的文件摘要。`Bytes()` 对内置表返回空值；不能将范围表摘要拿来校验 JSON。

转换器只读显式本地输入，不联网下载，也不修改运行配置或系统网络。先从[官方页面](https://db-ip.com/db/download/ip-to-country-lite)取得对应月份的压缩 CSV 并核对来源和许可，再运行：

```sh
node scripts/data/convert-dbip.mjs \
  --input dbip-country-lite-2026-10.csv.gz \
  --sha256 097426b8ddae89157d444a59ac1847e873f7943c32d52becc4371c8b0273af80 \
  --release 2026-10 --retrieved-at 2026-10-31T18:04:18Z \
  --output-dir ./converted --json ./converted/geoip.json
```

原始 CSV 解压后 31210433 字节，IPv4 共 362122 段、IPv6 共 348712 段；转换不裁剪 IPv4 国家数据，只排除尚未支持的 IPv6。输出定长表 3621220 字节，仓库中的 gzip 为 2274743 字节；另行生成的导入 JSON 为 22621111 字节。转换检查来源 SHA256、gzip 校验、UTF-8/CSV、国家代码、IPv4 顺序与交叠以及 500000 段/32 MiB 输出上限；更新资产时同时更新来源清单、归因、固定数据测试和发行包。

启动只解包一次，验证压缩与原始表摘要、大小和每段边界，再构建查询表；没有自动下载。国家代码字符串共享，查询不分配内存。362122 段在 64 位平台的范围表约 8.69 MB，在 ARMv7 的 32 位布局约 5.79 MB；另有约 2.27 MB 只读压缩资产，解包临时缓冲约 3.62 MB。ARMv7 数字来自结构布局估算，尚未视为 Raspberry Pi 硬件实测；内置解码测试和下述基准报告实际 CI 平台的启动耗时、分配量与查询速度。完整 JSON 导入会额外持有 JSON 与校验中间结果，建议在内存充足的管理机器转换，并在网关暂停接管后安装。

## 开发接口与性能基线

`geoip.Load(reader, expectedSHA256)` 返回不可变数据库；`Country(netip.Addr)` 只读查询，`Metadata()` 返回独立元数据值，`Bytes()` 返回原始文件副本。`OpenRepository`、`Install`、`Rollback` 管理本地持久化；`RecoverPrevious` 是损坏后的显式修复操作。

`WithGeoIPDatabase` 在创建引擎前指定数据。`ApplyGeoIP` / `ApplyGeoIPDatabase` 和 `RollbackGeoIP` 使用运行策略代次进行并发检查，在同一原子快照内发布规则与数据；失败保留原快照。管理控制层采用暂停后安装，再启动的新实例，避免把保存成功与运行应用成功混成一个状态。

以下基准不创建 TUN、不改变系统网络，也不连接外部服务：

```sh
go test -run '^$' -bench 'Benchmark(Query|ImmutableDatabaseLookup)' -benchmem -count=5 ./pkg/geoip
go test -run '^TestBundledDatasetStartupMemoryAndPublicQueryConsistency$' -v ./pkg/geoip
go test -run '^$' -bench '^BenchmarkBuiltinDecode$' -benchmem -count=3 ./pkg/geoip
go test -run '^$' -bench 'Benchmark(RuleDecision|DNSResponseCache)' -benchmem -count=5 ./pkg/kone
```

每次操作按 Go 基准迭代次数计量，报告分配，并覆盖纯规则决策、GeoIP 查找和真实 DNS 响应缓存副本开销。应在相同设备、构建选项和负载下比较多轮结果；这些微基准不能代替真实 TUN 吞吐、延迟、CPU、内存及长时并发测试。
