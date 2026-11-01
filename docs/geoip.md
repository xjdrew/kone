# GeoIP 数据源、导入与回退

GeoIP 为 `GEOIP` 规则提供 IP 到国家/地区代码的映射，不代表目标可以连接，也不能证明某个目标应该使用代理。默认使用离线内置库；可选择以下国家 MMDB 数据源或保留自定义 JSON，查看来源、许可、版本、发布时间、SHA256 和实际 IPv4 / IPv6 覆盖，并保留上一版供回退。

管理界面只在暂停接管时安装或回退数据，随后显式启用接管；保存的数据会在下次启动重新校验。管理配置版本与运行策略代次分开，规则解释和连接记录同时报告它们使用的 GeoIP 版本与 SHA256。已建立会话持有原规则和原数据快照。

## 如何选择数据源

| 配置名称 | 数据源与更新频率 | 使用方式与许可 |
| --- | --- | --- |
| `builtin` | 内置 DB-IP Country Lite 2026-10，IPv4 | 无需下载或账号；CC-BY-4.0 |
| `dbip-lite` | [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite)，每月 | 官方 MMDB 可免账号下载，解压 `.gz` 后导入；CC-BY-4.0 |
| `ipinfo-lite` | [IPinfo Lite](https://ipinfo.io/developers/ipinfo-lite-database)，每天 | 自行注册免费账号，使用自己的 token 下载国家/ASN MMDB；CC-BY-SA-4.0 |
| `maxmind-geolite2` | [MaxMind GeoLite2 Country](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)，每周二、五 | 自行注册账号并使用 license key 下载 Country MMDB，解压 `.tar.gz`；CC-BY-SA-4.0 与 [GeoLite EULA](https://www.maxmind.com/en/geolite/eula) |
| `kone-json` | 用户维护的 IPv4 范围表 | 沿用下文的严格 JSON 格式和数据自身许可 |

三种 MMDB 都可承载 IPv4 和 IPv6，实际覆盖以导入文件为准。国家识别存在误差，各来源对同一地址也可能不同；更新频率、格式和获取方式是选择依据，没有在 KONE 用户流量上证明某一家普遍更准确。需要较新数据时可试用 IPinfo Lite；无需账号时选 DB-IP；已有 MaxMind 更新流程时可复用 GeoLite2 Country。一次只启用一个数据集，不混合多个来源的冲突结果。

数据许可独立于 KONE 的 GPL-3.0-or-later。导入前自行阅读来源条款、保留归因；MaxMind 还要求在新版本发布后 30 天内删除旧版本，包含自行保留的回退文件和备份。外部数据不随 KONE 发行，也不会把 token、账号或 license key 写进 TOML。KONE 不根据配置、来源字段或 MMDB 中的 URL 自动下载；下载、解压和确认来源由用户完成。

管理界面：暂停接管，在“设置 → GeoIP 数据 → 更新 GeoIP 数据”选择来源/格式，选择已解压的文件，填写可信下载记录中的 SHA256，校验后确认保存。然后显式启用接管。更换下拉选项只决定待导入文件的结构，不会直接替换活动数据。

CLI 文件模式可省略整个 `[geoip]`，使用内置库；也可配置本地文件：

```toml
[geoip]
provider = "ipinfo-lite" # builtin | dbip-lite | ipinfo-lite | maxmind-geolite2 | kone-json
file = "data/ipinfo_lite.mmdb" # 相对于本 TOML 文件；也可用绝对路径
sha256 = "替换为整个解压后文件的64位小写SHA256"
```

外部文件在启动时完整校验，校验失败不创建 TUN、不改变系统网络，也不静默回退。修改这三项需要重启；在原路径更新文件后也需要重启。管理模式通过上传维护自己的数据仓库，不接受从浏览器传入的主机文件路径；其数据不通过 `[geoip] file` 管理。

## MMDB 校验与国家字段

MMDB 原始文件最多 64 MiB，不接收压缩包。KONE 先校验预期 SHA256，再验证 MMDB 树和数据结构、构建时间、国家记录与条目数量。DB-IP / MaxMind 读取 `country.iso_code`，IPinfo Lite 读取 `country_code`；不会用注册地、ASN 名称或缺失字段猜测实际国家。未知地址、空值和 `ZZ` 不命中国家规则。

校验后的原始字节和只读 reader 由快照持有，支持 IPv4、IPv4 映射地址和 IPv6；不会 mmap 一个稍后被覆盖的文件，也不会在旧连接仍引用数据时关闭 reader。格式验证和校验和不能认证发布者身份；选择来源表示选择相应的数据结构与许可说明。

## 自定义 JSON 格式

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

每段范围包括起止 IPv4 地址，边界均包含在内。地址必须规范书写，范围按起始地址升序且互不重叠，`country` 是两个大写英文字母，`ZZ` 表示未知国家。文件最多 32 MiB、500000 段；不接受 IPv6、重复 JSON 字段、未知字段、倒序/交叠范围、空版本/许可、无发布时间或超过一天的未来发布时间。JSON 和内置库只提供 IPv4 国家识别；需要 IPv6 国家规则时选择含 IPv6 记录的 MMDB，也可使用明确的 `IP-CIDR6` 规则。

导入同时提供**整个文件原始字节**的 SHA256，包含空格、换行和元数据。可使用 PowerShell `Get-FileHash -Algorithm SHA256 ./geoip.json` 或 `sha256sum geoip.json` 计算，并使用小写十六进制摘要。SHA256 检查内容是否与预期一致，不代替发布者签名或可信下载来源。改动文件的任何字节后都需要重新计算摘要。

## 持久化、失败与恢复

管理配置目录的 `geoip` 子目录保存按 SHA256 命名的数据文件及 `manifest.json`。导入先校验完整文件，再写入数据文件并同步到磁盘，最后以同目录原子替换发布清单；清单记录当前和上一版。正常更新只保留这两版，不清理目录中的其他用户文件。请备份整个子目录，不单独复制清单。

校验、写入或清单发布失败时保留原活动版本；没有自动下载，因此断网不影响使用已保存的数据。启动再次校验文件摘要和结构，损坏时阻止接管并保留管理入口，不静默切回另一套规则数据。当前文件损坏且清单、上一版仍有效时，可显式恢复上一版。清单或两版均损坏时，应从可信备份恢复或重新导入，避免手工猜测摘要。

## 可追溯的内置数据库

首次运行使用完整的 **DB-IP Country Lite 2026-10 IPv4**，共 362122 段，发布日期为 2026-10-01。旧未知来源表已经移除，公开查询和规则使用同一个不可变快照。数据采用 [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/)，来源、原始 CSV/压缩包摘要、转换记录及归因见 [licenses/DB-IP.md](../licenses/DB-IP.md)；[IP Geolocation by DB-IP](https://db-ip.com)。GeoIP 数据不是连接可达性或目标归属的证明。

内置版本的 `sha256` 标识解压后的 10 字节定长范围表，`source_sha256` 标识原始官方 CSV.gz。内置紧凑表不是 JSON 导入文件，转换器另行输出的 JSON 有独立的文件摘要。`Bytes()` 对内置表返回空值；不能将范围表摘要拿来校验 JSON。

转换器只读显式本地输入，不联网下载，也不修改运行配置或系统网络。先从[官方页面](https://db-ip.com/db/download/ip-to-country-lite)取得对应月份的压缩 CSV 并核对来源和许可，再运行：

```sh
just ci geoip-convert \
  --input dbip-country-lite-2026-10.csv.gz \
  --sha256 097426b8ddae89157d444a59ac1847e873f7943c32d52becc4371c8b0273af80 \
  --release 2026-10 --retrieved-at 2026-10-31T18:04:18Z \
  --output-dir ./converted --json ./converted/geoip.json
```

原始 CSV 解压后 31210433 字节，IPv4 共 362122 段、IPv6 共 348712 段；该紧凑内置格式只保留 IPv4；IPv6 国家识别由可选 MMDB 提供。输出定长表 3621220 字节，仓库中的 gzip 为 2274743 字节；另行生成的导入 JSON 为 22621111 字节。转换检查来源 SHA256、gzip 校验、UTF-8/CSV、国家代码、IPv4 顺序与交叠以及 500000 段/32 MiB 输出上限；更新资产时同时更新来源清单、归因、固定数据测试和发行包。

启动只解包一次，验证压缩与原始表摘要、大小和每段边界，再构建查询表；没有自动下载。国家代码字符串共享，查询不分配内存。362122 段在 64 位平台的范围表约 8.69 MB，在 ARMv7 的 32 位布局约 5.79 MB；另有约 2.27 MB 只读压缩资产，解包临时缓冲约 3.62 MB。ARMv7 数字来自结构布局估算，尚未视为 Raspberry Pi 硬件实测；内置解码测试和下述基准报告实际 CI 平台的启动耗时、分配量与查询速度。完整 JSON 导入会额外持有 JSON 与校验中间结果，建议在内存充足的管理机器转换，并在网关暂停接管后安装。

在提交 `49b79ba` 的 [Linux amd64 CI 样本](https://github.com/xjdrew/kone/actions/runs/41229662366/job/124621057488)中，Go 1.27.3 单次解码约 37.0 ms、累计分配 12969536 字节，查询表为 8690928 字节。该结果只描述对应 runner 和数据版本，不外推 Raspberry Pi 启动时间；更换数据后国家规则的结果可能变化，应检查规则解释。

## 开发接口与性能基线

`geoip.Load(reader, expectedSHA256)` / `LoadMMDB(reader, expectedSHA256, provider)` 返回不可变数据库；`Country(netip.Addr)` 只读查询，`Metadata()` 返回独立元数据值，`Bytes()` 返回原始文件副本。`OpenRepository`、`Install` / `InstallMMDB`、`Rollback` 管理本地持久化；`RecoverPrevious` 是损坏后的显式修复操作。旧 JSON 仓库清单仍可读取，MMDB 清单额外记录每份文件的来源结构；不会按扩展名猜测结构。

`WithGeoIPDatabase` 在创建引擎前指定数据。`ApplyGeoIP` / `ApplyGeoIPDatabase` 和 `RollbackGeoIP` 使用运行策略代次进行并发检查，在同一原子快照内发布规则与数据；失败保留原快照。管理控制层采用暂停后安装，再启动的新实例，避免把保存成功与运行应用成功混成一个状态。

以下基准不创建 TUN、不改变系统网络，也不连接外部服务：

```sh
just quality benchmark
```

任务在 `baseline/` 保存环境信息、内置数据启动检查、核心与 GeoIP 基准的三个样本，以及匹配的画像和测试程序。每次操作按 Go 基准迭代次数计量，报告分配，并覆盖纯规则决策、GeoIP 查找和真实 DNS 响应缓存副本开销。应在相同设备、构建选项和负载下比较多轮结果；这些微基准不能代替真实 TUN 吞吐、延迟、CPU、内存及长时并发测试。入口与依赖见 [开发任务](development.md)。
