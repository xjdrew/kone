# DB-IP Country Lite 数据归因

IP Geolocation by [DB-IP](https://db-ip.com).

KONE includes the complete IPv4 portion of **DB-IP IP to Country Lite, October 2026**. The data is provided by DB-IP.com / Eris Networks S.A.S under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/); the license text is included in [CC-BY-4.0.txt](CC-BY-4.0.txt). This data retains its CC-BY-4.0 terms separately from KONE's GPL-3.0-or-later code license. DB-IP does not endorse KONE, and no accuracy or availability warranty is supplied.

- Official dataset and licensing: <https://db-ip.com/db/download/ip-to-country-lite>
- CSV specification: <https://db-ip.com/db/format/ip-to-country-lite/csv.html>
- Source archive: <https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz>
- Published: 2026-10-01; retrieved: 2026-10-31T18:04:18Z.
- Archive SHA256: `097426b8ddae89157d444a59ac1847e873f7943c32d52becc4371c8b0273af80`.
- Uncompressed CSV SHA256: `53864a68fbfef02c27c717d08d431a6d453e9e00e77d9e8da841d382267fca88`.
- The uncompressed CSV matches the provider's published MD5 `4c77817b3a3397de2b871257670f9687` and SHA1 `c8ad1dfe98cb29bcacd82a5c3ec361c880e5bb59`. These legacy digests corroborate the download; KONE records SHA256 for content identification.

Changes: the source's 362,122 IPv4 ranges are preserved, including unknown-country `ZZ` ranges; 348,712 IPv6 ranges are omitted because the country-rule database is currently IPv4 only. Adjacent same-country ranges may be merged without changing any lookup (this release already has no mergeable adjacent ranges). Each IPv4 entry is encoded as a big-endian 32-bit start, a big-endian 32-bit end, and two ASCII country bytes, then gzip compressed. There are no geolocation edits. `ZZ` is reported as unknown by KONE, consistent with its unknown-country behavior.

The manifest in `pkg/geoip/data/` records original and converted digests, sizes, counts, dates and changes. `scripts/data/convert-dbip.mjs` reproduces the artifact from the explicitly supplied local source archive; it never downloads or refreshes data automatically. The global Web footer and GeoIP panel link to DB-IP as required by the provider's attribution instructions.
