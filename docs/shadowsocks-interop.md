# Shadowsocks 互操作验收

客户端支持 AEAD2017 的 `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`，分别验证 TCP 和原生 UDP。独立 SIP004/SIP007 测试对端继续保留，用于发现双方共用客户端库可能掩盖的线格式错误；另一个 CI 门禁使用实际官方服务器。

服务器固定为 [shadowsocks-rust v1.25.0](https://github.com/shadowsocks/shadowsocks-rust/releases/tag/v1.25.0)，发布于 2026-08-26，源码 tag 对应 `ab388c7466d21f979430e33cc9ef10e22fb05955`。镜像来自项目[官方 GHCR 镜像发布流程](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/.github/workflows/build-docker-image.yml)，固定引用：

```text
ghcr.io/shadowsocks/ssserver-rust@sha256:22240c07d8ce3a36421ede770bd775dcc5fc56d5d829943196957b05452dc36f
```

该 OCI 索引的 Linux amd64 manifest 为 `sha256:1816b2b09f3db929a688e48efb1333e4ee459ba158a951f9e73c3580628ab964`。测试再次执行镜像中的 `ssserver --version`，校验版本为 1.25.0；更新固定版本时应同时核实源码 tag、镜像 digest 和实际二进制版本。

CI 先拉取固定镜像和编译测试程序，再在 `--network none` 的临时容器执行。容器只开放自己的 loopback，不发布主机端口，根文件系统只读，移除所有 capabilities，限制 CPU、内存和进程数；不创建 TUN，不改主机路由、DNS、代理、防火墙或证书。该脚本拒绝在普通本地会话运行。

测试覆盖：

- 三种方法的 TCP/UDP 加密双向回显。
- 官方服务器通过容器内专用 DNS 解析原始域名；Go 客户端解析器被设为拒绝查询，任何业务域名本地解析都会令测试失败。
- 错误密码不能返回业务载荷，且不会向回显服务提交数据。
- 已建立 UDP 会话在取消后关闭并唤醒读取，已取消上下文不能再建立 TCP 连接。

服务器测试配置只含公开的 CI 专用口令。CI 结果保留实际版本、镜像、方法/传输、DNS/取消/拒绝结果及日志；不记录用户代理凭据。`shadowsocks-interop` 与其他门禁处于同一个流水线，发行验证标记必须依赖它成功，不会因为另一个工作流成功而忽略互操作失败。

验收结果以对应提交的 CI 为准。这个矩阵验证所选官方服务器版本和三种已声明方法，不代表 AEAD-2022、插件、其他供应商版本或全部 IPv6 部署已通过。
