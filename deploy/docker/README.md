# Docker（Linux）

从仓库根目录构建和检查配置：

```sh
docker build -f deploy/docker/Dockerfile -t kone:local .
docker run --rm kone:local -check -config /etc/kone/config.toml
```

此检查不需要 TUN、管理员网络能力或代理可达。
实际运行前编辑 `configs/kone.example.toml` 的上游代理地址，再执行：

```sh
docker compose -f deploy/docker/docker-compose.yml up -d --build
```

Compose 使用 Linux host 网络、`NET_ADMIN` 和 `/dev/net/tun`，会修改宿主机网络；运行前检查配置。
默认管理端仍为回环地址。网关场景的 DNS 与客户端路由需要另外配置。
这里提供独立 KONE 镜像，旧版 Pi-hole/v2raya 混合配置已移除。
