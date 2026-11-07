# 后续需求与决策记录

B01–B08 已由用户确认并实现于 [PR #51](https://github.com/xjdrew/kone/pull/51)，现行行为同步到 [PRD](prd.md)、[Web 规格](web-ui.md) 与用户指南。以下保留原请求的意图、实现决策和回归入口；是否已发布及平台检查结果以 PR 和对应提交的 CI 为准。

| ID | 用户请求 | 已实现决策 | 回归证据 / 对应契约 |
| --- | --- | --- | --- |
| B01 | 通过 `127.0.0.1` 打开 Web 时无需密码，自动拥有全部权限；其他地址才需管理员密码 | HTTP 数字回环来源自动创建管理会话；同时校验实际来源、Host/端口、Origin 和跨站标记，不信任转发头。本机仍使用 Cookie/CSRF，不能远程复用会话；远端密码和设备配对保留 | [本机会话单测](../../pkg/control/local_session_test.go)、[真实 HTTP 集成](../../test/integration/local_management_test.go)、[真实浏览器](../../web/e2e/real-console.spec.js)；UI-03/06、MG-QUALITY-01 |
| B02 | 添加或修改规则立即生效，不需重启代理 | 包括 IPv4/IPv6 CIDR 增删改与排序，先更新路由再发布策略；旧连接保留策略和所需路由。失败回滚，回滚无法完成则停止引擎。TUN/core、DNS 等设置仍需停用；文件模式仍需重启加载文件 | [路由事务单测](../../pkg/kone/live_routes_test.go)、[管理保存](../../pkg/control/readiness_test.go)、[原生 Linux 集成](../../test/integration/live_routes_linux_test.go)；RULE-03、MG-RULE-03 |
| B03 | 将原“启用接管”等术语改为“启用代理”或“启用 TUN”，统一所有位置 | Web、托盘和当前指南统一使用“代理”；纯直连确认使用“启用 TUN（仅直连）”，说明不会经过上游代理服务器；内部 API 字段保持兼容 | [托盘测试](../../pkg/application/desktop_test.go)、[三浏览器交互](../../web/e2e/console.spec.js)；UI-02、DESK-01 |
| B04 | 右上角用开关启停；启用后左侧显示实时出口带宽，单位自动调整 | 开关显示后端代理状态，忙碌/切换/无权限时禁用；分别显示当前采样的上传/下载业务载荷速率，单位自动换算，不计代理封装；过期显示不可用，停止隐藏 | [本机及分组浏览器用例](../../web/e2e/console.spec.js)；OBS-03、MG-GLOBAL-02 |
| B05 | 简化出站页最终规则显示，减少说明 | FINAL 主摘要为“其余流量 → 出站”，出站引用显示“其余流量”；编辑入口统一，保留条件范围与范围外直连说明 | [配置页单测](../../web/test/configuration-pages.test.mjs)、[浏览器 FINAL 用例](../../web/e2e/console.spec.js)；MG-OUT-01、MG-RULE-01 |
| B06 | 主机支持 IPv6 时默认配置 IPv6 网段 | 新建/恢复默认管理配置按活动非回环接口的全局单播地址（含 ULA）检测，排除仅链路本地地址，选无接口网段冲突的 ULA /120；无法检测则留空。保留已有选择，文件模式默认关闭，仍预检真实出口、DNS 与 LAN/VPN | [网段选择单测](../../pkg/kone/ipv6_defaults_test.go)、[已保存选择回归](../../pkg/control/local_session_test.go)；PROTO-01、MG-IN-02 |
| B07 | 首页“需要关注”按域名合并 | 规范化域名优先，无域名回退目标 IP；按目标展示次数、最近失败原因与时间，多事件钻取固定原始流 ID 集合，单事件保留详情及规则快捷操作 | [分组单测](../../web/test/flow-groups.test.mjs)、[浏览器钻取](../../web/e2e/console.spec.js)；OBS-02、MG-HOME-01 |
| B08 | 连接记录按同一目标折叠 | 先筛选、再按目标分组和分页；不同端口/协议保留原始行，同 IP 的不同域名分开；汇总连接数、活动/失败数、字节和速率，刷新保留展开状态，仅汇总已载入记录 | [分组单测](../../web/test/flow-groups.test.mjs)、[三浏览器展开/刷新](../../web/e2e/console.spec.js)；OBS-02/03、MG-CONN-01 |

## 验收环境与边界

- 本地 Linux：Go 1.27.3 全包 race、vet 与覆盖率比较；65 项 Web 单元测试、51 项任务脚本测试；Chromium、WebKit、Firefox 的桌面与 390 px 触控界面，以及真实 Go 管理服务的会话、密码轮换、保存与重启闭环。
- 原生网络：CI 的隔离 Linux 命名空间执行三种协议栈及新增 CIDR 在线更新用例；Windows Wintun、macOS UTUN 和系统 DNS 使用既有平台门禁。最终结果绑定 PR 的最新提交。
- 自动化浏览器和接口地址检测不替代真实 iOS/Android 证书与软键盘、桌面授权弹窗、VPN 共存、物理 IPv6 连通性或长期负载验收；这些部署边界按 [开发指南](../development/development.md#5-验收按风险定位) 单独核对。

后续新增或未决请求继续记录在这里；不得把尚未实现的候选方案写成现行行为。
