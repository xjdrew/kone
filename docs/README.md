# KONE 文档

| 阅读目的 | 文档 | 内容顺序 |
| --- | --- | --- |
| 安装与日常使用 | [使用指南](user/usage.md) | 安装 → 首次配置 → 日常操作 → 手机/CLI/网关 → 升级卸载 |
| 调整行为 | [配置指南](user/configuration.md) | 生效范围 → 最小示例 → 出站规则 → TUN/IPv6 → DNS → GeoIP → 迁移 |
| 定位故障 | [观察与排障](user/troubleshooting.md) | 症状分流 → 读懂数据 → 独立诊断 → 恢复 → 复现报告 |
| 修改实现 | [开发指南](development/development.md) | 环境 → 模块 → 工作流程 → 检查 → 验收 → 提交 |
| 测量开销 | [性能观察](development/performance.md) | 问题指标 → 采样 → 基准 → 分析复验 → 原生数据 → 结论 |
| 交付程序 | [打包与发布](development/packaging.md) | 前提产物 → 本地打包 → 验证 → 版本 → 发布 → 回退 |
| 定义产品 | [产品 PRD](requirements/prd.md) | 问题用户 → 目标范围 → 能力 → 需求 → 约束 → 验收 → 风险 |
| 讨论未来方向 | [技术边界与产品研究](research/product-direction-2026-11-07.md) | 实现边界 → 复现实验 → 竞品 → smart/app → 路线与验收建议 |
| 重写或重构 Web | [Web 规格](requirements/web-ui.md) | 信息架构 → 权限状态 → 配置 → 功能域 → 数据契约 → 质量与验收 |
| 设计与实现 Web 界面 | [UI/UX 设计规则](design-system/kone/MASTER.md) | 任务与点击预算 → 顶部双工作区 → 视觉变量 → 组件与操作 → 工具 → 验收 |
| 处理后续请求 | [待办与决策](requirements/backlog.md) | 请求 → 决策与实现 → 回归证据 → 验收边界 |
| 理解技术原理 | [技术参考](technical/README.md) | 架构、DNS、运行可靠性、macOS 权限与 sing-tun |

使用文档描述现行行为；PRD 与 Web 规格定义产品和重构验收契约；UI/UX 设计规则定义界面实现目标，不代表已交付；需求记录保存后续请求、已确认决策与实施证据；研究文档保留有日期和基线的证据与方向建议，不代表已批准需求。能力核对基线写在 PRD，测试通过与真机验收分别记录。历史过程文档已移除，旧版本可从 Git 历史追溯。

文档组织依据 [Diátaxis](https://www.diataxis.fr/start-here/) 区分操作、参考和原理；步骤采用 [Google 技术文档规范](https://developers.google.com/style/procedures) 的前提、动作与结果结构。PRD 按 [Atlassian 指南](https://www.atlassian.com/agile/product-management/requirements) 组织目标、用户、范围和验收。维护时先确定读者与任务，再调整对应文档，避免重复维护同一默认值或行为。
