# KONE 开发规范

- 在 `codex/<topic>` 开发分支工作；新任务基于最新 `origin/master`，相关任务复用分支。不得直接推送 `master` 或擅自合并 PR。
- 推送后使用 `gh` 自动创建或更新面向 `master` 的 PR，检查 CI 并修复失败；权限不足时说明阻断。
- CI 由 PR、`master` 推送及正式版本 tag 触发，开发分支 push 不运行 CI。每次 PR 的 KONE 模块全包语句覆盖率不得低于目标分支基线；独立第三方模块另行验证补丁。
- 代码变更补充单元测试和端到端测试，修复缺陷增加回归用例，维持测试覆盖率；单元测试随包，端到端测试放在 `test/integration/`。
- 每次变更更新 `CHANGELOG.md`；行为或配置变化同步更新示例和文档。
- PR 标题使用 Conventional Commits（如 `feat:`、`fix:`，破坏性变更用 `!` 或 `BREAKING CHANGE:`）；需要指定版本时，在合并提交保留 `Release-As: X.Y.Z`，只能提高自动计算的版本。
- CHANGELOG 面向用户，按版本或日期归类，区分 Features、Bugfixes，其他变更列 Changes；每项尽量一句话，只写用户可感知的变化和必要迁移，不写实现、调试、测试细节或未实现计划。
- 使用 Go 1.27.3、`gofmt`、结构化 `log/slog` 和严格 TOML 配置；源码放在 `cmd/`、`pkg/`，根目录不放 Go 源码。
- 日常开发统一使用根 just 入口（init/dev/quality/build/package）；细分 CI 与维护任务使用 `just ci`。Windows 使用 Git Bash，新增入口同步文档。
- 修改系统网络前校验配置；检查外部输入边界与并发安全，不记录凭据。依赖变更检查维护状态、平台兼容性与 GPL-3.0-or-later 许可要求。
- 提交前检查 diff，仅提交本任务文件，保留用户改动；运行相关质量检查和 `just quality vet`，如实报告未验证的边界。
