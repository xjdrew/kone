# sing-tun 依赖与修补

KONE 使用 [xjdrew/sing-tun](https://github.com/xjdrew/sing-tun) 的固定提交
`fc4685fee0a37e59f174ad964e7b0b4b7894a251`，通过 go.mod 的远程 replace
保留 `github.com/sagernet/sing-tun` 导入路径。仓库内不再复制 sing-tun 源码，
也不依赖开发者本机的 `../sing-tun` 目录；克隆 KONE 即可独立构建。

基线为上游 `040db71fcd33`（sing-box v1.14.4 使用的版本），避免把依赖迁移
与 dev 分支的协议栈/API 变化混在一起。修补通过 [fork PR #1](https://github.com/xjdrew/sing-tun/pull/1)
独立审查并合并到 `codex/kone-stable-base`；KONE 固定引用其合并提交。

修补内容：

1. 精确限定 PE section table 的切片长度，修复 Windows race/checkptr 崩溃。
2. Wintun session 创建失败立即释放 adapter，并保留启动和清理错误。
3. 可选 `EXP_Exclusive`：Linux 使用 IFF_TUN_EXCL，Windows 拒绝回退打开同名设备；KONE 启用此项。
4. 将 adapter API 返回的 HRESULT_FROM_WIN32 转为普通 Win32 错误，使 errors.Is 正确识别重名等错误。

fork 保留原有平台/ping CI，只补 Linux 持久 TUN 步骤和一个 Go 1.27.3 Windows
race 回归任务，包括真实 Wintun、默认复用、注入 session 失败和 PE 堆内存边界。
独立用例和原始基线的失败证据见 fork 的 [复现说明](https://github.com/xjdrew/sing-tun/blob/fc4685fee0a37e59f174ad964e7b0b4b7894a251/docs/tun-creation.md)。KONE CI 另外验证 system/gvisor/mixed
的真实网关、DNS/TCP/UDP 和启动/退出回滚，并对已固定的 fork 模块执行 Windows 回归。

升级时同步检查 fork 的修补是否已被上游吸收；更新固定提交后重新执行这两组 CI。
仅修改 require 的上游版本不会覆盖 replace；切回上游时必须同时删除远程 replace。

## 运行时协议栈与版本边界

固定提交的 [NewStack 实现](https://github.com/xjdrew/sing-tun/blob/fc4685fee0a37e59f174ad964e7b0b4b7894a251/stack.go) 具名支持 `system`、`gvisor`、`mixed`：分别为系统 TCP/sing-tun UDP、完整 gVisor TCP/UDP、系统 TCP/gVisor UDP。KONE 显式默认 `system`，避免依赖空名称的自动选择；三种模式编入同一产物，在配置中切换后重新启用接管。

上游通过 `with_gvisor` 编译标签启用 [gVisor 实现](https://github.com/xjdrew/sing-tun/blob/fc4685fee0a37e59f174ad964e7b0b4b7894a251/stack_gvisor.go)。KONE 的 just 构建、测试与发布统一提供该依赖标签，不再保留本项目的协议栈编译分支。Linux amd64/arm64/ARMv7、Windows amd64/arm64、macOS amd64/arm64 使用相同模式列表；ARMv7 也可以编译固定的 SagerNet gVisor fork，不能套用其他 gVisor 版本的架构限制。跨编译不等于 Raspberry Pi 真机吞吐或长期稳定性验收。

[sing-box 1.15 的当前文档](https://sing-box.sagernet.org/configuration/inbound/tun/#stack) 已说明改用新版 sing-tun 自有 TCP/IP 栈，并弃用其 `stack` 配置；这是更新的依赖架构，不是当前固定基线的第四种模式。本次保留已验证的设备所有权与平台修补，不顺带升级内核/API，也不将新内核的性能说明作为 KONE 的性能承诺。

Wintun 内嵌 DLL 为官方未修改的 0.14.1 二进制，使用 [预编译二进制许可](../licenses/WINTUN.txt)。
四个架构的文件均已与 [官方压缩包](https://wintun.net/builds/wintun-0.14.1.zip) 逐字节核对，
压缩包 SHA-256 为 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`。
其他组件保留各自原始许可，二进制对应源码和依赖由 CI 源码包提供。
