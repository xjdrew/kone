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
独立用例和原始基线的失败证据见 fork 的 [复现说明](https://github.com/xjdrew/sing-tun/blob/fc4685fee0a37e59f174ad964e7b0b4b7894a251/docs/tun-creation.md)。KONE CI 另外验证 system/mixed
的真实网关、DNS/TCP/UDP 和启动/退出回滚，并对已固定的 fork 模块执行 Windows 回归。

升级时同步检查 fork 的修补是否已被上游吸收；更新固定提交后重新执行这两组 CI。
仅修改 require 的上游版本不会覆盖 replace；切回上游时必须同时删除远程 replace。

Wintun 内嵌 DLL 为官方未修改的 0.14.1 二进制，使用 [预编译二进制许可](../licenses/WINTUN.txt)。
四个架构的文件均已与 [官方压缩包](https://wintun.net/builds/wintun-0.14.1.zip) 逐字节核对，
压缩包 SHA-256 为 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`。
其他组件保留各自原始许可，二进制对应源码和依赖由 CI 源码包提供。
