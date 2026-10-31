# macOS 桌面入口与验收边界

无参数管理启动与启用接管是两个动作。管理、浏览器及菜单在普通用户上下文运行，特权数据面通过独立助手和受限制的私有通道控制；菜单不自行配置 TUN、路由或 DNS。关闭浏览器不停止接管，选择退出则交给统一生命周期完成恢复。

菜单使用系统 `/usr/bin/osascript` 的 JavaScript for Automation Objective-C bridge 调用 AppKit，不增加 CGO 或第三方桌面框架。它只创建自己的 `NSStatusBar`、`NSMenu` 与 target/action 对象，不向其他应用发送 Apple Events，也不请求辅助功能权限。实现依据 [Apple 的 JXA bridge 说明](https://devstreaming-cdn.apple.com/videos/wwdc/2014/306xxjtg7uz13v0/306/306_javascript_for_automation.pdf) 和 [NSStatusItem API](https://developer.apple.com/documentation/appkit/nsstatusitem?language=objc)。

Go 父进程通过有界管道发送缓存状态和可用动作；脚本仅能返回“打开管理、启用、暂停、诊断、退出”枚举。凭据、管理令牌、代理 URL 和完整配置不经过该协议。点击动作仍由 Go 控制层处理，原生菜单不直接发网络请求。状态未知时不显示已接管，操作按钮按实际状态启停。

脚本在 WindowServer 控制台会话中创建菜单，成功后才发送 `READY`。没有桌面会话会明确返回不可用；初始化、协议或进程失败时报告原因并保留 Web 管理。父进程关闭管道后，脚本移除自己的菜单并退出；异常挂起只终止本次创建的子进程，不按名称杀死其他 `osascript`。

原生自测入口 `--self-test` 创建真实 AppKit 菜单，通过 `performActionForItemAtIndex` 验证目标/selector、动作顺序、禁用操作和退出状态，然后移除菜单。没有 WindowServer 时以固定不可用状态退出，不把 headless 跳过当作图形功能通过。Go 测试还检查有界协议、启动超时、异常断连与子进程清理；浏览器验收只证明管理 Web 的交互，不代替 AppKit 验收。

本轮代码与 CI 结果分别核对，不能在原生任务尚未完成时声称 macOS 已全部通过。实际菜单点击、锁屏/唤醒、权限对话框、独立助手授权、干净机器安装/升级/卸载仍需带桌面的 macOS 验收。发行包尚未签名或公证，系统信任限制仍然适用；没有自动安装证书、服务或开机接管。
