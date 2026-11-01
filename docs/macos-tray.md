# macOS 桌面入口与验收边界

打开 `Kone.app` 默认只显示菜单栏图标，不弹终端、不自动打开浏览器；选择“打开管理”后配置并启用接管。终端使用独立的 `kone-cli`。无参数管理启动与启用接管是两个动作，Web profile 不读取项目 `config.toml`；首次需核对 TUN 入站、出站与规则，见 [桌面指南](desktop.md)。管理、浏览器及菜单在普通用户上下文运行，特权数据面通过独立助手和受限制的私有通道控制；菜单不自行配置 TUN、路由或 DNS。关闭浏览器不停止接管，选择退出则交给统一生命周期完成恢复。

菜单使用系统 `/usr/bin/osascript` 的 JavaScript for Automation Objective-C bridge 调用 AppKit，不增加 CGO 或第三方桌面框架。它只创建自己的 `NSStatusBar`、`NSMenu` 与 target/action 对象，不向其他应用发送 Apple Events，也不请求辅助功能权限。实现依据 [Apple 的 JXA bridge 说明](https://devstreaming-cdn.apple.com/videos/wwdc/2014/306xxjtg7uz13v0/306/306_javascript_for_automation.pdf) 和 [NSStatusItem API](https://developer.apple.com/documentation/appkit/nsstatusitem?language=objc)。

Go 父进程通过有界管道发送缓存状态和可用动作；脚本仅能返回“打开管理、启用、暂停、诊断、退出”枚举。凭据、管理令牌、代理 URL 和完整配置不经过该协议。点击动作仍由 Go 控制层处理，原生菜单不直接发网络请求。“诊断”会直接打开管理页的诊断页面，不会自动发起探测。状态未知时不显示已接管，操作按钮按实际状态启停。

脚本实际尝试创建 AppKit 菜单，检查显示环境、状态项和按钮，成功后才发送 `READY`。不因会话属性预先跳过全部图形能力。没有可用桌面时明确返回不可用；GUI 无法维持菜单时显示启动提示并退出，避免留下没有入口的后台进程，CLI 管理可继续使用已有浏览器入口。普通用户启动可尝试菜单入口，管理员进程不创建桌面菜单。

菜单启用或暂停接管失败会显示安全的原生提示并打开 Web 诊断；错误写入有界脱敏运行日志，管理服务保留。成功操作不会强制打开页面。权限助手或流量数据暂不可用与管理连接中断分别显示。

长驻阶段使用 `NSApplication` 事件循环和 `NSTimer` 读取有界状态管道，由 AppKit 管理每轮临时对象。管道 EOF 时停止计时器、恢复描述符标志、移除自己的状态项并退出；输入错误也先完成同样的清理。异常挂起只终止本次创建的子进程，不按名称杀死其他 `osascript`。

原生自测入口 `--self-test` 创建真实 AppKit 菜单，通过 `performActionForItemAtIndex` 验证目标/selector、动作顺序、禁用操作和退出状态，然后移除菜单。没有 WindowServer 时以固定不可用状态退出，不把 headless 跳过当作图形功能通过。Go 测试还检查有界协议、启动超时、异常断连与子进程清理；浏览器验收只证明管理 Web 的交互，不代替 AppKit 验收。

历史原生 macOS CI 已实际通过菜单 selector/状态自测和 UTF-8 状态管道 EOF 清理，两项均未跳过；管理员助手的真实私有通道、正常停止和断连清理，以及当时 system/mixed 的 UTUN TCP/UDP 往返与失败回滚也已通过。可核对 [原生菜单与助手验证记录](https://github.com/xjdrew/kone/actions/runs/41233263296/job/124631668985) 和 [UTUN 验证记录](https://github.com/xjdrew/kone/actions/runs/41233263296/job/124631669146)。当前三栈与合并后的平台任务必须查看新 SHA 的执行结果，不能把旧证据当作 gvisor 验收。权限边界见 [macOS 网络助手](macos-helper.md)。

实际鼠标菜单交互、锁屏/唤醒、管理员权限对话框、干净机器安装/升级/卸载仍需带桌面的 macOS 验收。发行包尚未签名或公证，系统信任限制仍然适用；没有自动安装证书、服务或开机接管。
