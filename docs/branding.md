# KONE 图标

图标以 K1 表盘为意象：深色底、浅色圆环和 K 形指针，金色指针表示流量的方向。它表达稳定引导网络流量的寓意；SVG 为项目自行绘制，不使用第三方商标素材。

主图源文件为 [icon.svg](../web/public/icon.svg)，托盘使用 [tray.svg](../web/native/tray.svg)。Web 图标、Windows ICO/程序资源、macOS ICNS 和托盘资源由同一套生成流程维护：

```sh
just ci icons generate
just ci icons check
```

修改源图后重新生成并提交对应资源；`check` 检查已提交资源与源图一致。日常构建复用生成结果，不需要手工编辑二进制图标。平台图标、托盘和 Web 使用一致的视觉含义；窗口系统的缓存可能使刚替换的程序暂时显示旧图标。
