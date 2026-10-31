module github.com/xjdrew/kone

go 1.27.3

require (
	github.com/miekg/dns v1.1.73
	github.com/pelletier/go-toml/v2 v2.4.3
	github.com/sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1
	github.com/sagernet/sing v0.8.12-0.20260717023913-84ab32b56cb8
	github.com/sagernet/sing-shadowsocks2 v0.2.2-0.20260929152114-a69d1086332b
	github.com/sagernet/sing-tun v0.9.7-0.20261023115432-040db71fcd33
	github.com/stretchr/testify v1.12.1
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
)

require (
	github.com/florianl/go-nfqueue/v2 v2.1.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.6.0 // indirect
	github.com/sagernet/fswatch v0.1.2 // indirect
	github.com/sagernet/netlink v0.0.0-20240612041022-b9a21c07ac6a // indirect
	github.com/sagernet/nftables v0.3.0-mod.4 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)

replace github.com/sagernet/sing-tun => github.com/xjdrew/sing-tun v0.0.0-20261031132454-fc4685fee0a3
