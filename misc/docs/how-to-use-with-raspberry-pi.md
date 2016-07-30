# 在树莓派上使用kone

kone完全基于go语言开发，需要依赖linux 2.2.x以上内核版本。从go1.6开始，go官方提供ARMv6架构的预编译安装包，使得在树莓派上部署go程序非常方便。

## 硬件需求

1. 需要一个可以更改静态路由的路由器。

   普通的非智能路由器，如[tp-link](http://service.tp-link.com.cn/detail_article_28.html)之类，都有这个功能。反而智能路由器，如小米、极路由之类没有开放这个功能。如果你的路由器恰好没有这个功能，那你可以把树莓派改造成路由器，不过这种方法不在这篇文档讨论:-)

2. 树莓派可以正常使用互联网。假设树莓派的局域网ip地址是: 192.168.10.101

## 软件安装

* 在树莓派上安装go

目前最新版本的go是[go1.6.3](https://storage.googleapis.com/golang/go1.6.3.linux-armv6l.tar.gz)。

安装方法参考这个文档: https://golang.org/doc/install

安装成功后，运行如下命令检查：
```bash
$ go version
go version go1.6.3 linux/armv6l
```

* 编译kone

kone是一个普通的go程序，简单说就是```go get -t github.com/xjdrew/kone```

## 配置树莓派

* 把树莓派设置成路由模式(需要切换到root用户)

```
echo 1 > /proc/sys/net/ipv4/ip_forward
```

## 配置并启动kone

* 修改kone的配置文件

在代码目录```misc/example/example.ini```，提供了一份默认配置文件。
为了简化问题，只需要把默认配置文件拷贝到合适的目录，命名为```my.ini```，然后把```[proxy "A"]```配置项下的url改成你拥有的代理，目前支持http, socks5代理。

```
[proxy "A"]
url = http://example.com:3228 # 修改成你的代理，支持http, socks5
default = yes
```

* 启动kone

```
sudo ./kone my.ini &
```

## 配置路由器
* 配置静态路由

在路由器上添加一条静态路由：

目的IP地址 | 子网掩码    | 网关           | 状态 
---------- | ----------- | -------------- | ----
10.192.0.0 | 255.255.0.0 | 192.168.10.101 | 生效

* 修改默认dns

把路由器的默认dns修改为：10.192.0.1

tp-link 路由器的修改参考这里：http://service.tp-link.com.cn/detail_article_575.html

## 测试

取消手机的所有代理，使用wifi加入局域网，如果你提供的代理可以访问google，那么手机应该可以直接访问google.com

## 故障定位

1. 使用tcpdump在树莓派上抓包，看看dns请求是不是到了树莓派
2. 启动kone时加上```-debug```选项，查看打印日志
```
sudo ./kone -debug my.ini
```

## 还有问题?

提issue

