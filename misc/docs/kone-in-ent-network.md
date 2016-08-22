# 在一个200人的企业网中使用kone
## 准备工作
1. 企业网关服务器(4G内存，i3以上的CPU)，假设网关的IP是192.168.1.1，企业内部所有设备的default gateway都配置成192.168.1.1。当然，这台网关可能不是一台linux，而是一台商业网关服务器，只要它支持路由配置，都属于一台称职的网关服务器，本案例假设这台网关是一台标准的linux服务器。
* [PC/手机] ----> [网关192.168.1.1] -----> [Internet]

2. 一个用于翻墙的httpproxy/sock5proxy服务器。是的，kone本身并不是一个proxy实现，kone的作用只是把路由请求转发到proxy server上

##  过程
1. 检查你的httpproxy/sock5proxy是否工作正常
```
curl -x http://myproxy:2080 https://www.google.com.hk
```
2. 在网关上启动kone，配置文件参考example.ini
```
[general]
network = 10.19.0.1/16
...
[dns]
# DEFAULT VALUE: 53
# dns-port = 53
nameserver = 192.168.1.1
...
[proxy "A"]
url = http://myproxy:2080
default = yes
```
3. 查看kone是否启动成功，缺省会创建虚拟网口tun0，IP地址为10.192.0.1，同时10.192.0.1也是一个新的DNS服务器
```
>ifconfig tun0
tun0      Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  
          inet addr:10.19.0.1  P-t-P:10.19.0.1  Mask:255.255.0.0
          UP POINTOPOINT RUNNING NOARP MULTICAST  MTU:1500  Metric:1
```

4. 在PC/手机上，把DNS服务器改成10.192.0.1，dig www.google.com.hk 测试是否返回一个10.192.x.x的地址池地址，如果返回的地址正常说明kone工作正常
```
>dig www.google.com.hk @10.19.0.1                   
  ;; ANSWER SECTION:                                  
  www.google.com.hk.      600     IN      A       10.19.0.55
```    
5. 改动企业网内部的DHCPD服务器，把缺省DNS服务器改为10.19.0.1，则企业内部的设备会自动使用kone实现透明翻墙
6. 一个200人的企业网络，httpproxy/sock5proxy至少需要3M带宽可以保证google/facebook/twitter等的访问，如果需要流畅的看youtube 720P，则带宽起码需要10M
