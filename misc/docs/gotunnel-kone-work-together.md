# gotunnel和kone的珠联璧合


## 分工
  * [gotunnel]( https://github.com/xjdrew/gotunnel )负责打通内外，创建一个可用的proxy通道，当然，创建通道需要配合squid/ATS等传统proxy软件
  * kone负责做路由转发，实现透明xx

## 流程
一个典型的流程是这样的:
  * 首先在长城墙外申请一个XX云/linode之类的VPS，我们称为梯子的落点
  * 然后在国内的XX云也申请一个VPS，我们称为梯子的起点
  * 选择梯子的起点和落点，需要保证起点和落点之间的ping值质量要高，举个栗子，起点选择XX云的杭州节点，落点选择同一家公司的新加坡节点，因为是同一家公司的VPS，所以它们不同节点之间的网络质量还是有保证的
  * 有人会问，梯子起点能选择自己公司或者家里的网络出口吗？可以当然是可以，但到梯子落点的网络质量难以保证，而且容易被监控，选择服务商的VPS做起点，一来可以撇清关系，二来可以随时更换VPS，是不是更好？
  * 在梯子落点安装squid/ATS，在梯子起点与落点之间使用gotunnel搭建一条通道，通道最终指向squid/ATS，具体方法可参考[gotunnel](https://github.com/xjdrew/gotunnel)上的说明
  * 如果要更加安全，可以从公司或者家里的出口，也使用gotunnel做一条通道到梯子的起点
```
    [home/office] ---gotunnel---> [梯子起点] ---gotunnel--->  [梯子落点] ----> squid/ATS
```
  * 最后按照 [在一个200人的企业中使用kone](./kone-in-ent-network.md)提供的方法，把需要xx的流量都转到这条proxy通道上即可
  * 除了使用kone的dns欺骗功能实现xx，更好的做法是在网关上启用策略路由，把需要xx的IP地址池全部指向kone创建的虚拟口tun0，这样流程会更加干净，而且对所有用户都是透明的，做法如下：kone启动，创建虚拟口tun0，虚拟地址为10.19.0.1，然后跑以下脚本
```
#!/bin/bash

####在策略路由中创建一个名为fanqiang的路由链，路由指向为tun0
ip route delete default dev tun0 table fanqiang
ip route add default dev tun0 table fanqiang

#### 删除原来的fanqiang链中的策略
ip rule show | egrep "lookup fanqiang" | awk '{print $5}' | sort | uniq  > /etc/fanqiang_del.list
for i in `cat /etc/fanqiang_del.list`
do
    ip rule delete to ${i} table fanqiang
done

####重新生成一次fanqiang路由链
for p in `cat /etc/fanqiang.list` ##fanqiang.list为平时收集的需要xx的IP段
do
    ip rule add to ${p} table fanqiang pref 77 ##fanqiang链的优先级设定为77，自行调配
done

####刷新一次策略路由使其生效
ip route flush cache
```

  * 附上收集的需要xx的2000多个IP段[fanqiang.list]( ./fanqiang.list ) ，和久经考验的[squid.conf]( ./squid.conf )

