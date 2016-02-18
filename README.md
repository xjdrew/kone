# KONE
K1 (K1 chronometer made by Larcum Kendall)

# documents
[tun](https://www.kernel.org/doc/Documentation/networking/tuntap.txt)
[Tun/Tap interface tutorial](http://backreference.org/2010/03/26/tuntap-interface-tutorial/)

# tun
```
# create/delete tun
$ ip tuntap add dev tun0 mode tun
$ ip tuntap del dev tun0 mode tun

# up/down tun
$ ip link set tun0 up
$ ip link set tun0 down

# alloc ip
$ ip addr add 10.0.0.1/24 dev tun0

```

