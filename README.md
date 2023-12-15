
# KONE
The project aims to improve the experience of accessing internet in home/enterprise network.

The name "KONE" comes from [k1](https://en.wikipedia.org/wiki/Larcum_Kendall#K1), a chronometer made by Larcum Kendall and played a important role in Captain Cook's voyage.

By now, it supports:

* linux
* macosx
* windows (8 / Server 2012 and above)

## Use

```bash
go build ./cmd/kone
sudo ./kone -debug -config cmd/kone/test.ini
```
For more information, please read [test.ini](./cmd/kone/test.ini).

## Web Status
The default web status port is 9200 , just visit http://localhost:9200/ to check the kone status.

<img src=./misc/images/kone_webui.png border=0>

## Documents
* [how to use with Raspberry Pi (在树莓派上使用kone)](./misc/docs/how-to-use-with-raspberry-pi.md)
* [how to use kone in an ENT network (企业网中如何使用kone)](./misc/docs/kone-in-ent-network.md)
* [how to make gotunnel & kone work together(gotunnel和kone的珠联璧合)](./misc/docs/gotunnel-kone-work-together.md)

## License
The MIT License (MIT) Copyright (c) 2016 xjdrew

## todo
- [ ] upgrade to surge like config
- [ ] default hijack dns query
- [ ] show process name of network
