
![github workflow](https://github.com/xjdrew/kone/actions/workflows/go.yml/badge.svg)
[![codecov](https://codecov.io/gh/xjdrew/kone/graph/badge.svg?token=cGQLHTtaVc)](https://codecov.io/gh/xjdrew/kone)
# KONE
The project aims to improve the experience of accessing internet in home/enterprise network.

The name "KONE" comes from [k1](https://en.wikipedia.org/wiki/Larcum_Kendall#K1), a chronometer made by Larcum Kendall and played a important role in Captain Cook's voyage.

By now, it supports:

* linux
* macosx
* windows (10 and above) （refer to [use kone in windows](./misc/windows/README.md) for more information)

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
* [how to use with Raspberry Pi](./misc/docs/how-to-use-with-raspberry-pi.md)
* [how to use kone in an ENT network](./misc/docs/kone-in-ent-network.md)
* [how to make gotunnel & kone work together](./misc/docs/gotunnel-kone-work-together.md)

## License
The MIT License (MIT) Copyright (c) 2016 xjdrew
