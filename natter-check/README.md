# NatterCheck

使用 NatterCheck 检查您当前网络的 NAT 类型：

```bash
python3 natter-check.py
```

或者使用 Docker：

```bash
docker run --rm --net=host nattertool/check
```

两项指标均显示 OK ，表示您当前使用的网络可以正常使用 Natter。

```
> NatterCheck v2.0.0-rc1

Checking TCP NAT...                  [   OK   ] ... NAT Type: 1
Checking UDP NAT...                  [   OK   ] ... NAT Type: 1
```
