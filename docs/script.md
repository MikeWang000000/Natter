# Natter 通知脚本

在 NAT 1 中，不仅外部 IP 是动态的，外部端口也是动态的。

使用 Natter 对外开放端口时，Natter 可以调用通知脚本，以通知实时的外部 IP 和端口号。

Natter 设置通知脚本的参数为 `-e <path>`，映射成功时，会调用路径为 `<path>` 的脚本。  

Natter 调用脚本时，会在命令行传入五个参数：

| 参数序号 | 参数说明   | 参数格式              |
| -------- | ---------- | --------------------- |
| 1        | 传输层协议 | `tcp`, `udp` 二者之一 |
| 2        | 内部 IP    | 点分十进制 IPv4 地址  |
| 3        | 内部端口   | `1` - `65535` 的整数  |
| 4        | 外部 IP    | 点分十进制 IPv4 地址  |
| 5        | 外部端口   | `1` - `65535` 的整数  |

如果您使用 Shell 脚本，我们推荐您使用以下的代码作为开头：

```bash
#!/bin/sh

# Natter notification script arguments
protocol="$1"; private_ip="$2"; private_port="$3"; public_ip="$4"; public_port="$5"
```

这样，您便可以直接使用这五个变量，例如 `echo "${public_port}"` 。

Natter 也可以调用 Python 脚本，我们推荐您使用以下的代码作为开头：

```python
#!/usr/bin/env python3

# Natter notification script arguments
protocol, private_ip, private_port, public_ip, public_port = sys.argv[1:6]
```

这样，您便可以直接使用这五个变量，例如 `print(public_port)` 。

需要注意，通知脚本需要具有可执行权限。使用下方命令赋予脚本执行权限：

```bash
chmod a+x <通知脚本路径>
```


## 调用示例

下面将使用示例，具体说明通知脚本是如何被 Natter 调用的。

下方示例中，Natter 会将映射的实时外部 IP 和端口号通知给 `/opt/qb.sh` 脚本：

```bash
python3 natter.py -m iptables -e /opt/qb.sh
```

Natter 打洞成功，端口关系显示如下：
```
tcp://192.168.1.100:14600 <--iptables--> tcp://192.168.1.100:43910 <--Natter--> tcp://203.0.113.10:14600
```
> 注：示例中的 Natter 命令没有指定目标 IP 和端口，此时目标为本机，且目标端口与外部端口保持一致。

此时，Natter 将使用以下命令行调用 `/opt/qb.sh`

```bash
/opt/qb.sh "tcp" "192.168.1.100" "14600" "203.0.113.10" "14600"
```


## Natter 提供的实用通知脚本

Natter 仓库中包含一些已经写好的通知脚本。您只需修改脚本中的一些配置，如对应服务的 URL 等，便可直接使用。

这些实用通知脚本如下：

- [`qb.sh`](../natter-docker/qbittorrent/qb.sh)：Shell 脚本，用于更新 qBittorrent 监听端口，使其向 tracker 通告的端口号与外部端口一致；
- [`tr.sh`](../natter-docker/transmission/tr.sh)：Shell 脚本，用于更新 Transmission 监听端口，使其向 tracker 通告的端口号与外部端口一致；
- [`cf-srv.py`](../natter-docker/minecraft/cf-srv.py)：Python 脚本，用于更新 Cloudflare 域名的 A 记录和 SRV 记录，使得 Minecraft 等服务可通过域名直接访问。
- [`cf-redir.py`](../natter-docker/nginx-cloudflare/cf-redir.py)：Python 脚本，用于实现 Cloudflare 的跳转功能，使得直接访问域名即可动态跳转到目标端口。
