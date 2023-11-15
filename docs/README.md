# Natter

将 fullcone NAT (NAT 1) 后的端口，打洞暴露至互联网。

*注意：Natter 2.0 重写了整个程序，并不兼容先前版本的命令行用法。详见 [更新说明](upgrade.md) 。*


## 快速开始

```bash
python3 natter.py
```

或者, 使用 Docker:

```bash
docker run --net=host nattertool/natter
```

```
2023-11-01 01:00:08 [I] Natter v2.0-dev
2023-11-01 01:00:08 [I] Tips: Use `--help` to see help messages
2023-11-01 01:00:12 [I]
2023-11-01 01:00:12 [I] tcp://192.168.1.100:13483 <--Natter--> tcp://203.0.113.10:14500
2023-11-01 01:00:12 [I]
2023-11-01 01:00:12 [I] Test mode in on.
2023-11-01 01:00:12 [I] Please check [ http://203.0.113.10:14500 ]
2023-11-01 01:00:12 [I]
2023-11-01 01:00:12 [I] LAN > 192.168.1.100:13483   [ OPEN ]
2023-11-01 01:00:12 [I] LAN > 192.168.1.100:13483   [ OPEN ]
2023-11-01 01:00:12 [I] LAN > 203.0.113.10:14500    [ OPEN ]
2023-11-01 01:00:13 [I] WAN > 203.0.113.10:14500    [ OPEN ]
2023-11-01 01:00:13 [I]
```

上述例子中, `203.0.113.10` 是您 NAT 1 外部的公网 IP 地址。Natter 打开了 TCP 端口 `203.0.113.10:14500` 以供测试。

在局域网外访问 `http://203.0.113.10:14500` ，您可以看到如下网页:

```
It works!

--------
Natter
```


## 使用方法

- 详见 [参数说明](usage.md) 。
- 有关转发方法，详见 [转发方法](forward.md) 。
- 有关通知脚本，详见 [Natter 通知脚本](script.md) 。

```
usage: natter.py [--version] [--help] [-v] [-q] [-u] [-k <interval>]
                 [-s <address>] [-h <address>] [-e <path>] [-i <interface>]
                 [-b <port>] [-m <method>] [-t <address>] [-p <port>] [-r]

Expose your port behind full-cone NAT to the Internet.

options:
  --version, -V   show the version of Natter and exit
  --help          show this help message and exit
  -v              verbose mode, printing debug messages
  -q              exit when mapped address is changed
  -u              UDP mode
  -k <interval>   seconds between each keep-alive
  -s <address>    hostname or address to STUN server
  -h <address>    hostname or address to keep-alive server
  -e <path>       script path for notifying mapped address

bind options:
  -i <interface>  network interface name or IP to bind
  -b <port>       port number to bind

forward options:
  -m <method>     forward method, common values are 'iptables', 'nftables',
                  'socat', 'gost' and 'socket'
  -t <address>    IP address of forward target
  -p <port>       port number of forward target
  -r              keep retrying until the port of forward target is open
```


## Docker 使用方法

详见 [natter-docker](../natter-docker) 。


## 使用例

使用内置转发，对外开放本机 80 端口：

```bash
python3 natter.py -p 80
```

使用 iptables 内核转发（需要 root 权限），对外开放本机 80 端口：

```bash
sudo python3 natter.py -m iptables -p 80
```


## 依赖

- Python 2.7 (最低), >= 3.6 (推荐)
- 不需要安装第三方模块。


## 许可证

GNU General Public License v3.0
