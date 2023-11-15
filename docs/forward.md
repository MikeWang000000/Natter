# 转发方法

Natter 提供多种途径，将 Natter 端口流量转发至目标端口。


## 方法对比

下表列出了不同转发方法之间的差异。

总的来说：
 - *iptables* 是最推荐的转发方法。
 - 如果您不是 Linux 用户，您可以选择 *socat*, *gost* 或者 *socket* 方法。
 - *socket* 方法，是 Natter 采用的默认转发方法。

| &nbsp;       | iptables | nftables | socat   | gost    | socket  |
| ------------ | -------- | -------- | ------- | ------- | ------- |
| 操作系统限制 | 仅 Linux | 仅 Linux | 跨平台  | 跨平台  | 跨平台  |
| 保留源 IP    | 可       | 可       | 不可    | 不可    | 不可    |
| 转发效率     | 高       | 高       | 中      | 中      | 中      |
| 转发类型     | 内核     | 内核     | 多进程  | 协程    | 多线程  |
| root 权限    | 需要     | 需要     | 无需    | 无需    | 无需    |
| 第三方依赖   | 是       | 是       | 是      | 是      | 否      |
| 依赖最低版本 | 1.4.1    | 0.9.0    | 1.7.2   | 2.3     | -       |
| 依赖最佳版本 | ≥ 1.4.20 | ≥ 1.0.6  | ≥ 1.7.2 | ≥ 2.3   | -       |


> 注：  
> 保留源 IP，转发目标所属的应用程序可以获得来访者的真实 IP 和端口；  
> 不保留源 IP，应用程序获得的 IP 地址则为 Natter 所在的 IP 地址。



## iptables 转发
[iptables](https://www.netfilter.org/projects/iptables/) 是一个用于控制 Linux 内核 netfilter 模块的命令行工具。

使用 iptables 转发，有以下四种命令行可选：
```
-m iptables -t <目标 IP> -p <目标端口>
```
```
-m iptables-snat -t <目标 IP> -p <目标端口>
```
```
-m sudo-iptables -t <目标 IP> -p <目标端口>
```
```
-m sudo-iptables-snat -t <目标 IP> -p <目标端口>
```

1. `-m iptables`

    - 使用此方法时，Natter 应当具有 root 权限，例如：`sudo python natter.py -m iptables`；
    - 此方法可保留源 IP 地址；
    - 此方法的目标 IP 具有限制，应当为 **本机** 或其 **下级主机** 的 IP 地址。

    > 注：  
    > 下级主机，指网关为 Natter 所在 IP 的主机。  
    > 例如：Natter 运行于路由器，其 LAN 口的机器均为下级；或者 Natter 运行于服务器，这台服务器上的虚拟机均为下级。

2. `-m iptables-snat`

    - 使用此方法时，Natter 应当具有 root 权限，例如：`sudo python natter.py -m iptables-snat`；
    - 此方法不保留源 IP 地址；

3. `-m sudo-iptables`

    - 使用此方法时，Natter 所在用户对于 `iptables` 具有 `sudo` 免密权限，这样 Natter 可不以 root 方式运行。
    - 除此之外，其他与 `-m iptables` 相同。

4. `-m sudo-iptables-snat`

    - 使用此方法时，Natter 所在用户对于 `iptables` 具有 `sudo` 免密权限，这样 Natter 可不以 root 方式运行。
    - 除此之外，其他与 `-m iptables-snat` 相同。

### 技术细节
使用 iptables 转发时，Natter 会在 `iptables` 中 `nat` 表内创建 `NATTER` 和 `NATTER_SNAT` 两个链：
```
-N NATTER
-N NATTER_SNAT
-A PREROUTING -j NATTER
-A INPUT -j NATTER_SNAT
-A OUTPUT -j NATTER
-A POSTROUTING -j NATTER_SNAT
```
所有规则均会创建在这两个链内。您可以通过以下命令查看具体规则：
```bash
iptables -t nat -S NATTER
```
```bash
iptables -t nat -S NATTER_SNAT
```
除了强制退出，例如 `SIGKILL`，Natter 在正常退出时均会清理相关规则。否则需要手动清理，或者重启机器让系统自动重置。


## nftables 转发

[nftables](https://www.netfilter.org/projects/nftables/) 是 iptables 的最新替代，同样适用于数据包分类等工作。

> 如果您不确定是否应使用 `-m nftables`，请使用 `-m iptables`。

使用 nftables 转发，有以下四种命令行可选：
```
-m nftables -t <目标 IP> -p <目标端口>
```
```
-m nftables-snat -t <目标 IP> -p <目标端口>
```
```
-m sudo-nftables -t <目标 IP> -p <目标端口>
```
```
-m sudo-nftables-snat -t <目标 IP> -p <目标端口>
```

相关作用请参照上文 iptables 转发部分。


## socat 转发
[socat](http://www.dest-unreach.org/socat/) 是一个开源的，由 C 语言实现的多功能中继工具。

使用 socat 转发，命令行为：
```
-m socat -t <目标 IP> -p <目标端口>
```

- `socat` 程序所在目录应当在 `PATH` 环境变量内，以便 Natter 调用；
- `socat` 使用多进程的方式维护连接，连接数不宜过多；
- 此转发方法不保留源 IP 地址。


## gost 转发
[gost](https://gost.run/) 是一个开源的，由 Go 语言实现的安全隧道。

使用 gost 转发，命令行为：
```
-m gost -t <目标 IP> -p <目标端口>
```

- `gost` 程序所在目录应当在 `PATH` 环境变量内，以便 Natter 调用；
- 此转发方法不保留源 IP 地址。


## socket 转发
[socket](https://docs.python.org/3/library/socket.html) 转发，是 Natter 基于 Python 内置 socket 库的一个简单的端口转发实现。

使用 socket 转发，命令行为：
```
-m socket -t <目标 IP> -p <目标端口>
```

- 此转发方法使用多线程的方式维护连接，连接数不宜过多；
- 此转发方法不保留源 IP 地址。
