# 更新说明 - 升级至 Natter (v2)


## 前言

Natter 于 2022 年创建，目前已经更新至第二代。第二代 Natter 重写了整个程序，特色功能有 Docker 的支持、自动设置内核转发等。

第二代 Natter 不再兼容先前版本，而是使用了完全不同的命令行用法；同时也也去除了一些功能，例如配置文件。Natter 多端口转发的配置，将由 Docker Compose 替代，以便更好的融合到您的 Docker 容器管理中。


## 我是否应该升级至 Natter (v2) ？

如果您的主力设备是 NAS，我们强烈建议您升级 Natter 至 v2。

总的来说，在以下情形中，您需要停留在先前版本：

- 我希望使用原有的配置文件；
- 我不想花费时间学习新的使用方法。

除此之外，您都应该升级至 Natter (v2)。


## 用法上的变化

- 第一代 Natter：

    先前版本的 Natter 多数场景需要依赖 OpenWrt 的端口转发功能，因此需要安装在 OpenWrt 中。

    ```
    服务器 <------> OpenWrt 路由器 (Natter) <---运营商 NAT---> 互联网
    ```

- 第二代 Natter：

    第二代 Natter 具有内置转发，因此可以下移部署至服务器上，而路由器仅需全端口转发（设置 DMZ 主机）至服务器即可。
  
    ```
    服务器 (Natter) <---DMZ 主机---> 普通路由器 <---运营商 NAT---> 互联网
    ```


## 命令上的变化

第二代 Natter 不再兼容先前版本 Natter 的命令行用法。

请使用以下命令查看命令行帮助，或者参考 [参数说明](../docs/usage.md) ：

```
python3 natter.py --help
```

下面是一些常用命令的对照：

### 启用测试 HTTP 服务器

 - 第一代 Natter：

    ```bash
    python natter.py -t 3456
    ```

 - 第二代 Natter：

    ```bash
    python natter.py -m test -b 3456
    ```

### 仅打洞

 - 第一代 Natter：

    ```bash
    python natter.py 3456
    ```

 - 第二代 Natter：

    ```bash
    python natter.py -m none -b 3456
    ```

### 检查 NAT 类型

 - 第一代 Natter：

    ```bash
    python natter.py --check-nat
    ```

 - 第二代 Natter：

    ```bash
    python natter-check.py
    ```
