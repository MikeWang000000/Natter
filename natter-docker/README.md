# Natter & Docker

在 Docker 中使用 Natter ，将 Fullcone NAT (NAT 1) 中的 TCP / UDP 端口，打洞暴露至公网上。

## 准备工作

1. 与公网 IP 操作相同，将外部流量全部转发至内网服务器上，下方为参考步骤：
   - 设置光猫为桥接模式；
   - 设置路由器「DMZ 主机」为内网服务器 IP 地址。

    拓扑参考：
    ```
    服务器 (Natter) <---DMZ 主机---> 路由器 <---桥接---> 光猫 <---运营商 NAT---> 互联网
    ```

    > 设置完成后，您可以在服务器上运行 [NatterCheck](../natter-check) 检查 NAT 类型是否满足要求。

2. 在服务器上安装 Docker ，下方使用 [清华大学开源软件镜像站](https://mirrors.tuna.tsinghua.edu.cn/help/docker-ce/) 作为参考：

    ```bash
    export DOWNLOAD_URL="https://mirrors.tuna.tsinghua.edu.cn/docker-ce"
    curl -fsSL https://get.docker.com/ | sudo -E sh
    ```

    > 需要注意，Natter 只能在 Linux 主机上的 Docker 内工作，而 Docker Desktop for Mac、Docker Desktop for Windows 等不被支持，因为它们不能使用 Host 网络。非 Linux 用户，请在主机上安装 Python 使用 Natter。

## 使用 Natter

运行 Natter ，默认会开启 HTTP 测试模式：

```bash
docker run --net=host nattertool/natter
```

使用内置转发，对外开放本机 80 端口：

```bash
docker run --net=host nattertool/natter -p 80
```

使用 iptables 内核转发（需要额外权限），对外开放本机 80 端口：

```bash
docker run \
    --net=host \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    nattertool/natter -m iptables -p 80
```


查询命令行相关帮助:

```bash
docker run --rm --net=host nattertool/natter --help
```

有关详细参数用法，参见 [参数说明](../docs/usage.md) 。


## 选择不同的 Tag

使用默认的 `latest` Tag 就可以满足绝大多数需求。以下是全部种类：

- `nattertool/natter:debian`  （等同于 `latest`。基于 Debian 系统）
- `nattertool/natter:alpine`  （基于 Alpine Linux 系统）
- `nattertool/natter:openwrt` （基于 OpenWrt 系统）
- `nattertool/natter:minimal` （不推荐。基于 OpenWrt 系统。最小体积，只能使用最基本的功能）

目前仅支持 `AMD64`（又称 `x86_64`, `x64`）和 `ARM64`（又称 `AArch64`, `ARMv8`）两种架构。


## 与其他 Docker 服务结合使用

Natter 可以和众多的 Docker 服务结合使用。本仓库提供了一些用例，可供您参考编写。

### Web 服务器

本仓库提供了以下用例，作为最基础的用法参考：  
- [Nginx](nginx)

### BT 类程序

BT 类程序的特点是，需要向 Tracker 宣告自己的端口号。  
本仓库提供了以下两种用例，可以开箱即用：  
- [qBittorrent](qbittorrent)
- [Transmission](transmission)

### 使用 SRV 记录的程序

利用更改 DNS 的 SRV 记录应对随时可能变化的外部端口号。  
本仓库提供了以下用例，需要填写您的 CloudFlare API 令牌：  
- [Minecraft](minecraft)

### 使用 HTTP 跳转服务

利用 HTTP 跳转，实时跳转到当前的外部端口的 HTTP 服务。  
本仓库提供了以下用例，需要填写您的 CloudFlare API 令牌：  
- [Nginx-CloudFlare](nginx-cloudflare)

### 使用订阅服务

利用订阅服务，及时更新外部 IP 和端口号，使用代理工具回家。  
订阅服务本身由 HTTP 跳转实现。  
本仓库提供了以下用例，需要填写您的 CloudFlare API 令牌：  
- [V2Fly-Nginx-CloudFlare](v2fly-nginx-cloudflare)
