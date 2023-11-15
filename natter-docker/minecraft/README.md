# Minecraft

此目录为在 Docker 中使用 Natter 的一个示例。

本示例可以运行一个 Minecraft 服务端，使用 Natter 将其端口映射至公网，并使用 CloudFlare 动态更新 A 记录和 SRV 记录。

动态更新的 A 记录保存了您的 IP 地址，SRV 保存了您 Minecraft 服务端的端口号。这样您就可以直接使用域名登录 Minecraft 服务器，而不用指定 IP 地址和端口号。


## 使用前

- 您的域名需已加入 CloudFlare

- 修改 `cf-srv.py` 中的相关参数：
    - `cf_srv_service` 值保持不变。
    - `cf_domain` 值修改为您想要设置的二级域名。
    - `cf_auth_email` 值修改为您的 CloudFlare 邮箱。
    - `cf_auth_key` 值修改为您的 CloudFlare API Key。获取方式：
        - 登录 [CloudFlare](https://dash.cloudflare.com/)
        - 进入 [https://dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
        - 点击 **Global API Key** 右侧「查看」按钮

- 使用 `cd` 命令进入此目录


## 开始使用

前台运行：
```bash
docker compose up
```

后台运行：
```bash
docker compose up -d
```

查看日志：
```bash
docker compose logs -f
```

结束运行：
```bash
docker compose down
```


## 修改参数

### 修改 Minecraft 服务的端口号

本示例使用 `25565` 端口。

在 `docker-compose.yml` 中，请修改 `minecraft-server:` 部分：

```yaml
ports:
    - "25565:25565"
```

以及 `natter-mc:` 部分：

```yaml
command: -m iptables -e /opt/cf-srv.py -p 25565 -r
```

将 `25565` 修改为其他端口。
