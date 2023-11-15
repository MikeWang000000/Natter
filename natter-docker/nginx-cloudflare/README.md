# Nginx-CloudFlare

此目录为在 Docker 中使用 Natter 的一个示例。

本示例可以运行一个 Nginx 服务器，使用 Natter 将其端口映射至公网，并使用 CloudFlare 动态跳转。


## 使用前

- 您的域名需已加入 CloudFlare

- 修改 `cf-redir.py` 中的相关参数：
    - `cf_redirect_to_https` 值保持不变。
    - `cf_redirect_host` 值修改为您的“跳转域名”，访问该域名会跳转到“直连域名:动态端口号”。
    - `cf_direct_host` 值修改为您的“直连域名”，该域名指向您的动态 IP 地址。
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

### 修改 Nginx 服务的端口号

本示例使用 `18888` 端口。

在 `docker-compose.yml` 中，请修改 `nginx:` 部分：

```yaml
ports:
    - "18888:80"
```

以及 `natter-nginx:` 部分：

```yaml
command: -m iptables -e /opt/cf-redir.py -p 18888
```

将 `18888` 修改为其他端口。
