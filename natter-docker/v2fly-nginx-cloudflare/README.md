# V2Fly-Nginx-CloudFlare

此目录为在 Docker 中使用 Natter 的一个示例。

本示例使用 V2Fly 核心运行一个 VMess 服务器，并使用 Natter 将其端口映射至公网，外部设备可通过 VMess 协议接入内网。同时，参考 [Nginx-CloudFlare](../nginx-cloudflare) 建立一个 Web 服务，提供订阅信息，以便动态更新 IP 地址和端口。


## 使用前

- 您的域名需已加入 CloudFlare

- 修改 `cf-redir.py` 中的相关参数：
    - `cf_redirect_to_https` 值保持不变。
    - `cf_redirect_host` 值修改为您的“跳转域名”，访问该域名会跳转到“直连域名:动态端口号”。该域名将作为订阅链接的域名。
    - `cf_direct_host` 值修改为您的“直连域名”，该域名指向您的动态 IP 地址。
    - `cf_auth_email` 值修改为您的 CloudFlare 邮箱。
    - `cf_auth_key` 值修改为您的 CloudFlare API Key。获取方式：
        - 登录 [CloudFlare](https://dash.cloudflare.com/)
        - 进入 [https://dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
        - 点击 **Global API Key** 右侧「查看」按钮

- 修改 `config.json` 中的 `id` 值：
    - 生成一个 UUID ，替换配置中默认的 `11111111-1111-1111-1111-111111111111`

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

客户端配置：

假设 `cf_redirect_host` 的值为 `redirect.example.com`，客户端 ID 设置为 `11111111-1111-1111-1111-111111111111`。

该示例提供两种订阅地址，URL 为：
```
http://redirect.example.com/11111111-1111-1111-1111-111111111111.txt
```
```
http://redirect.example.com/11111111-1111-1111-1111-111111111111.yml
```

请选择客户端支持的一种订阅格式，将 URL 输入至客户端订阅列表中。


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

### 修改 V2Fly 服务的端口号

本示例使用 `19999` 端口。

在 V2Fly 配置 `config.json` 中，请修改 `"inbounds":` 部分：

```json
"port": 19999,
```

并修改 `docker-compose.yml` 中的 `natter-v2fly:` 部分：

```yaml
command: -m iptables -e /opt/v2subsc.py -p 19999
```

将 `19999` 修改为其他端口。
