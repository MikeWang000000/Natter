# qBittorrent

此目录为在 Docker 中使用 Natter 的一个示例。

本示例可以运行 qBittorrent 进行 BT 下载或做种，并使用 Natter 将其端口映射至公网。


## 使用前

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

### 修改 qBittorrent 的用户名和密码

您可以直接在 qBittorrent 的 Web 页面中修改用户名和密码。

完成后，修改通知脚本 `qb.sh`：

```bash
qb_username="admin"
qb_password="adminadmin"
```

将用户名 `admin` 和密码 `adminadmin` 修改为您设置的新用户名和密码。

### 修改 Transmission 的 Web 端口号

本示例使用 `18080` 端口。

在 `docker-compose.yml` 中，请修改 `qbittorrent:` 部分：

```yaml
environment:
    - WEBUI_PORT=18080
```

并修改通知脚本 `qb.sh`：

```bash
qb_web_url="http://127.0.0.1:18080"
```

将 `18080` 修改为其他端口。
