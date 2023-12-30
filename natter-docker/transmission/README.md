# Transmission

此目录为在 Docker 中使用 Natter 的一个示例。

本示例可以运行 Transmission 进行 BT 下载或做种，并使用 Natter 将其端口映射至公网。


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

Web 后台地址（请将 127.0.0.1 替换为当前主机 IP 地址）：
```
http://127.0.0.1:9091/
```


## 修改参数

### 修改 Transmission 的用户名和密码

在 `docker-compose.yml` 中，请修改 `transmission:` 部分：

```yaml
environment:
    - USER=admin
    - PASS=adminadmin
```

并修改通知脚本 `tr.sh`：

```bash
tr_username="admin"
tr_password="adminadmin"
```

将用户名 `admin` 和密码 `adminadmin` 修改为您所想要设置的值。

### 修改 Transmission 的 Web 端口号

本示例使用 `9091` 端口。

容器停止运行时，修改 Transmission 配置文件 `config/settings.json`：

```json
"rpc-port": 9091,
```

并修改通知脚本 `tr.sh`：

```bash
tr_web_url="http://127.0.0.1:9091/transmission"
```

将 `9091` 修改为其他端口。
