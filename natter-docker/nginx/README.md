# Nginx

此目录为在 Docker 中使用 Natter 的一个示例。

本示例可以运行一个 Nginx 服务器，并使用 Natter 将其端口映射至公网。


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

### 修改 Nginx 服务的端口号

本示例使用 `18888` 端口。

在 `docker-compose.yml` 中，请修改 `nginx:` 部分：

```yaml
ports:
    - "18888:80"
```

以及 `natter-nginx:` 部分：

```yaml
command: -m iptables -p 18888
```

将 `18888` 修改为其他端口。
