# Cloudflare-origin

此目录为在 Docker 中使用 Natter 的一个示例。

本示例可以运行 Natter 容器将指定端口映射至公网并解析到 cloudflare，同时使用 CloudFlare 的回源规则(origin-rules)实现域名隐藏端口号访问。


## 使用前

- 您的域名需已加入 CloudFlare

- 修改 `cf-origin.py` 中的相关参数：
    - `cf_domains` 修改为实现隐藏端口号的域名。
    - `cf_origin_rule_descriptions` 回源规则的描述, 英文字符。
    - `cf_origin_rule_expressions` 回源规则表达式, 不清楚如何编写可以通过 cf 控制台的origin-rules编辑页面建立规则后复制过来。
    - `cf_auth_email` 值修改为您的 CloudFlare 邮箱。
    - `cf_auth_key` 值修改为您的 CloudFlare API Key。获取方式：
        - 登录 [CloudFlare](https://dash.cloudflare.com/)
        - 进入 [https://dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
        - 点击 **Global API Key** 右侧「查看」按钮
- `cf_domains` `cf_origin_rule_descriptions` `cf_origin_rule_expressions` 可以添加多条参数
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

### 需要暴露的端口号

修改 `natter-cf-origin:` 部分：

```yaml
command: -e /opt/cf-origin.py -p 80 -r
```

将 `80` 修改为需要对外访问的端口。