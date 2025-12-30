# CloudFlare All In One 脚本使用说明
CloudFlare All In One 脚本（以下简称aio脚本）整合了 `cf-srv.py` 和 `cf-redir.py` 脚本的能力，并加入了 POT ( Port Over TXT )的记录能力，关于 POT, 可以参考详细使用参考 [Natter POT 动态端口记录](pot.md) 。

aio脚本匹配natter的通知逻辑，接收5个参数，分别为 [**protocol**] [**local_ip**] [**local_port**] [**remote_ip**] [**remote_port**]，其他域名、密钥等信息保存在配置中

aio脚本使用配置文件来决定上传的行为，***配置文件应存放在脚本的同级目录***，配置文件名固定为 **cf-aio.conf**

```bash
scripts % ls -l
total 64
-rw-r--r--  1 natter  staff    305  8 10 12:01 cf-aio.conf
-rwxr-xr-x  1 natter  staff  17464  8 10 12:10 cf-aio.py
```

## 配置文件格式
```json
{
    "cf_email":"email@example.com",
    "cf_key":"d41d8cd98f00b204e9800998ecf8427e",
    "direct_host":"direct.example.com",
    "redirect_to_https":false,
    "redirect_host":null,
    "srv_host":null,
    "srv_name":"_minecraft",
    "pot_service_host":null,
    "pot_service_key":"ssh"
}
```

## 配置含义

| 参数                  | 说明                                | 值类型   | 强关联参数                             |
|---------------------|-----------------------------------|-------|-----------------------------------|
| ***必选项：***          |                                   |       |                                   |
| `cf_email`          | CloudFlare 登录邮箱                   | 字符串   | /                                 |
| `cf_key`            | 打印此帮助并退出                          | 字符串   | /                                 |
| ***自定义选项：***        |                                   |       |                                   |
| `direct_host`       | 配置 CloudFlare 的直连域名，代表你的公网IP      | 字符串或空 | /                                 |
| `redirect_to_https` | 配置 CloudFlare 跳转时是否强制 HTTPS       | 布尔值或空 | `redirect_to_host`                |
| `redirect_host`     | 配置 CloudFlare 跳转时是否强制 HTTPS       | 字符串或空 | `direct_host`、`redirect_to_https` |
| `srv_host`          | 配置 CloudFlare SRV 记录的域名           | 字符串或空 | `srv_name`                         |
| `srv_name`          | 配置 SRV 的服务名称                      | 字符串或空 | `srv_host`                        |
| `pot_service_host`  | 配置 CloudFlare TXT记录，用于记录 POT 服务端口 | 字符串或空 | `direct_host`、`pot_service_key`   |
| `pot_service_key`   | 配置 POT 的服务关键字                     | 字符串或空 | `direct_host`、`pot_service_host`  |

如果需要的配置有强关联参数，则强关联的参数变为必选，不可以为空