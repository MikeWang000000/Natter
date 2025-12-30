# Natter POT 动态端口记录

在 NAT 1 中，不仅外部 IP 是动态的，外部端口也是动态的。 虽然HTTP访问可以利用规则进行302跳转从而比较方便地访问，但是对于其他类型的协议，如FTP、SSH、RDP等，就不太方便进行访问，因此需要找到一种方法，能比较方便地了解到自己服务的端口信息。

在同类开源项目Natmap中，提出了 [使用NATMap在NAT-1私网IP宽带上部署SSH服务](https://github.com/heiher/natmap/wiki/ssh)，其定义了一种叫IP4P的格式，将动态的公网IP和端口号以IP4P格式保存到DNS的AAAA记录里，从而可以通过DNS查询找到服务的IP和端口信息。

但是，使用IP4P格式保存端口信息的话，一个服务的端口号就要占用一条AAAA记录，如果有使用多个端口，会使得DNS记录里有很多AAAA记录，而这些DNS记录中指向的IP地址本质是相同的，感觉会有一点浪费资源。

而采用SRV记录的方式，有RFC规范，但是，一个域名记录也只能对应一个服务端口，并且本质上需要两条记录，一个A记录和一个SRV记录，如果本地需要暴露的服务端口比较多，也会创建很多域名记录。

为了能更方便地管理，不创建冗余的域名记录，提出使用TXT记录来保存端口信息，将这种方法叫做 POT (Port Over TXT)，以 `服务关键字_协议:端口号` 的字符串格式来保存端口号信息，例如

```bash
ssh_tcp:12345
ftp_tcp:34567
rdp_tcp:23421
```

这段数据会被编码成base64格式并存储在域名的txt记录里，转换后的值如`c3NoX3RjcDoxMjM0NQpmdHBfdGNwOjM0NTY3CnJkcF90Y3A6MjM0MjE=`，如果觉得这样不安全的话，也可以修改脚本，使用一些别的办法进行加密和解密。

在实际使用的时候，可以使用脚本查询对应服务的端口号。

这样一来，只需要一个直连域名的A记录来记录公网IP，和一个TXT记录来记录服务暴露的公网端口，


## 使用方法（以SSH为例）
### 打洞时配置通知脚本参数
```bash
python3 natter.py -e cf-redir.py -key ssh cf-service.py
```


| -key 参数序号 | 参数说明     | 参数格式                   |
|-----------|----------|------------------------|
| 1         | 服务名称     | `ssh`、`rdp` 或者你自己定义的名称 |
| 2         | 端口通知脚本路径 | 脚本路径                   |

### SSH客户端配置
SSH客户端访问的时候，需要使用ProxyCommand来运行端口解析的脚本

假设你在 [cf-aio.conf](../scripts/cf-aio.conf) 中定义直连的域名为 **direct.example.com** ，TXT记录的POT域名为 **pot.example.com**，POT 服务的名称为 **ssh**

由于采用TCP打洞的方式，因此实际使用的时候，key要改写为`ssh_tcp`


#### macOS/Linux 用户
配置SSH config如下
```bash
Host direct.example.com
    ProxyCommand ~/.ssh/potssh.sh %h
```
编辑 potssh.sh 中的
```bash
#!/bin/sh
key=ssh_tcp # 你定义的POT KEY与协议类型的组合
service_host=pot.example.com # host name for query services port

host=$1
raw=$(dig +short -t txt $service_host)
raw_formatted=$(echo $raw | sed 's/"//g')
str=$(echo $raw_formatted | base64 -d)
port=22 #default ssh port value

if grep -qiE '^$key:' <<< "$str"; then
  port=$(echo "$str" | grep '^ssh_tcp:' | cut -d ':' -f2)
fi

echo "destination port: $port"
exec nc ${host} ${port}
```

`potssh.sh` 文件需要使用`chmod a+x` 赋予权限

#### Windows用户
1. 下载并安装nmap: https://nmap.org/download.html#windows
   - 安装时要勾选 Ncat (默认是勾选的)
2. 更新powershell执行策略
以管理员权限启动 powershell 执行以下命令
```shell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
```
3. 编辑 [potssh.ps1](../scripts/pot/potssh.ps1) 脚本，配置你的key和pot域名
```bash
param(
	[string]$sshhost,
	[string]$key="ssh_tcp", # 你定义的POT KEY与协议类型的组合
	[string]$service_host="pot.example.com"
)

# 使用 Resolve-DnsName 获取 TXT 记录
$raw = (Resolve-DnsName -Name $service_host -Type TXT).Strings
$rawFormatted = $raw -replace '"', ''
$str = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($rawFormatted))
Write-Host "destination rawf: $rawFormatted"
Write-Host "destination str: $str"

$port = 22


if ($str -match '^' + $([regex]::escape($key)) + ':\s*(\d+)$') {
    $port = $Matches[1]
	Write-Host "SSH port: $port"
}

Write-Host "destination: $sshhost, port: $port"

# 使用 ncat 进行连接
ncat $sshhost $port 
```

4. 编辑ssh配置，如果你的ps1脚本不在 `.ssh` 目录，要注意修改你的ps1脚本路径
```bash
Host direct.example.com
    ProxyCommand powershell ~/.ssh/potssh.ps1 %h
```

### SSH客户端访问
连接ssh时，使用如下命令连接即可
```bash
ssh username@direct.example.com
```

---

对于其他类型的服务，也可以采用类似的方法，通过对TXT记录进行解析后得到服务的端口号后再进行访问。