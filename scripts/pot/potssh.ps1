param(
	[string]$sshhost,
	[string]$key="ssh_tcp",
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