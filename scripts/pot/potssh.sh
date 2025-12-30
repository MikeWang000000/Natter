#!/bin/sh
key=ssh_tcp # your service key
service_host=pot.example.com # host name for query services port

host=$1
raw=$(dig +short -t txt $service_host)
raw_formatted=$(echo $raw | sed 's/"//g')
str=$(echo $raw_formatted | base64 -d)
port=22 #default ssh port value

if grep -qiE "^$key:" <<< "$str"; then
  port=$(echo "$str" | grep '^ssh_tcp:' | cut -d ':' -f2)
fi

echo "destination port: $port"
exec nc ${host} ${port}