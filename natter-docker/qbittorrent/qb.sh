#!/bin/sh

# Natter notification script arguments
protocol="$1"; private_ip="$2"; private_port="$3"; public_ip="$4"; public_port="$5"

# qBittorrent
qb_web_url="http://127.0.0.1:18080"
qb_username="admin"
qb_password="adminadmin"

echo "Update qBittorrent listening port to ${public_port}..."

qb_cookie=$(
    curl "${qb_web_url}/api/v2/auth/login" \
        -X POST -sS --include \
        -H "Referer: ${qb_web_url}" \
        --data-raw "username=${qb_username}&password=${qb_password}" \
    | grep -m1 -i '^Set-Cookie: ' | cut -c13- | tr -d '\r'
)

curl "${qb_web_url}/api/v2/app/setPreferences" \
    -X POST -sS \
    -H "Referer: ${qb_web_url}" \
    --cookie "${qb_cookie}" \
    --data-raw 'json={"listen_port":"'"${public_port}"'"}'

curl "${qb_web_url}/api/v2/auth/logout" \
    -X POST -sS \
    -H "Referer: ${qb_web_url}" \
    --cookie "${qb_cookie}"

echo "Done."
