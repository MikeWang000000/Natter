#!/bin/sh

# Natter notification script arguments
protocol="$1"; private_ip="$2"; private_port="$3"; public_ip="$4"; public_port="$5"

# Transmission
tr_web_url="http://127.0.0.1:9091/transmission"
tr_username="admin"
tr_password="adminadmin"

echo "Update Transmission listening port to ${public_port}..."

tr_sessid=$(
    curl "${tr_web_url}/rpc" \
        -X POST -Ss --include \
        -u "${tr_username}:${tr_password}" \
        -H "Referer: ${tr_web_url}" \
    | grep -m1 -i '^X-Transmission-Session-Id: ' | cut -c28- | tr -d '\r'
)

curl "${tr_web_url}/rpc" \
    -X POST -Ss \
    -u "${tr_username}:${tr_password}" \
    -H "X-Transmission-Session-Id: ${tr_sessid}" \
    -H "Referer: ${tr_web_url}" \
    --data-raw '{"method":"session-set","arguments":{"peer-port":'"${public_port}"'}}'

echo "Done."
