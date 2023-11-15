#!/usr/bin/env python3
import base64
import json
import sys
import re

# Natter notification script arguments
protocol, private_ip, private_port, public_ip, public_port = sys.argv[1:6]

v2ray_json_template = '{"v":"2","ps":"Home","add":"{{public_ip}}","port":"{{public_port}}","id":"{{client_id}}","type":"none","aid":"0","net":"tcp"}'

clash_template = '''\
mode: rule
proxies:
  - name: Home
    type: vmess
    server: {{public_ip}}
    port: {{public_port}}
    uuid: {{client_id}}
    alterId: 0
    cipher: auto
    mux: true
proxy-groups:
  - name: GoHome
    type: select
    proxies:
      - Home
rules:
  - IP-CIDR,10.0.0.0/8,GoHome,no-resolve
  - IP-CIDR,172.16.0.0/12,GoHome,no-resolve
  - IP-CIDR,192.168.0.0/16,GoHome,no-resolve
  - MATCH,DIRECT
'''


def main():
    config_path = "/etc/v2ray/config.json"
    client_id = get_client_id(config_path)

    v2ray_subsc_path = f"/usr/share/nginx/html/{client_id}.txt"
    write_v2ray_subscription(v2ray_subsc_path, v2ray_json_template, public_ip, public_port, client_id)
    print(f"V2ray subscription [{client_id}.txt] written successfully")

    clash_subsc_path = f"/usr/share/nginx/html/{client_id}.yml"
    write_clash_subscription(clash_subsc_path, clash_template, public_ip, public_port, client_id)
    print(f"Clash subscription [{client_id}.yml] written successfully")


def get_client_id(config_path):
    with open(config_path, "r") as fin:
        conf = json.load(fin)
    vmess_conf = None
    for inb in conf["inbounds"]:
        if inb.get("protocol") == "vmess":
            if not vmess_conf:
                vmess_conf = inb
            else:
                raise ValueError("Multiple vmess inbounds are found")
    if vmess_conf and vmess_conf.get("settings") and vmess_conf["settings"].get("clients"):
        client_conf = vmess_conf["settings"]["clients"][0]
        client_id = client_conf["id"]
    else:
        raise ValueError("No vmess client ID is found")
    client_id = str(client_id)
    if not re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", client_id):
        raise ValueError(f"Invalid client ID: {client_id}")
    return client_id


def write_clash_subscription(subsc_path, clash_template, public_ip, public_port, client_id):
    clash_subsc = clash_template.replace("{{public_ip}}",   f"{public_ip}") \
                                .replace("{{public_port}}", f"{public_port}") \
                                .replace("{{client_id}}",   f"{client_id}")
    with open(subsc_path, "w") as fout:
        fout.write(clash_subsc)


def write_v2ray_subscription(subsc_path, v2ray_json_template, public_ip, public_port, client_id):
    v2ray_subsc_json = v2ray_json_template.replace("{{public_ip}}",   f"{public_ip}") \
                                          .replace("{{public_port}}", f"{public_port}") \
                                          .replace("{{client_id}}",   f"{client_id}")
    v2ray_subsc =  base64.b64encode(b"vmess://" + base64.b64encode(v2ray_subsc_json.encode()) + b"\n").decode()
    with open(subsc_path, "w") as fout:
        fout.write(v2ray_subsc)


if __name__ == "__main__":
    main()
