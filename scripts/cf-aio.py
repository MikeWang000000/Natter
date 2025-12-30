#!/usr/bin/env python3
import urllib.request
import json
import sys
import base64
import os

# Natter notification script arguments
protocol, private_ip, private_port, public_ip, public_port = sys.argv[1:6]

cf_auth_email = None
cf_auth_key = None
cf_redirect_to_https = False
cf_direct_host = None
cf_redirect_host = None
cf_srv_host = None
cf_srv_name = None
cf_pot_service_host = None
cf_pot_service_key = None

# 获取当前文件的绝对路径
current_file_path = os.path.abspath(__file__)
# 获取当前文件所在的目录
current_dir = os.path.dirname(current_file_path)
# 配置文件路径
config_path = os.path.join(current_dir, "cf-aio.conf")

def main():
    queryConfiguration()
    print("email: %s, key: %s, redirect_to_https: %s, direct_host: %s, \
    redirect_host: %s, srv_host: %s, srv_name: %s ,pot_host: %s, pot_key: %s" % \
          (cf_auth_email, cf_auth_key, cf_redirect_to_https, cf_direct_host, \
           cf_redirect_host, cf_srv_host, cf_srv_name, \
           cf_pot_service_host, cf_pot_service_key))

    cf = CloudFlareApi(cf_auth_email, cf_auth_key)

    if cf_direct_host is not None:
        print(f"Setting [ {cf_direct_host} ] DNS to [ {public_ip} ] directly...")
        cf.set_a_record(cf_direct_host, public_ip, False)

    if cf_redirect_host is not None:
        print(f"Setting [ {cf_redirect_host} ] DNS to [ {public_ip} ] proxied by CloudFlare...")
        cf.set_a_record(cf_redirect_host, public_ip, True)
        if cf_direct_host is not None:
            print(f"Setting [ {cf_redirect_host} ] redirecting to [ {cf_direct_host}:{public_port} ], https={cf_redirect_to_https}...")
            cf.set_redirect_rule(cf_redirect_host, cf_direct_host, public_port, cf_redirect_to_https)

    if cf_srv_host is not None and cf_srv_name is not None:
        print(f"Setting {cf_srv_host} A record to {public_ip}...")
        cf.set_a_record(cf_srv_host, public_ip)

        print(f"Setting {cf_srv_host} SRV record to {protocol} port {public_port}...")
        cf.set_srv_record(cf_srv_host, public_port, service=cf_srv_name, protocol=f"_{protocol}")

    if cf_pot_service_key is not None and cf_pot_service_host is not None:
        service_key_combined = cf_pot_service_key + "_" + protocol
        print("service_key_combined: " + service_key_combined)
        print(f"Setting service [ {service_key_combined} ] port to [ {public_port} ] into [ {cf_pot_service_host} ] TXT record on CloudFlare...")
        cf.set_txt_record(cf_pot_service_host, service_key_combined, public_port)

def queryConfiguration():
    config = None
    print("config path: %s" % config_path)
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
    except FileNotFoundError as e:
        print(e)
    if config is None:
        print("config not found, exit")
        exit(1)

    global cf_auth_email
    global cf_auth_key
    global cf_redirect_to_https
    global cf_direct_host
    global cf_redirect_host
    global cf_srv_host
    global cf_srv_name
    global cf_pot_service_host
    global cf_pot_service_key

    cf_auth_email = config.get("cf_email", None)
    cf_auth_key = config.get("cf_key", None)
    cf_redirect_to_https = config.get("redirect_to_https", False)
    cf_direct_host = config.get("direct_host", None)
    cf_redirect_host = config.get("redirect_host", None)
    cf_srv_host = config.get("srv_host", None)
    cf_srv_name = config.get("srv_name", None)
    cf_pot_service_host = config.get("pot_service_host", None)
    cf_pot_service_key = config.get("pot_service_key", None)

class CloudFlareApi:
    def __init__(self, auth_email, auth_key):
        self.opener = urllib.request.build_opener()
        self.opener.addheaders = [
            ("X-Auth-Email",    auth_email),
            ("X-Auth-Key",      auth_key),
            ("Content-Type",    "application/json")
        ]

    def set_a_record(self, name, ipaddr, proxied=False):
        zone_id = self._find_zone_id(name)
        if not zone_id:
            raise ValueError("%s is not on CloudFlare" % name)
        rec_id = self._find_a_record(zone_id, name)
        if not rec_id:
            rec_id = self._create_a_record(zone_id, name, ipaddr, proxied)
        else:
            rec_id = self._update_a_record(zone_id, rec_id, name, ipaddr, proxied)
        return rec_id

    def set_srv_record(self, name, port, service="_natter", protocol="_tcp"):
        zone_id = self._find_zone_id(name)
        if not zone_id:
            raise ValueError("%s is not on CloudFlare" % name)
        rec_id = self._find_srv_record(zone_id, name)
        if not rec_id:
            rec_id = self._create_srv_record(zone_id, name, service,
                                             protocol, port, name)
        else:
            rec_id = self._update_srv_record(zone_id, rec_id, name, service,
                                             protocol, port, name)
        return rec_id

    def set_txt_record(self, name, key, port):
        zone_id = self._find_zone_id(name)
        if not zone_id:
            raise ValueError("%s is not on CloudFlare" % name)
        rec_id = self._find_txt_record(zone_id, name)
        if not rec_id:
            rec_id = self._create_txt_record(zone_id, name, key, port)
        else:
            print("rec_id is: " + rec_id)
            rec_id = self._update_txt_record(zone_id, rec_id, name, key, port)
        return rec_id

    def set_redirect_rule(self, redirect_host, direct_host, public_port, https):
        zone_id = self._find_zone_id(redirect_host)
        ruleset_id = self._get_redir_ruleset(zone_id)
        if not ruleset_id:
            ruleset_id = self._create_redir_ruleset(zone_id)
        rule_id = self._find_redir_rule(zone_id, ruleset_id, redirect_host)
        if not rule_id:
            rule_id = self._create_redir_rule(zone_id, ruleset_id, redirect_host, direct_host, public_port, https)
        else:
            rule_id = self._update_redir_rule(zone_id, ruleset_id, rule_id, redirect_host, direct_host, public_port, https)
        return rule_id

    def _url_req(self, url, data=None, method=None):
        data_bin = None
        if data is not None:
            data_bin = json.dumps(data).encode()
        req = urllib.request.Request(url, data=data_bin, method=method)
        try:
            with self.opener.open(req, timeout=10) as res:
                ret = json.load(res)
        except urllib.error.HTTPError as e:
            ret = json.load(e)
        if "errors" not in ret:
            raise RuntimeError(ret)
        if not ret.get("success"):
            raise RuntimeError(ret["errors"])
        return ret

    def _find_zone_id(self, name):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones"
        )
        for zone_data in data["result"]:
            zone_name = zone_data["name"]
            if name == zone_name or name.endswith("." + zone_name):
                zone_id = zone_data["id"]
                return zone_id
        return None

    def _find_a_record(self, zone_id, name):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        )
        for rec_data in data["result"]:
            if rec_data["type"] == "A" and rec_data["name"] == name:
                rec_id = rec_data["id"]
                return rec_id
        return None

    def _create_a_record(self, zone_id, name, ipaddr, proxied=False, ttl=120):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            data={
                "content":  ipaddr,
                "name":     name,
                "proxied":  proxied,
                "type":     "A",
                "ttl":      ttl
            },
            method="POST"
        )
        return data["result"]["id"]

    def _update_a_record(self, zone_id, rec_id, name, ipaddr, proxied=False, ttl=120):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec_id}",
            data={
                "content":  ipaddr,
                "name":     name,
                "proxied":  proxied,
                "type":     "A",
                "ttl":      ttl
            },
            method="PUT"
        )
        return data["result"]["id"]

    def _find_srv_record(self, zone_id, name):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        )
        for rec_data in data["result"]:
            if rec_data["type"] == "SRV" and rec_data["data"]["name"] == name:
                rec_id = rec_data["id"]
                return rec_id
        return None

    def _create_srv_record(self, zone_id, name, service, protocol, port, target,
                           priority=1, weight=10, ttl=120):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            data={
                "data": {
                    "name":     name,
                    "port":     port,
                    "priority": priority,
                    "proto":    protocol,
                    "service":  service,
                    "target":   target,
                    "weight":   weight
                },
                "proxied":  False,
                "type":     "SRV",
                "ttl":      ttl
            },
            method="POST"
        )
        return data["result"]["id"]

    def _update_srv_record(self, zone_id, rec_id, name, service, protocol, port, target,
                           priority=1, weight=10, ttl=120):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec_id}",
            data={
                "data": {
                    "name":     name,
                    "port":     port,
                    "priority": priority,
                    "proto":    protocol,
                    "service":  service,
                    "target":   target,
                    "weight":   weight
                },
                "proxied":  False,
                "type":     "SRV",
                "ttl":      ttl
            },
            method="PUT"
        )
        return data["result"]["id"]

    def _find_txt_record(self, zone_id, name):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        )
        for rec_data in data["result"]:
            if rec_data["type"] == "TXT" and rec_data["name"] == name:
                rec_id = rec_data["id"]
                return rec_id
        return None

    def _create_txt_record(self, zone_id, name, key, port, ttl=120):
        name = name.lower()
        content_combined = key+":"+port
        encoded_content = base64.b64encode(content_combined.encode()).decode()
        print("encoded content: " + encoded_content)
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            data={
                "content":  encoded_content,
                "name":     name,
                "type":     "TXT",
                "ttl":      ttl
            },
            method="POST"
        )
        return data["result"]["id"]

    def _update_txt_record(self, zone_id, rec_id, name, key, port, ttl=120):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec_id}",
            data={
                "name":     name,
                "type":     "TXT",
            },
            method="GET"
        )
        b64content = data["result"]["content"]
        decoded_message = ""
        try:
            decoded_message = base64.b64decode(b64content).decode()
        except Exception as e:
            print(f"Error decoding base64 content: {e}")

        print("decode string: " + decoded_message)

        key_found = False
        need_update = False

        updated_text = []
        for line in decoded_message.splitlines():
            service, sport = line.split(":")
            if service == key:
                print("found service: " + service)
                key_found = True
                if sport == port:
                    print("port not changed")
                else:
                    print("port changed to " + port)
                    sport = port
                    need_update = True
            updated_text.append(f"{service}:{sport}")


        if not need_update and key_found:
            print("no need to update, exit")
            return data["result"]["id"]

        if not key_found:
            updated_text.append(f"{key}:{port}")

        new_txt_record = "\n".join(updated_text)
        print("updated message: " + new_txt_record)

        new_txt_base64 = base64.b64encode(new_txt_record.encode()).decode()

        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec_id}",
            data={
                "content":  new_txt_base64,
                "name":     name,
                "type":     "TXT",
                "ttl":      ttl
            },
            method="PUT"
        )

        return data["result"]["id"]

    def _get_redir_ruleset(self, zone_id):
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"
        )
        for ruleset_data in data["result"]:
            if ruleset_data["phase"] == "http_request_dynamic_redirect":
                ruleset_id = ruleset_data["id"]
                return ruleset_id
        return None

    def _create_redir_ruleset(self, zone_id):
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets",
            data={
                "name":     "Redirect rules ruleset",
                "kind":     "zone",
                "phase":    "http_request_dynamic_redirect",
                "rules":    []
            },
            method="POST"
        )
        return data["result"]["id"]

    def _get_description(self, redirect_host):
        return f"Natter: {redirect_host}"

    def _find_redir_rule(self, zone_id, ruleset_id, redirect_host):
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}"
        )
        if "rules" not in data["result"]:
            return None
        for rule_data in data["result"]["rules"]:
            if rule_data["description"] == self._get_description(redirect_host):
                rule_id = rule_data["id"]
                return rule_id
        return None

    def _create_redir_rule(self, zone_id, ruleset_id, redirect_host, direct_host, public_port, https):
        proto = "http"
        if https:
            proto = "https"
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}/rules",
            data={
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "status_code": 302,
                        "target_url": {
                            "expression": f'concat("{proto}://{direct_host}:{public_port}", http.request.uri.path)'
                        },
                        "preserve_query_string": True
                    }
                },
                "description": self._get_description(redirect_host),
                "enabled": True,
                "expression": f'(http.host eq "{redirect_host}")'
            },
            method="POST"
        )
        for rule_data in data["result"]["rules"]:
            if rule_data["description"] == self._get_description(redirect_host):
                rule_id = rule_data["id"]
                return rule_id
        raise RuntimeError("Failed to create redirect rule")

    def _update_redir_rule(self, zone_id, ruleset_id, rule_id, redirect_host, direct_host, public_port, https):
        proto = "http"
        if https:
            proto = "https"
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
            data={
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "status_code": 302,
                        "target_url": {
                            "expression": f'concat("{proto}://{direct_host}:{public_port}", http.request.uri.path)'
                        },
                        "preserve_query_string": True
                    }
                },
                "description": self._get_description(redirect_host),
                "enabled": True,
                "expression": f'(http.host eq "{redirect_host}")'
            },
            method="PATCH"
        )
        for rule_data in data["result"]["rules"]:
            if rule_data["description"] == self._get_description(redirect_host):
                rule_id = rule_data["id"]
                return rule_id
        raise RuntimeError("Failed to update redirect rule")

if __name__ == "__main__":
    main()
