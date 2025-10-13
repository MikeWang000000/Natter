#!/usr/bin/env python3
import urllib.request
import json
import sys

# Natter notification script arguments
protocol, private_ip, private_port, public_ip, public_port = sys.argv[1:6]

cf_domains = ["origin.example.com"]
cf_origin_rule_descriptions = ["nas"]
cf_origin_rule_expressions = ['(http.host contains "origin.example.com")']
cf_auth_email = "laoxinhxx@gmail.com"
cf_auth_key = "3eb7ba3c36bbf34e0add81da0e84980166641"

def main():
    cf = CloudFlareDNS(cf_auth_email, cf_auth_key)
    for i in range(len(cf_domains)):
        print(f"Setting {cf_domains[i]} A record to {public_ip}...")
        cf.set_a_record(cf_domains[i], public_ip)
    for i in range(len(cf_origin_rule_descriptions)):
        print(
            f"Setting {cf_domains[i]} {cf_origin_rule_expressions[i]} origin rule to {cf_origin_rule_expressions[i]} port {public_port}...")
        cf.set_origin_rule(cf_domains[i], cf_origin_rule_descriptions[i], cf_origin_rule_expressions[i], int(public_port))


class CloudFlareDNS:
    def __init__(self, auth_email, auth_key):
        self.opener = urllib.request.build_opener()
        self.opener.addheaders = [
            ("X-Auth-Email", auth_email),
            ("X-Auth-Key", auth_key),
            ("Content-Type", "application/json")
        ]

    def set_a_record(self, name, ipaddr):
        zone_id = self._find_zone_id(name)
        if not zone_id:
            raise ValueError("%s is not on CloudFlare" % name)
        rec_id = self._find_a_record(zone_id, name)
        if not rec_id:
            rec_id = self._create_a_record(zone_id, name, ipaddr)
        else:
            rec_id = self._update_a_record(zone_id, rec_id, name, ipaddr)
        return rec_id

    def set_origin_rule(self, name, description, expression, port):
        zone_id = self._find_zone_id(name)
        if not zone_id:
            raise ValueError("%s is not on CloudFlare" % name)
        ruleset_id, rule_id = self._get_origin_ruleset_id_and_rule_id(name, description)
        if not rule_id:
            rule_id = self._create_origin_rule(name, description, expression, port)
        else:
            rule_id = self._update_origin_rule(name, description, expression, port)
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
            print(e)
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
        # print(data)
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

    def _create_a_record(self, zone_id, name, ipaddr, proxied=True, ttl=120):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            data={
                "content": ipaddr,
                "name": name,
                "proxied": proxied,
                "type": "A",
                "ttl": ttl
            },
            method="POST"
        )
        return data["result"]["id"]

    def _update_a_record(self, zone_id, rec_id, name, ipaddr, proxied=True, ttl=120):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec_id}",
            data={
                "content": ipaddr,
                "name": name,
                "proxied": proxied,
                "type": "A",
                "ttl": ttl
            },
            method="PUT"
        )
        return data["result"]["id"]

    def _get_origin_ruleset_id_and_rule_id(self, name, description):
        zone_id = self._find_zone_id(name)
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/phases/http_request_origin/entrypoint"
        )
        for rule_data in data["result"]["rules"]:
            if rule_data["description"] == description:
                rule_id = rule_data["id"]
                return data["result"]["id"], rule_id
        return data["result"]["id"], None

    def _create_origin_rule(self, name, description, expression, port):
        zone_id = self._find_zone_id(name)
        ruleset_id, rule_id = self._get_origin_ruleset_id_and_rule_id(name, description)
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}/rules",
            {
                "description": description,
                "expression": expression,
                "action": "route",
                "ref": "my_ref",
                "action_parameters": {
                    'origin': {'port': port}
                }
            },
            method="POST"
        )
        return data["result"]["id"]

    def _update_origin_rule(self, name, description, expression, port):
        zone_id = self._find_zone_id(name)
        ruleset_id, rule_id = self._get_origin_ruleset_id_and_rule_id(name, description)
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
            {
                "description": description,
                "expression": '(http.host contains "modwu.com")',
                "action": "route",
                # "action_parameters": {
                #     "id": "4814384a9e5d4991b9815dcfc25d2f1f"
                # },
                # "ref": "my_ref",
                "action_parameters": {
                    'origin': {'port': port}
                }
            },
            method="PATCH"
        )
        return data["result"]["id"]


# 示例用法


if __name__ == "__main__":
    main()
