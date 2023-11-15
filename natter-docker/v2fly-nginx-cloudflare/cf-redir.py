#!/usr/bin/env python3
import urllib.request
import json
import sys

# Natter notification script arguments
protocol, private_ip, private_port, public_ip, public_port = sys.argv[1:6]

cf_redirect_to_https    = False
cf_redirect_host        = "redirect.example.com"
cf_direct_host          = "direct.example.com"
cf_auth_email           = "email@example.com"
cf_auth_key             = "d41d8cd98f00b204e9800998ecf8427e"


def main():
    cf = CloudFlareRedir(cf_auth_email, cf_auth_key)

    print(f"Setting [ {cf_redirect_host} ] DNS to [ {public_ip} ] proxied by CloudFlare...")
    cf.set_a_record(cf_redirect_host, public_ip, proxied=True)

    print(f"Setting [ {cf_direct_host} ] DNS to [ {public_ip} ] directly...")
    cf.set_a_record(cf_direct_host, public_ip, proxied=False)

    print(f"Setting [ {cf_redirect_host} ] redirecting to [ {cf_direct_host}:{public_port} ], https={cf_redirect_to_https}...")
    cf.set_redirect_rule(cf_redirect_host, cf_direct_host, public_port, cf_redirect_to_https)


class CloudFlareRedir:
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
