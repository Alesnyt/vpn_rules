import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import unittest

from build_profile import build, parse, DOMAIN_TYPES

ROOT = Path(__file__).resolve().parent
SOURCE = (ROOT / "reference-shadowrocket.conf").read_text()
ASNS = json.loads((ROOT / "asn-prefixes.json").read_text())
META = json.loads((ROOT / "reference-metadata.json").read_text())
PROFILE = json.loads((ROOT / "AlexClubs-Selective-v1.json").read_text())
RULES = parse(SOURCE)


def domain_match(pattern, name):
    kind, value = pattern.split(":", 1)
    if kind == "full":
        return value == name
    if kind == "domain":
        return value == name or name.endswith("." + value)
    if kind == "keyword":
        return value in name
    raise ValueError(pattern)


def in_networks(address, networks):
    return any(address.version == (net := ipaddress.ip_network(n)).version and address in net for n in networks)


def shadow_decision(destination):
    try:
        address = ipaddress.ip_address(destination)
    except ValueError:
        address = None
    for rule in RULES:
        kind, value = rule["kind"], rule["value"]
        if kind == "FINAL":
            return rule["action"]
        if address is None and kind in DOMAIN_TYPES:
            if domain_match(DOMAIN_TYPES[kind] + value, destination):
                return rule["action"]
        elif address is not None:
            if kind in {"IP-CIDR", "IP-CIDR6"} and in_networks(address, [value]):
                return rule["action"]
            if kind == "IP-ASN" and in_networks(address, ASNS[value]["prefixes"]):
                return rule["action"]
        # Source GEOIP RU is in the redundant DIRECT tail, before FINAL DIRECT.
    raise AssertionError("No final policy")


def happ_decision(destination, order=("Direct", "Proxy")):
    try:
        address = ipaddress.ip_address(destination)
    except ValueError:
        address = None
    for group in order:
        match = (in_networks(address, PROFILE[group + "Ip"]) if address is not None else
                 any(domain_match(p, destination) for p in PROFILE[group + "Sites"]))
        if match:
            return "DIRECT" if group == "Direct" else "PROXY"
    return "DIRECT"


class ProfileTests(unittest.TestCase):
    def test_source_pinned(self):
        self.assertEqual(hashlib.sha256(SOURCE.encode()).hexdigest(), META["sha256"])
        self.assertIn(META["source_commit"], META["source_url"])

    def test_policy_and_dns(self):
        self.assertEqual(PROFILE["GlobalProxy"], "false")
        self.assertEqual(PROFILE["FakeDNS"], "false")
        self.assertEqual(PROFILE["DomainStrategy"], "AsIs")
        self.assertEqual(PROFILE["RemoteDNSType"], "DoH")
        self.assertEqual(PROFILE["DomesticDNSType"], "DoH")
        self.assertEqual(PROFILE["DnsHosts"]["dns.google"], "8.8.8.8")
        self.assertEqual(PROFILE["DnsHosts"]["dns10.quad9.net"], "9.9.9.10")
        self.assertNotIn("cloudflare", json.dumps(PROFILE).lower())
        self.assertNotIn("1.1.1.1", json.dumps(PROFILE))
        self.assertNotIn("UpdateUrl", PROFILE)
        self.assertNotIn("providerid", json.dumps(PROFILE).lower())

    def test_import_round_trip(self):
        link = (ROOT / "IMPORT-HAPP.txt").read_text().strip()
        prefix = "happ://routing/add/"
        self.assertTrue(link.startswith(prefix))
        self.assertEqual(json.loads(base64.b64decode(link[len(prefix):], validate=True)), PROFILE)

    def test_offline_rebuild(self):
        bundle = build(SOURCE, ASNS, META)
        for name, content in bundle.items():
            self.assertEqual((ROOT / name).read_text(), content, name)

    def test_all_proxy_domains_retained(self):
        for rule in RULES:
            if rule["action"] == "PROXY" and rule["kind"] in DOMAIN_TYPES:
                self.assertIn(DOMAIN_TYPES[rule["kind"]] + rule["value"], PROFILE["ProxySites"])

    def test_no_global_proxy_ranges_or_geodata_dependencies(self):
        self.assertNotIn("0.0.0.0/0", PROFILE["ProxyIp"])
        self.assertNotIn("::/0", PROFILE["ProxyIp"])
        for key in ("DirectSites", "ProxySites", "DirectIp", "ProxyIp"):
            self.assertFalse(any(p.startswith(("geoip:", "geosite:", "ext:")) for p in PROFILE[key]))

    def test_domain_decisions_against_source(self):
        candidates = {"example.org", "api.ipify.org", "sber.ru", "gosuslugi.ru", "vk.com",
                      "yandex.com", "google.com", "maps.google.com", "ru.alexclubs.com",
                      "dns.google", "dns10.quad9.net", "gopro.ru", "yandex.ai",
                      "fcmtoken.googleapis.com", "firebaselogging-pa.googleapis.com",
                      "apple.com", "telegram.org", "youtube.com", "chatgpt.com", "cursor.com"}
        for rule in RULES:
            if rule["kind"] in DOMAIN_TYPES:
                value = rule["value"]
                candidates.update([value, "cdn." + value, value + ".unrelated.test", "unrelated-" + value,
                                   "cdn." + value + ".ru", "cdn." + value + ".ai"])
        for destination in sorted(candidates):
            expected = shadow_decision(destination)
            for order in (("Direct", "Proxy"), ("Proxy", "Direct")):
                self.assertEqual(happ_decision(destination, order), expected, (destination, order))
        print(f"Validated {len(candidates)} domain probes under both group orders")

    def test_ip_decisions_against_source(self):
        candidates = {"8.8.8.8", "9.9.9.10", "45.151.102.120", "45.144.29.113", "192.168.1.1",
                      "127.0.0.1", "1.2.3.4", "::1", "fd00::123", "149.154.167.51"}
        networks = PROFILE["DirectIp"] + PROFILE["ProxyIp"]
        for item in ASNS.values():
            networks += item["prefixes"]
        for prefix in networks:
            net = ipaddress.ip_network(prefix)
            candidates.update([str(net.network_address), str(net.broadcast_address),
                               str(net.network_address + net.num_addresses // 2)])
        for destination in candidates:
            self.assertEqual(happ_decision(destination), shadow_decision(destination), destination)
        print(f"Validated {len(candidates)} IPv4/IPv6 probes")

    def test_invalid_source_rejected(self):
        with self.assertRaises(ValueError):
            parse("[Rule]\nFINAL,PROXY\n")
        with self.assertRaises(ValueError):
            parse("[Rule]\nPROCESS-NAME,test,PROXY\nFINAL,DIRECT\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
