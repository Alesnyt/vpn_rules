import argparse
import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import sys
import unittest

from remote import make_bundle, ARTIFACTS, BASE, domain_match, ip_match, validate_mapping

ROOT = Path(__file__).resolve().parent
SOURCE = (ROOT / "reference-shadowrocket.conf").read_text()
ASNS = json.loads((ROOT / "asn-prefixes.json").read_text())
META = json.loads((ROOT / "reference-metadata.json").read_text())


def fields(data):
    """Independent wire decoder for the small supported protobuf subset."""
    offset = 0
    def read_int():
        nonlocal offset
        result = 0
        for shift in range(0, 70, 7):
            if offset >= len(data):
                raise ValueError("Truncated varint")
            byte = data[offset]
            offset += 1
            result |= (byte & 127) << shift
            if byte < 128:
                return result
        raise ValueError("Oversize varint")
    result = {}
    while offset < len(data):
        tag = read_int()
        field, kind = tag >> 3, tag & 7
        if field == 0:
            raise ValueError("Invalid field")
        if kind == 0:
            value = read_int()
        elif kind == 2:
            length = read_int()
            if offset + length > len(data):
                raise ValueError("Truncated bytes")
            value = data[offset:offset + length]
            offset += length
        else:
            raise ValueError("Unsupported wire type")
        result.setdefault(field, []).append(value)
    return result


def decode(data, site):
    result = {}
    for raw in fields(data)[1]:
        entry = fields(raw)
        tag = entry[1][0].decode()
        if tag in result:
            raise ValueError("Duplicate group")
        values = []
        for item in entry.get(2, []):
            rule = fields(item)
            if site:
                kind = {0: "keyword:", 2: "domain:", 3: "full:"}[rule.get(1, [0])[0]]
                values.append(kind + rule[2][0].decode())
            else:
                values.append(str(ipaddress.ip_network((ipaddress.ip_address(rule[1][0]), rule[2][0]), strict=True)))
        result[tag] = values
    return result


def verify_bundle(bundle):
    assert set(bundle) == set(ARTIFACTS)
    profile = json.loads(bundle["profile.json"])
    flat = json.loads(bundle["rules.json"])
    manifest = json.loads(bundle["manifest.json"])
    for name, item in manifest["files"].items():
        assert item["sha256"] == hashlib.sha256(bundle[name]).hexdigest(), name
        assert item["bytes"] == len(bundle[name]), name
    sites, ips = decode(bundle["geosite.dat"], True), decode(bundle["geoip.dat"], False)
    for group in ("Direct", "Proxy"):
        tag = "ALEXCLUBS-" + group.upper()
        assert sites[tag] == flat[group + "Sites"]
        assert ips[tag] == flat[group + "Ip"]
        assert profile[group + "Sites"] == ["geosite:" + tag.lower()]
        assert profile[group + "Ip"] == ["geoip:" + tag.lower()]
    assert profile["Geositeurl"] == BASE + "/geosite.dat"
    assert profile["Geoipurl"] == BASE + "/geoip.dat"
    assert profile["GlobalProxy"] == "false"
    assert profile["BlockSites"] == profile["BlockIp"] == []
    assert "cloudflare" not in json.dumps(profile).lower()
    assert "1.1.1.1" not in json.dumps(profile)
    assert "UpdateUrl" not in profile
    assert "LastUpdated" not in profile  # No new import needed for list updates.
    prefix = b"happ://routing/add/"
    assert bundle["IMPORT-HAPP.txt"].startswith(prefix)
    decoded = json.loads(base64.b64decode(bundle["IMPORT-HAPP.txt"].strip()[len(prefix):], validate=True))
    assert decoded == profile
    assert bundle["SUBSCRIPTION-HAPP.txt"].startswith(prefix)
    subscription = json.loads(base64.b64decode(
        bundle["SUBSCRIPTION-HAPP.txt"].strip()[len(prefix):], validate=True))
    version = subscription.pop("LastUpdated")
    assert version == manifest["subscription_profile_version"]
    assert int(version) > 0
    assert subscription == profile  # Delivery metadata cannot change routing/DNS.


class RemoteTests(unittest.TestCase):
    def test_binary_roundtrip_and_profile(self):
        verify_bundle(make_bundle(SOURCE, ASNS, META))

    def test_remote_list_update_does_not_change_import(self):
        first = make_bundle(SOURCE, ASNS, META)
        changed = SOURCE.replace("[Rule]", "[Rule]\nDOMAIN,update-probe.invalid,PROXY")
        second = make_bundle(changed, ASNS, META)
        verify_bundle(second)
        self.assertEqual(first["profile.json"], second["profile.json"])
        self.assertEqual(first["IMPORT-HAPP.txt"], second["IMPORT-HAPP.txt"])
        self.assertNotEqual(first["geosite.dat"], second["geosite.dat"])
        self.assertEqual(first["geoip.dat"], second["geoip.dat"])
        self.assertIn("full:update-probe.invalid", decode(second["geosite.dat"], True)["ALEXCLUBS-PROXY"])

    def test_remove_domain_changes_remote_list(self):
        before = make_bundle(SOURCE, ASNS, META)
        changed = SOURCE.replace("DOMAIN-SUFFIX,crixet.com,PROXY\n", "")
        after = make_bundle(changed, ASNS, META)
        self.assertNotEqual(before["geosite.dat"], after["geosite.dat"])
        self.assertNotIn("domain:crixet.com", decode(after["geosite.dat"], True)["ALEXCLUBS-PROXY"])
        self.assertEqual(before["IMPORT-HAPP.txt"], after["IMPORT-HAPP.txt"])

    def test_ipv4_ipv6_and_keyword_survive(self):
        bundle = make_bundle(SOURCE, ASNS, META)
        self.assertIn("keyword:gopro", decode(bundle["geosite.dat"], True)["ALEXCLUBS-PROXY"])
        networks = decode(bundle["geoip.dat"], False)["ALEXCLUBS-PROXY"]
        self.assertEqual({ipaddress.ip_network(p).version for p in networks}, {4, 6})

    def test_default_policy_change_rejected(self):
        with self.assertRaises(ValueError):
            make_bundle(SOURCE.replace("FINAL,DIRECT", "FINAL,PROXY"), ASNS, META)

    def test_unsupported_rule_rejected(self):
        with self.assertRaises(ValueError):
            make_bundle(SOURCE.replace("[Rule]", "[Rule]\nPROCESS-NAME,app,PROXY"), ASNS, META)

    def test_reordering_that_changes_decisions_rejected(self):
        source = "[Rule]\nDOMAIN-SUFFIX,example.com,PROXY\nDOMAIN,api.example.com,DIRECT\nDOMAIN,other.test,PROXY\nFINAL,DIRECT\n"
        with self.assertRaises(ValueError):
            make_bundle(source, {}, META)

    def test_direct_exception_before_broad_proxy_allowed(self):
        source = "[Rule]\nDOMAIN,api.example.com,DIRECT\nDOMAIN-SUFFIX,example.com,PROXY\nFINAL,DIRECT\n"
        verify_bundle(make_bundle(source, {}, META))

    def test_dns_bootstrap_proxy_conflict_rejected(self):
        with self.assertRaises(ValueError):
            make_bundle(SOURCE.replace("[Rule]", "[Rule]\nDOMAIN,dns.google,PROXY"), ASNS, META)

    def test_google_asn_preserves_exact_dns_exceptions(self):
        source = ("[Rule]\nDOMAIN-SUFFIX,google,PROXY\n"
                  "DOMAIN-SUFFIX,google.com,PROXY\nIP-ASN,15169,PROXY,no-resolve\n"
                  "FINAL,DIRECT\n")
        # Deterministic fixture, not an assertion about the current BGP table.
        asns = {"15169": {"prefixes": ["8.8.8.0/24", "2001:4860::/32"]}}
        bundle = make_bundle(source, asns, META)
        verify_bundle(bundle)
        flat = json.loads(bundle["rules.json"])

        def decide(destination):
            try:
                address = ipaddress.ip_address(destination)
            except ValueError:
                address = None
            for group in ("Direct", "Proxy"):
                match = (ip_match(address, flat[group + "Ip"]) if address else
                         any(domain_match(p, destination) for p in flat[group + "Sites"]))
                if match:
                    return group.upper()
            return "DIRECT"

        for destination in ("dns.google", "8.8.8.8", "dns10.quad9.net", "9.9.9.10"):
            self.assertEqual(decide(destination), "DIRECT", destination)
        for destination in ("google.com", "www.google.com", "google", "cdn.dns.google",
                            "8.8.8.0", "8.8.8.7", "8.8.8.9", "8.8.8.255", "2001:4860::1"):
            self.assertEqual(decide(destination), "PROXY", destination)
        for last_octet in range(256):
            destination = ipaddress.ip_address(f"8.8.8.{last_octet}")
            self.assertEqual(ip_match(destination, flat["ProxyIp"]), last_octet != 8)
        self.assertEqual(bundle["profile.json"], make_bundle(SOURCE, ASNS, META)["profile.json"])
        self.assertEqual(bundle["IMPORT-HAPP.txt"], make_bundle(SOURCE, ASNS, META)["IMPORT-HAPP.txt"])
        # The validator must still catch accidental bypasses of other Google hosts.
        corrupted = {key: list(value) for key, value in flat.items()}
        corrupted["DirectSites"].append("full:google.com")
        with self.assertRaises(ValueError):
            validate_mapping(source, asns, corrupted)

    def test_dns_exception_does_not_hide_explicit_conflicts(self):
        for rule in ("DOMAIN,dns.google,PROXY", "DOMAIN-SUFFIX,dns.google,PROXY",
                     "IP-CIDR,8.8.8.8/32,PROXY,no-resolve",
                     "IP-CIDR,8.8.8.0/24,PROXY,no-resolve"):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                make_bundle("[Rule]\n" + rule + "\nFINAL,DIRECT\n", {}, META)
        source = ("[Rule]\nIP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n"
                  "IP-ASN,15169,PROXY,no-resolve\nFINAL,DIRECT\n")
        with self.assertRaises(ValueError):
            make_bundle(source, {"15169": {"prefixes": ["10.0.0.0/24"]}}, META)

    def test_current_source_build_and_import_compatibility(self):
        source = (ROOT.parent / "vpn_rules.conf").read_text()
        # Real ASN refresh and full snapshot validation run at publication time.
        asns = {**ASNS, "15169": {"prefixes": ["8.8.8.0/24", "2001:4860::/32"]}}
        bundle = make_bundle(source, asns, META)
        verify_bundle(bundle)
        flat = json.loads(bundle["rules.json"])
        self.assertIn("domain:meduza.io", flat["ProxySites"])
        for host in ("vk.com", "ozon.kz", "yandex.com", "cdn.wildberries.by", "example.org",
                     'notagentrouter.org',
                     'agentrouter.org.unrelated.test',
                     'other.umami.dev',
                     'other.bytednsdoc.com'):
            self.assertFalse(any(domain_match(p, host) for p in flat["ProxySites"]), host)
        for host in ("meduza.io", "cdn.meduza.io", "google.ru", "telegram.org", "instagram.com",
                     'agentrouter.org',
                     'api.agentrouter.org',
                     'co.agentrouter.org',
                     'assets.agentrouter.org',
                     'future.deep.agentrouter.org',
                     'connect.linux.do',
                     'linux.do',
                     'cloud.umami.is',
                     'gateway.umami.is',
                     'eu.umami.is',
                     'api-gateway.umami.dev',
                     'api-gateway-eu.umami.dev',
                     'lf3-static.bytednsdoc.com'):
            self.assertTrue(any(domain_match(p, host) for p in flat["ProxySites"]), host)
        baseline = make_bundle(SOURCE, ASNS, META)
        self.assertEqual(bundle["profile.json"], baseline["profile.json"])
        self.assertEqual(bundle["IMPORT-HAPP.txt"], baseline["IMPORT-HAPP.txt"])

    def test_subscription_release_version_without_policy_change(self):
        first = make_bundle(SOURCE, ASNS, META)
        metadata = {**META, "source_commit_date": "2026-10-25T09:00:00+00:00"}
        second = make_bundle(SOURCE, ASNS, metadata)
        verify_bundle(first)
        verify_bundle(second)
        for name in ("profile.json", "IMPORT-HAPP.txt", "geosite.dat", "geoip.dat", "rules.json"):
            self.assertEqual(first[name], second[name], name)
        self.assertNotEqual(first["SUBSCRIPTION-HAPP.txt"], second["SUBSCRIPTION-HAPP.txt"])
        with self.assertRaises(ValueError):
            make_bundle(SOURCE, ASNS, {**META, "source_commit_date": "2026-10-25T09:00:00"})

    def test_corrupt_binary_rejected(self):
        with self.assertRaises(ValueError):
            decode(b"\x0a\xff", True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path)
    args = parser.parse_args()
    if args.artifacts:
        bundle = {name: (args.artifacts / name).read_bytes() for name in ARTIFACTS}
        verify_bundle(bundle)
        asns = json.loads(bundle["asn-prefixes.json"])
        manifest = json.loads(bundle["manifest.json"])
        source = (ROOT.parent / "vpn_rules.conf").read_text().rstrip("\n") + "\n"
        expected = make_bundle(source, asns, manifest)
        for name in ("profile.json", "IMPORT-HAPP.txt", "SUBSCRIPTION-HAPP.txt", "rules.json", "geosite.dat", "geoip.dat"):
            assert bundle[name] == expected[name], name
        print("Published bundle validated: protobuf, hashes, source mapping and stable import")
    else:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
