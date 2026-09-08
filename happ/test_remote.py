import argparse
import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import sys
import unittest

from remote import make_bundle, ARTIFACTS, BASE

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
        for name in ("profile.json", "IMPORT-HAPP.txt", "rules.json", "geosite.dat", "geoip.dat"):
            assert bundle[name] == expected[name], name
        print("Published bundle validated: protobuf, hashes, source mapping and stable import")
    else:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
