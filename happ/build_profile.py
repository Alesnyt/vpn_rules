#!/usr/bin/env python3
"""Read-only fetch/converter. Emits generated file contents as JSON to stdout.

The caller saves the emitted artifacts. No app settings or servers are modified.
Rebuild offline: python3 build_profile.py --offline .
Refresh inputs: python3 build_profile.py --refresh
"""
import argparse
import base64
import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess

REPO = "Alesnyt/vpn_rules"
NAME = "AlexClubs Selective v1"
DOMAIN_TYPES = {"DOMAIN": "full:", "DOMAIN-SUFFIX": "domain:", "DOMAIN-KEYWORD": "keyword:"}


def get(url):
    return subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location",
                           "--connect-timeout", "8", "--max-time", "35", url],
                          check=True, capture_output=True, text=True).stdout


def parse(text):
    section = ""
    rules = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line.lower()
            continue
        if section != "[rule]":
            continue
        fields = [part.strip() for part in line.split(",")]
        kind = fields[0]
        if kind == "FINAL":
            if fields != ["FINAL", "DIRECT"]:
                raise ValueError("This converter requires FINAL,DIRECT")
            rules.append({"kind": kind, "value": "", "action": "DIRECT", "line": number})
            continue
        if kind not in {*DOMAIN_TYPES, "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}:
            raise ValueError(f"Unsupported rule at {number}: {line}")
        if len(fields) < 3 or fields[2] not in {"DIRECT", "PROXY"}:
            raise ValueError(f"Unsupported action at {number}: {line}")
        if fields[3:] not in ([], ["no-resolve"]):
            raise ValueError(f"Unsupported options at {number}: {line}")
        rules.append({"kind": kind, "value": fields[1].lower(), "action": fields[2], "line": number})
    if not rules or rules[-1]["kind"] != "FINAL":
        raise ValueError("Missing final DIRECT rule")
    return rules


def collapse(prefixes):
    networks = [ipaddress.ip_network(p, strict=True) for p in prefixes]
    result = []
    for version in (4, 6):
        result.extend(str(n) for n in ipaddress.collapse_addresses(n for n in networks if n.version == version))
    return result


def fetch_asn(asn):
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    response = json.loads(get(url))
    if response.get("status") != "ok":
        raise ValueError(f"RIPEstat failed for AS{asn}")
    data = response["data"]
    cutoff = min(data["query_endtime"], data["latest_time"])
    current = [item["prefix"] for item in data["prefixes"]
               if any(t["starttime"] <= cutoff <= t["endtime"] for t in item["timelines"])]
    if not current:
        raise ValueError(f"No visible prefixes at {cutoff} for AS{asn}; manual review required")
    return asn, {"url": url, "observed_at": cutoff, "min_peers_seeing": 10,
                 "visible_prefix_count": len(current), "prefixes": collapse(current)}


def fetch_inputs():
    commit = json.loads(get(f"https://api.github.com/repos/{REPO}/commits/main"))
    revision = commit["sha"]
    url = f"https://raw.githubusercontent.com/{REPO}/{revision}/vpn_rules.conf"
    upstream = get(url)
    source = upstream.rstrip("\n") + "\n"
    asns = sorted({r["value"] for r in parse(source) if r["kind"] == "IP-ASN"})
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        asn_data = dict(executor.map(fetch_asn, asns))
    metadata = {"source_url": url, "source_commit": revision,
                "source_commit_date": commit["commit"]["committer"]["date"],
                "fetched_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "sha256": hashlib.sha256(source.encode()).hexdigest(),
                "upstream_text_sha256": hashlib.sha256(upstream.encode()).hexdigest(),
                "snapshot_normalization": "LF text with exactly one terminal newline"}
    return source, asn_data, metadata


def build(source, asn_data, metadata):
    rules = parse(source)
    last_proxy = max(i for i, r in enumerate(rules) if r["action"] == "PROXY")
    profile = {
        "Name": NAME, "GlobalProxy": "false",
        "RemoteDNSType": "DoH", "RemoteDNSDomain": "https://dns.google/dns-query", "RemoteDNSIP": "8.8.8.8",
        "DomesticDNSType": "DoH", "DomesticDNSDomain": "https://dns10.quad9.net/dns-query", "DomesticDNSIP": "9.9.9.10",
        "DnsHosts": {"dns.google": "8.8.8.8", "dns10.quad9.net": "9.9.9.10"},
        "DirectSites": [], "DirectIp": [], "ProxySites": [], "ProxyIp": [],
        "BlockSites": [], "BlockIp": [], "DomainStrategy": "AsIs", "FakeDNS": "false",
        "Geoipurl": "", "Geositeurl": ""
    }
    omitted = []
    for index, rule in enumerate(rules):
        kind, value, action = rule["kind"], rule["value"], rule["action"]
        # A DIRECT suffix after the final PROXY rule is equivalent to the
        # DIRECT default. Omitting it also avoids changing first-match order
        # when Happ groups all Direct rules before all Proxy rules.
        if index > last_proxy:
            omitted.append(rule)
            continue
        key = "Proxy" if action == "PROXY" else "Direct"
        if kind in DOMAIN_TYPES:
            profile[key + "Sites"].append(DOMAIN_TYPES[kind] + value)
        elif kind in {"IP-CIDR", "IP-CIDR6"}:
            profile[key + "Ip"].append(str(ipaddress.ip_network(value, strict=True)))
        elif kind == "IP-ASN":
            profile[key + "Ip"].extend(asn_data[value]["prefixes"])
        else:
            raise ValueError(f"Rule requires manual ordering review: {rule}")
    # These are operational exceptions, not additional destinations sent via
    # the VPN. Runtime precedence against Happ's own DNS rules needs a device test.
    profile["DirectSites"].extend(["full:dns.google", "full:dns10.quad9.net", "full:ru.alexclubs.com"])
    profile["DirectIp"].extend(["8.8.8.8/32", "9.9.9.10/32"])
    for key in ("DirectSites", "ProxySites"):
        profile[key] = list(dict.fromkeys(profile[key]))
    for key in ("DirectIp", "ProxyIp"):
        profile[key] = collapse(profile[key])
    for a in profile["DirectIp"]:
        for b in profile["ProxyIp"]:
            aa, bb = ipaddress.ip_network(a), ipaddress.ip_network(b)
            if aa.version == bb.version and aa.overlaps(bb):
                raise ValueError(f"Ambiguous Direct/Proxy IP overlap: {a} / {b}")
    compact = json.dumps(profile, ensure_ascii=False, separators=(",", ":"))
    payload = base64.b64encode(compact.encode()).decode()
    report = {
        **metadata,
        "profile_name": NAME,
        "source_rule_count": len(rules),
        "counts": {k: len(profile[k]) for k in ("DirectSites", "DirectIp", "ProxySites", "ProxyIp")},
        "omitted_direct_tail": omitted,
        "asn_snapshot": {a: {k: v for k, v in d.items() if k != "prefixes"} for a, d in asn_data.items()},
        "important_differences": [
            "GitHub version is authoritative for this build: Apple is PROXY, unlike the older local copy.",
            "Shadowrocket system DNS is replaced by explicit Google DoH and Quad9 non-filtering DoH. Device test required.",
            "AsIs avoids extra DNS queries purely for routing and approximates the source no-resolve IP rules.",
            "ASN rules are observed BGP prefix snapshots, not live ASN lookup or exact MaxMind equivalence.",
            "Trailing DIRECT and GEOIP RU are replaced by the DIRECT default. This preserves explicit earlier VPN exceptions.",
            "No geosite/geoip tags are used. Happ itself may still initialize its default geo files.",
            "No UpdateUrl, Provider ID, credentials, subscription changes or automatic publication.",
            "Import validation and device traffic tests are separate from offline conversion tests."
        ],
        "device_verified": False,
        "import_link_bytes": len(payload) + len("happ://routing/add/")
    }
    def pretty(obj):
        return json.dumps(obj, ensure_ascii=False, indent=2) + "\n"
    return {
        "reference-shadowrocket.conf": source,
        "reference-metadata.json": pretty(metadata),
        "asn-prefixes.json": pretty(asn_data),
        "AlexClubs-Selective-v1.json": pretty(profile),
        "IMPORT-HAPP.txt": "happ://routing/add/" + payload + "\n",
        "conversion-report.json": pretty(report)
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--refresh", action="store_true")
    group.add_argument("--offline", type=Path)
    args = parser.parse_args()
    if args.refresh:
        inputs = fetch_inputs()
    else:
        inputs = ((args.offline / "reference-shadowrocket.conf").read_text(),
                  json.loads((args.offline / "asn-prefixes.json").read_text()),
                  json.loads((args.offline / "reference-metadata.json").read_text()))
    print(json.dumps(build(*inputs), ensure_ascii=False))
