#!/usr/bin/env python3
"""Build user-controlled Happ geodata from the checked-out Shadowrocket source.

Only generated artifacts in --output are written; no VPN server is accessed.
Wire format: XTLS/Xray-core common/geodata/geodat.proto (legacy-compatible).
"""
import argparse
import base64
import concurrent.futures
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess

from build_profile import build, parse, fetch_asn, DOMAIN_TYPES

ROOT = Path(__file__).resolve().parent.parent
BASE = "https://raw.githubusercontent.com/Alesnyt/vpn_rules/happ-data"
NAME = "AlexClubs Selective"
GROUPS = ("Direct", "Proxy")
DOMAIN_ENUM = {"keyword": 0, "domain": 2, "full": 3}
ARTIFACTS = ("geosite.dat", "geoip.dat", "profile.json", "IMPORT-HAPP.txt",
             "rules.json", "asn-prefixes.json", "manifest.json", "README.md")


def varint(value):
    if value < 0:
        raise ValueError("Negative protobuf integer")
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def blob(field, value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return varint((field << 3) | 2) + varint(len(value)) + value


def integer(field, value):
    return varint(field << 3) + varint(value)


def encode_sites(flat):
    result = b""
    for group in GROUPS:
        entry = blob(1, "ALEXCLUBS-" + group.upper())
        for item in flat[group + "Sites"]:
            kind, value = item.split(":", 1)
            entry += blob(2, integer(1, DOMAIN_ENUM[kind]) + blob(2, value))
        result += blob(1, entry)
    return result


def encode_ips(flat):
    result = b""
    for group in GROUPS:
        entry = blob(1, "ALEXCLUBS-" + group.upper())
        for item in flat[group + "Ip"]:
            network = ipaddress.ip_network(item, strict=True)
            cidr = blob(1, network.network_address.packed) + integer(2, network.prefixlen)
            entry += blob(2, cidr)
        result += blob(1, entry)
    return result


def domain_match(pattern, name):
    kind, value = pattern.split(":", 1)
    return ((kind == "full" and name == value) or
            (kind == "domain" and (name == value or name.endswith("." + value))) or
            (kind == "keyword" and value in name))


def ip_match(address, prefixes):
    return any(address.version == (net := ipaddress.ip_network(p)).version and address in net
               for p in prefixes)


def validate_mapping(source, asns, flat):
    """Refuse unsupported policy reordering instead of silently changing routing."""
    rules = parse(source)
    last_proxy = max(i for i, rule in enumerate(rules) if rule["action"] == "PROXY")
    # Happ's default Direct-before-Proxy group order must preserve first-match.
    # Reject an overlapping PROXY that originally precedes its DIRECT exception.
    positions = {}
    for index, rule in enumerate(rules):
        if rule["kind"] in DOMAIN_TYPES:
            positions.setdefault((rule["action"], DOMAIN_TYPES[rule["kind"]] + rule["value"]), index)
    for direct in flat["DirectSites"]:
        dk, dv = direct.split(":", 1)
        for proxy in flat["ProxySites"]:
            pk, pv = proxy.split(":", 1)
            overlap = (domain_match(proxy, dv) or domain_match(direct, pv) or
                       (dk == "keyword" and pk == "keyword") or
                       (dk == "domain" and pk == "keyword") or
                       (dk == "keyword" and pk == "domain"))
            if overlap and positions[("PROXY", proxy)] < positions.get(("DIRECT", direct), -1):
                raise ValueError(f"Direct/Proxy domain overlap needs review: {direct} / {proxy}")
    probes = {"example.org", "sber.ru", "api.ipify.org", "gopro.ru", "yandex.ai"}
    for rule in rules:
        if rule["kind"] in DOMAIN_TYPES:
            value = rule["value"]
            probes.update((value, "cdn." + value, "unrelated-" + value,
                           value + ".unrelated.test", "cdn." + value + ".ru"))
    # Include operational DNS exceptions and intersections with broad keywords.
    for direct in flat["DirectSites"]:
        probes.add(direct.split(":", 1)[1])
        for proxy in flat["ProxySites"]:
            if direct.startswith("domain:") and proxy.startswith("keyword:"):
                probes.add(proxy.split(":", 1)[1] + "." + direct.split(":", 1)[1])
    addresses = set()
    for key in ("DirectIp", "ProxyIp"):
        for prefix in flat[key]:
            network = ipaddress.ip_network(prefix)
            if prefix in {"0.0.0.0/0", "::/0"}:
                raise ValueError("Global IP range needs manual review")
            addresses.update((network.network_address, network.broadcast_address,
                              network.network_address + network.num_addresses // 2))
    for destination in probes | addresses:
        is_ip = not isinstance(destination, str)
        expected = "DIRECT"
        for rule in rules[:last_proxy + 1]:
            kind, value = rule["kind"], rule["value"]
            match = False
            if not is_ip and kind in DOMAIN_TYPES:
                match = domain_match(DOMAIN_TYPES[kind] + value, destination)
            if is_ip and kind in {"IP-CIDR", "IP-CIDR6"}:
                match = ip_match(destination, [value])
            if is_ip and kind == "IP-ASN":
                match = ip_match(destination, asns[value]["prefixes"])
            if match:
                expected = rule["action"]
                break
        actual = "DIRECT"
        for group in GROUPS:
            match = (ip_match(destination, flat[group + "Ip"]) if is_ip else
                     any(domain_match(p, destination) for p in flat[group + "Sites"]))
            if match:
                actual = group.upper()
                break
        if actual != expected:
            raise ValueError(f"Policy changed for {destination}: {expected} -> {actual}")
    return {"domain_probes": len(probes), "ip_probes": len(addresses)}


def make_bundle(source, asns, metadata):
    converted = build(source, asns, metadata)
    flat = json.loads(converted["AlexClubs-Selective-v1.json"])
    checks = validate_mapping(source, asns, flat)
    profile = {**flat, "Name": NAME,
               "Geositeurl": BASE + "/geosite.dat", "Geoipurl": BASE + "/geoip.dat"}
    for group in GROUPS:
        profile[group + "Sites"] = ["geosite:alexclubs-" + group.lower()]
        profile[group + "Ip"] = ["geoip:alexclubs-" + group.lower()]
    compact = json.dumps(profile, ensure_ascii=False, separators=(",", ":"))
    def pretty(value):
        return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    rules = {key: flat[key] for key in ("DirectSites", "DirectIp", "ProxySites", "ProxyIp")}
    bundle = {
        "geosite.dat": encode_sites(flat), "geoip.dat": encode_ips(flat),
        "profile.json": pretty(profile), "rules.json": pretty(rules),
        "asn-prefixes.json": pretty(asns),
        "IMPORT-HAPP.txt": ("happ://routing/add/" + base64.b64encode(compact.encode()).decode() + "\n").encode(),
        "README.md": ("# AlexClubs Selective — обновляемые списки Happ\n\n"
                      "Эта ветка содержит результаты автоматической сборки. Не редактировать вручную.\n\n"
                      "Исходник: [vpn_rules.conf](https://github.com/Alesnyt/vpn_rules/blob/main/vpn_rules.conf).\n\n"
                      "[Установка, обновления и отключение](https://github.com/Alesnyt/vpn_rules/blob/main/happ/REMOTE.md).\n\n"
                      "Первичная установка: открыть IMPORT-HAPP.txt, скопировать содержимое (не HTTPS-адрес) "
                      "и добавить маршрутизацию в Happ. Включение остаётся выбором пользователя.\n\n"
                      "Дальше обновляются geosite.dat и geoip.dat по постоянным URL. "
                      "Повторно копировать профиль при изменении доменов/IP не нужно. "
                      "Смена DNS/базовой политики профиля требует отдельного согласованного импорта.\n").encode(),
    }
    manifest = {
        **metadata, "profile_name": NAME, "checks": checks,
        "counts": {key: len(items) for key, items in rules.items()},
        "delivery": "Client fetches remote geofiles; no subscription or VPN server integration",
        "asn_note": "RIPEstat observed BGP prefix snapshot; refreshed on build, not live ASN matching",
        "files": {name: {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                  for name, content in bundle.items()},
    }
    bundle["manifest.json"] = pretty(manifest)
    assert set(bundle) == set(ARTIFACTS)
    return bundle


def read_inputs(refresh_asn=False):
    source = (ROOT / "vpn_rules.conf").read_text().rstrip("\n") + "\n"
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    committed = subprocess.check_output(["git", "show", revision + ":vpn_rules.conf"], cwd=ROOT, text=True)
    if source != committed.rstrip("\n") + "\n":
        raise ValueError("Commit source changes before publishing; source must be reproducibly pinned")
    commit_date = subprocess.check_output(["git", "show", "-s", "--format=%cI", revision], cwd=ROOT, text=True).strip()
    metadata = {"source_commit": revision,
                "source_url": f"https://raw.githubusercontent.com/Alesnyt/vpn_rules/{revision}/vpn_rules.conf",
                "source_commit_date": commit_date,
                "source_sha256": hashlib.sha256(source.encode()).hexdigest()}
    needed = sorted({rule["value"] for rule in parse(source) if rule["kind"] == "IP-ASN"})
    if refresh_asn:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            asns = dict(executor.map(fetch_asn, needed))
    else:
        cached = json.loads((ROOT / "happ/asn-prefixes.json").read_text())
        asns = {asn: cached[asn] for asn in needed}
    return source, asns, metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-asn", action="store_true")
    args = parser.parse_args()
    bundle = make_bundle(*read_inputs(args.refresh_asn))
    args.output.mkdir(parents=True, exist_ok=True)
    for name, content in bundle.items():
        (args.output / name).write_bytes(content)
    print(json.dumps(json.loads(bundle["manifest.json"])["counts"]))
