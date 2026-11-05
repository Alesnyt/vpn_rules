#!/usr/bin/env python3
"""Rebuild vpn_rules.conf from curated RU blocklists and the manual baseline.

vpn_rules.base.conf is the human-edited source; vpn_rules.conf is the
single published routing policy consumed by Shadowrocket AND Happ.
All external rules are evaluated after existing manual PROXY entries but
before manual DIRECT entries. Conflicting DIRECT domains are excluded.
No VPN credentials, subscriptions or node addresses are handled here.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "vpn_rules.base.conf"
OUTPUT = ROOT / "vpn_rules.conf"
ANCHOR = "DOMAIN-SUFFIX,ts.net,DIRECT\n"
BEGIN = "# BEGIN AUTO PROXY RULES (generated; edit vpn_rules.base.conf instead)"
END = "# END AUTO PROXY RULES"

# Curated/shorter lists; deliberately exclude the 700k-domain Antifilter dump.
SOURCES = (
    ("refilter-community",
     "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/community.lst"),
    ("antifilter-community",
     "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geosite/release/antifilter-download-community.txt"),
)
MIN_SOURCE_DOMAINS = 100
MAX_SOURCE_BYTES = 2_000_000
MAX_GENERATED_DOMAINS = 10_000
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")


def valid_domain(value: str) -> bool:
    if len(value) > 253 or "." not in value:
        return False
    labels = value.split(".")
    return all(1 <= len(part) <= 63 and LABEL.fullmatch(part) for part in labels)


def parse_source(text: str) -> set[str]:
    domains: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip().lower().lstrip("\ufeff")
        if not line or line.startswith(("#", "//", ";", "!")):
            continue
        if line.startswith(("domain:", "full:")):
            line = line.split(":", 1)[1]
        if line.startswith("*."):
            line = line[2:]
        if valid_domain(line):
            domains.add(line)
    return domains


def fetch_source(url: str) -> str:
    request = Request(url, headers={"User-Agent": "AlexClubs-vpn-rules/1.0"})
    with urlopen(request, timeout=35) as response:
        data = response.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError(f"Upstream file too large: {url}")
    return data.decode("utf-8-sig")


def manual_patterns(source: str, action: str) -> list[tuple[str, str]]:
    patterns = []
    section = ""
    for raw in source.splitlines():
        line = raw.strip()
        if line.startswith("["):
            section = line.lower()
        if section != "[rule]" or not line or line.startswith("#"):
            continue
        parts = [p.strip().lower() for p in line.split(",")]
        if len(parts) >= 3 and parts[2] == action.lower() and parts[0] in (
                "domain", "domain-suffix", "domain-keyword"):
            patterns.append((parts[0], parts[1]))
    return patterns


def intersects_direct(domain: str, direct: list[tuple[str, str]]) -> bool:
    # Parent/child overlap is intentionally conservative: do not allow an
    # external broad suffix to shadow any explicit local DIRECT exception.
    for kind, value in direct:
        if kind == "domain-keyword" and value in domain:
            return True
        if kind == "domain" and (domain == value or value.endswith("." + domain)):
            return True
        if kind == "domain-suffix" and (
                domain == value or domain.endswith("." + value) or
                value.endswith("." + domain)):
            return True
    return False


def already_proxy(domain: str, proxy: list[tuple[str, str]]) -> bool:
    for kind, value in proxy:
        if kind == "domain-keyword" and value in domain:
            return True
        if kind == "domain" and domain == value:
            return True
        if kind == "domain-suffix" and (domain == value or domain.endswith("." + value)):
            return True
    return False


def select_domains(manual: str, feeds: dict[str, str]) -> list[str]:
    direct = manual_patterns(manual, "DIRECT")
    proxy = manual_patterns(manual, "PROXY")
    selected: set[str] = set()
    for name, _ in SOURCES:
        if name not in feeds:
            raise ValueError(f"Missing upstream feed: {name}")
        domains = parse_source(feeds[name])
        if len(domains) < MIN_SOURCE_DOMAINS:
            raise ValueError(f"Suspiciously small or malformed {name}: {len(domains)} domains")
        for domain in domains:
            # Russia's own zones must take DIRECT even if foreign lists include
            # sites such as 4pda.ru. Explicit existing PROXY exceptions stay.
            if domain.endswith((".ru", ".su", ".xn--p1ai")):
                continue
            if intersects_direct(domain, direct) or already_proxy(domain, proxy):
                continue
            # Preserve Happ's hardcoded bootstrap DNS exceptions.
            if domain in ("dns.google", "dns10.quad9.net", "quad9.net",
                          "alexclubs.com", "ru.alexclubs.com"):
                continue
            selected.add(domain)
    if not selected or len(selected) > MAX_GENERATED_DOMAINS:
        raise ValueError(f"Unsafe generated rule count: {len(selected)}")
    return sorted(selected)


def render(manual: str, domains: list[str]) -> str:
    if manual.count(ANCHOR) != 1 or manual.count("[Rule]") != 1:
        raise ValueError("Manual configuration structure/anchor changed; review required")
    if manual.count("FINAL,DIRECT") != 1 or BEGIN in manual or END in manual:
        raise ValueError("Manual configuration must end routing with one FINAL,DIRECT")
    if "[Host]" not in manual or manual.index(ANCHOR) >= manual.index("FINAL,DIRECT"):
        raise ValueError("Unexpected routing order or missing Host section")
    block = [
        BEGIN,
        "# Sources: " + ", ".join(name for name, _ in SOURCES),
        "# External RU-blocked / anti-RU-geoblock community rules; .ru/.su/.rf protected",
        "# All explicit manual routing rules and FINAL,DIRECT are preserved.",
        *("DOMAIN-SUFFIX," + domain + ",PROXY" for domain in domains),
        END,
        "",
        "",
    ]
    # Avoid accumulating generated regions: always render from base file.
    return manual.replace(ANCHOR, "\n".join(block) + ANCHOR).rstrip("\n") + "\n"


def build(manual: str, feeds: dict[str, str]) -> str:
    return render(manual, select_domains(manual, feeds))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if published file differs")
    args = ap.parse_args()
    manual = BASE.read_text(encoding="utf-8")
    feeds = {name: fetch_source(url) for name, url in SOURCES}
    generated = build(manual, feeds)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != generated:
            print("vpn_rules.conf differs from current upstream lists", file=sys.stderr)
            return 1
        print("Published rules are current")
        return 0
    current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
    if current != generated:
        OUTPUT.write_text(generated, encoding="utf-8")
        print(f"Updated vpn_rules.conf: {len(generated.splitlines())} lines")
    else:
        print("No domain/routing changes; leaving published file untouched")
    print("Auto-proxy domains:", generated.count("\nDOMAIN-SUFFIX,") -
          manual.count("\nDOMAIN-SUFFIX,"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
