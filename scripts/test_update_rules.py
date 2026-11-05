#!/usr/bin/env python3
"""Offline regression tests for the generated Shadowrocket/Happ source policy."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from update_rules import (ANCHOR, BEGIN, END, SOURCES, build, parse_source,
                          render, select_domains, valid_domain)

ROOT = Path(__file__).resolve().parent.parent
MANUAL = (ROOT / "vpn_rules.base.conf").read_text(encoding="utf-8")


def fixture_feeds(extra=()):
    # A realistic minimum-size feed, without any network calls.
    words = [f"blocked-{i}.unavailable.test" for i in range(120)]
    words += list(extra)
    return {name: "\n".join(words) for name, _ in SOURCES}


def decide(source, destination):
    # Domain-match only; the Happ compiler separately validates IP and ASN.
    section = ""
    for line in source.splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line.lower()
            continue
        if section != "[rule]" or not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if parts[0] == "FINAL":
            return parts[1]
        if len(parts) < 3 or parts[0] not in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
            continue
        kind, value, policy = parts[:3]
        if (kind == "DOMAIN" and destination == value or
                kind == "DOMAIN-SUFFIX" and (
                    destination == value or destination.endswith("." + value)) or
                kind == "DOMAIN-KEYWORD" and value in destination):
            return policy
    raise AssertionError("No FINAL rule")


class GeneratorTests(unittest.TestCase):
    def test_valid_domains(self):
        for domain in ("website.com", "sub.website.co.uk", "xn--p1ai.example", "t2.ru"):
            self.assertTrue(valid_domain(domain))
        for domain in ("localhost", "*.example.com", "https://example.com",
                       "a..b", ".example.com", "a space.net", "example.com/path"):
            self.assertFalse(valid_domain(domain))
        self.assertEqual(parse_source(" # comment\n*.example.com\nDOMAIN:other.net\nhttps://bad.com\n"),
                         {"example.com", "other.net"})

    def test_empty_or_suspicious_feeds_fail_closed(self):
        feeds = fixture_feeds()
        feeds[SOURCES[0][0]] = "one.example\n"
        with self.assertRaisesRegex(ValueError, "Suspiciously small"):
            build(MANUAL, feeds)
        with self.assertRaisesRegex(ValueError, "Missing upstream"):
            build(MANUAL, {})

    def test_manual_direct_is_never_shadowed(self):
        additions = ("4pda.to", "t2.ru", "www.sber.ru", "gosuslugi.ru", "vk.com",
                     "yandex.com", "xn--e1afmkfd.xn--p1ai", "sub.wink.example",
                     "chatgpt.com", "dns.google", "dns10.quad9.net", "newblocked.example")
        domains = select_domains(MANUAL, fixture_feeds(additions))
        for protected in ("4pda.to", "t2.ru", "www.sber.ru", "gosuslugi.ru",
                          "vk.com", "yandex.com", "xn--e1afmkfd.xn--p1ai",
                          "sub.wink.example", "chatgpt.com", "dns.google", "dns10.quad9.net"):
            self.assertNotIn(protected, domains)
        self.assertIn("newblocked.example", domains)
        rendered = render(MANUAL, domains)
        self.assertEqual(rendered.count(BEGIN), 1)
        self.assertEqual(rendered.count(END), 1)
        self.assertEqual(rendered.count("FINAL,DIRECT"), 1)
        self.assertLess(rendered.index(BEGIN), rendered.index(ANCHOR))

    def test_route_regression_and_default(self):
        published = build(MANUAL, fixture_feeds(["newblocked.example"]))
        expected = {
            "t2.ru": "DIRECT", "mail.ru": "DIRECT", "vk.com": "DIRECT",
            "sber.ru": "DIRECT", "yandex.com": "DIRECT",
            "www.wink.ru": "DIRECT", "ozon.kz": "DIRECT",
            "example.org": "DIRECT", "newblocked.example": "PROXY",
            "cdn.newblocked.example": "PROXY",
            "telegram.org": "PROXY", "chess.com": "PROXY",
            "strava.com": "PROXY", "gopro.com": "PROXY",
            "openrouter.ai": "PROXY", "github.com": "PROXY",
            "music.apple.com": "PROXY", "google.ru": "PROXY",
            "meduza.io": "PROXY", "agentrouter.org": "PROXY",
        }
        for host, policy in expected.items():
            with self.subTest(host=host):
                self.assertEqual(decide(published, host), policy)
        self.assertIn("[Host]\nlocalhost = 127.0.0.1", published)
        self.assertTrue(published.endswith("\n"))

    def test_stable_across_source_order(self):
        first = fixture_feeds(["newblocked.example"])
        second = {key: "\n".join(reversed(value.splitlines()))
                  for key, value in first.items()}
        self.assertEqual(build(MANUAL, first), build(MANUAL, second))

    def test_missing_manual_anchor_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "structure"):
            render(MANUAL.replace(ANCHOR, "WRONG"), ["blocked.test"])
        with self.assertRaisesRegex(ValueError, "one FINAL"):
            render(MANUAL.replace("FINAL,DIRECT", "FINAL,PROXY"), ["blocked.test"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
