"""Offline IOC syntax classifier. It does not submit indicators to third parties."""

from __future__ import annotations
import hashlib
import ipaddress
import re
from noxtrace.modules.domain import analyze_domain
from noxtrace.modules.urlintel import analyze_url
from noxtrace.reporting import make_report

_HASHES = ((32, "MD5"), (40, "SHA-1"), (64, "SHA-256"), (96, "SHA-384"), (128, "SHA-512"))
_HEX = re.compile(r"^[a-fA-F0-9]+$")


def classify_ioc(value: str) -> dict:
    item = value.strip()
    if not item:
        return make_report("IOC Classifier", item, "error", "Enter an indicator to classify.")
    try:
        ipaddress.ip_address(item)
    except ValueError:
        pass
    else:
        return make_report("IOC Classifier", item, "ok", "Recognized an IPv4/IPv6 indicator.", {"type": "ip", "network_lookup_performed": False})
    if _HEX.fullmatch(item) and len(item) in dict((length, name) for length, name in _HASHES):
        return make_report("IOC Classifier", item, "ok", "Recognized a hexadecimal hash by length.", {"type": "file_hash", "likely_algorithm": dict(_HASHES)[len(item)], "reputation_lookup_performed": False}, notes=["Length and character pattern cannot prove that a hash is valid or malicious."])
    if "://" in item:
        report = analyze_url(item)
        return make_report("IOC Classifier", report["target"], report["status"], "Classified using static URL parsing.", {"type": "url", "analysis": report, "network_lookup_performed": False})
    report = analyze_domain(item)
    if report["data"].get("syntax_valid"):
        return make_report("IOC Classifier", item, "ok", "Looks like a domain/hostname indicator.", {"type": "domain", "network_lookup_performed": False})
    return make_report("IOC Classifier", item, "warning", "Indicator type could not be determined confidently.", {"type": "unknown", "network_lookup_performed": False})
