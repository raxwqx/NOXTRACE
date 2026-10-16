"""Offline domain/hostname syntax analysis; never claims domain ownership."""

from __future__ import annotations
import ipaddress
import re
from noxtrace.reporting import make_report

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def analyze_domain(value: str) -> dict:
    original = value.strip().rstrip(".")
    try:
        address = ipaddress.ip_address(original)
    except ValueError:
        address = None
    if address:
        return make_report("Domain Validation", original, "warning", "Input is an IP address, not a domain name.", {"normalized": str(address), "input_type": "ip"})
    try:
        ascii_name = original.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return make_report("Domain Validation", original, "error", "Could not normalize this hostname with IDNA.")
    labels = ascii_name.split(".") if ascii_name else []
    valid = bool(labels) and len(ascii_name) <= 253 and all(_LABEL.fullmatch(label) for label in labels)
    data = {"normalized_ascii": ascii_name, "label_count": len(labels), "labels": labels, "syntax_valid": valid}
    notes = ["Offline syntax check only: no DNS request, registration lookup, or ownership check was performed."]
    return make_report("Domain Validation", original, "ok" if valid else "error", "Hostname syntax looks valid." if valid else "Hostname syntax is invalid.", data, notes=notes)
