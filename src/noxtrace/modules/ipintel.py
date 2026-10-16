"""Local IPv4/IPv6 classification plus an optional, explicit PTR lookup."""

from __future__ import annotations

import ipaddress
import socket
from noxtrace.reporting import make_report


def analyze_ip(value: str, reverse_dns: bool = False) -> dict:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return make_report("IP Intelligence", value, "error", "Input is not a valid IPv4 or IPv6 address.")
    data = {
        "address": str(address), "version": address.version,
        "is_global": address.is_global, "is_private": address.is_private,
        "is_loopback": address.is_loopback, "is_link_local": address.is_link_local,
        "is_multicast": address.is_multicast, "is_reserved": address.is_reserved,
        "is_unspecified": address.is_unspecified,
    }
    notes = ["Classification was computed locally using Python's ipaddress module."]
    if reverse_dns:
        try:
            data["ptr_hostname"] = socket.gethostbyaddr(str(address))[0]
            notes.append("PTR name came from the configured resolver; it does not identify a person or prove ownership.")
        except (OSError, socket.herror, socket.gaierror):
            data["ptr_hostname"] = None
            notes.append("No PTR name was returned by the configured resolver.")
    else:
        data["ptr_lookup"] = "not requested"
    return make_report("IP Intelligence", str(address), "ok", f"Classified IPv{address.version} address locally.", data, notes=notes)
