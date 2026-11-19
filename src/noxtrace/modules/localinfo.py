"""Local-only runtime and host information. No external service is contacted."""

from __future__ import annotations
import ipaddress
import os
import platform
import socket
import sys
from noxtrace.reporting import make_report


def _address_sort_key(value: str) -> tuple[int, int, str]:
    """Sort IPv4 before IPv6 and numerically inside each family."""
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return (99, 0, value)
    return (address.version, int(address), "")


def collect_local_info() -> dict:
    return make_report("Local System Snapshot", platform.node() or "local", "ok", "Collected local runtime metadata.", {
        "hostname": platform.node(), "platform": platform.platform(), "system": platform.system(),
        "release": platform.release(), "architecture": platform.machine(), "python_version": sys.version.split()[0],
        "python_executable": sys.executable, "effective_user_id": os.geteuid() if hasattr(os, "geteuid") else None,
        "resolver_addresses_for_hostname": _hostname_addresses(),
    }, notes=["Hostname address resolution may consult the machine's configured name service.", "No process list, credential store, or private user file is collected."])


def _hostname_addresses() -> list[str]:
    hostname = platform.node()
    if not hostname:
        return []
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(hostname, None)}, key=_address_sort_key)
    except (OSError, UnicodeError):
        return []
