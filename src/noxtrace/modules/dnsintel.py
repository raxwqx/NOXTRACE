"""DNS record lookup using the system resolver and optional dnspython extras."""

from __future__ import annotations

import ipaddress
import re
import socket
from noxtrace.reporting import make_report

SUPPORTED = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "PTR"}
_CONTROL = re.compile(r"[\x00-\x20\x7f-\x9f]")


def _normalize_hostname(name: str) -> str:
    """Accept exactly one terminal dot and reject malformed input."""
    raw = name.strip() if isinstance(name, str) else ""
    if raw.endswith("."):
        raw = raw[:-1]
    if not raw:
        raise ValueError("Enter a valid hostname or IP address.")
    if raw.endswith("."):
        raise ValueError("Hostname must not end with multiple dots.")
    if len(raw) > 253:
        raise ValueError("Hostname is longer than 253 characters.")
    if _CONTROL.search(raw):
        raise ValueError("Hostname must not contain whitespace or control characters.")
    return raw


def analyze_dns(name: str, record_types: list[str] | None = None) -> dict:
    try:
        hostname = _normalize_hostname(name)
    except (TypeError, ValueError) as exc:
        return make_report("DNS Intelligence", str(name), "error", str(exc))
    requested = [item.upper() for item in (record_types or ["A", "AAAA", "MX", "NS", "TXT"])]
    invalid = sorted(set(requested) - SUPPORTED)
    if invalid:
        return make_report("DNS Intelligence", hostname, "error", f"Unsupported record type(s): {', '.join(invalid)}", notes=[f"Supported types: {', '.join(sorted(SUPPORTED))}"])
    data: dict[str, list[str] | None] = {}
    notes: list[str] = []
    if any(x in requested for x in ("A", "AAAA")):
        for kind, family in (("A", socket.AF_INET), ("AAAA", socket.AF_INET6)):
            if kind not in requested:
                continue
            try:
                answers = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None, family, socket.SOCK_STREAM)})
                data[kind] = answers
            except (OSError, UnicodeError) as exc:
                data[kind] = []
                notes.append(f"{kind} lookup: {exc}")
    if "PTR" in requested:
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            data["PTR"] = None
            notes.append("PTR lookup requires an IP address; supply an IP literal instead of a hostname.")
        else:
            try:
                data["PTR"] = [socket.gethostbyaddr(hostname)[0]]
            except OSError:
                data["PTR"] = []
                notes.append("No PTR name was returned by the configured resolver.")
    special = [x for x in requested if x in {"MX", "NS", "TXT", "CNAME"}]
    if special:
        try:
            import dns.resolver  # type: ignore[import-not-found]
        except ImportError:
            for kind in special:
                data[kind] = None
            notes.append("MX/NS/TXT/CNAME queries need the optional extra: python -m pip install -e '.[dns]'.")
        else:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 3.0
            for kind in special:
                try:
                    answers = resolver.resolve(hostname, kind, raise_on_no_answer=False)
                    data[kind] = sorted(str(record).strip('"') for record in answers) if answers.rrset else []
                except Exception as exc:  # DNS exceptions vary by dnspython version.
                    data[kind] = []
                    notes.append(f"{kind} lookup returned no usable answer: {type(exc).__name__}")
    status = "ok" if any(value for value in data.values() if isinstance(value, list)) else "warning"
    return make_report("DNS Intelligence", hostname, status, "Queried the selected DNS record types.", data, notes=notes + ["DNS results come from the configured resolver and may be cached or incomplete."])
