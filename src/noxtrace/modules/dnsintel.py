"""DNS record lookup using the system resolver and optional dnspython extras."""

from __future__ import annotations

import socket
from noxtrace.reporting import make_report

SUPPORTED = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "PTR"}


def analyze_dns(name: str, record_types: list[str] | None = None) -> dict:
    hostname = name.strip().rstrip(".")
    if not hostname or any(ch.isspace() for ch in hostname):
        return make_report("DNS Intelligence", name, "error", "Enter a valid hostname or IP address.")
    requested = [item.upper() for item in (record_types or ["A", "AAAA", "MX", "NS", "TXT"]) ]
    invalid = sorted(set(requested) - SUPPORTED)
    if invalid:
        return make_report("DNS Intelligence", hostname, "error", f"Unsupported record type(s): {', '.join(invalid)}", notes=[f"Supported types: {', '.join(sorted(SUPPORTED))}"])
    data: dict[str, list[str] | str | None] = {}
    notes: list[str] = []
    if any(x in requested for x in ("A", "AAAA")):
        for kind, family in (("A", socket.AF_INET), ("AAAA", socket.AF_INET6)):
            if kind not in requested:
                continue
            try:
                answers = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None, family, socket.SOCK_STREAM)})
                data[kind] = answers
            except socket.gaierror as exc:
                data[kind] = []
                notes.append(f"{kind} lookup: {exc}")
    if "PTR" in requested:
        try:
            data["PTR"] = [socket.gethostbyaddr(hostname)[0]]
        except (OSError, socket.herror, socket.gaierror):
            data["PTR"] = []
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
