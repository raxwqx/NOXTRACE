"""Static URL parsing and risk hints. This module never opens the URL."""

from __future__ import annotations
import ipaddress
import re
from urllib.parse import urlsplit
from noxtrace.reporting import make_report

_CONTROL = re.compile(r"[\x00-\x20\x7f-\x9f]")
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")


def normalize_url_host(host: str) -> str:
    if not host:
        raise ValueError("URL must contain a hostname.")
    candidate = host[:-1] if host.endswith(".") else host
    if not candidate or candidate.endswith("."):
        raise ValueError("URL hostname must not end with multiple dots.")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    try:
        return candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("URL hostname could not be normalized with IDNA.") from exc


def analyze_url(value: str) -> dict:
    raw = value.strip() if isinstance(value, str) else ""
    if not raw:
        return make_report("URL Inspection", "", "error", "Provide an absolute HTTP or HTTPS URL with a hostname.")
    if _CONTROL.search(raw):
        return make_report("URL Inspection", "[invalid URL]", "error", "URL must not contain whitespace or terminal control characters.")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
        host = normalize_url_host(parsed.hostname or "")
    except ValueError as exc:
        return make_report("URL Inspection", "[invalid URL]", "error", f"URL could not be parsed: {exc}")
    if parsed.scheme.lower() not in {"http", "https"}:
        return make_report("URL Inspection", raw, "error", "Provide an absolute HTTP or HTTPS URL with a hostname.")
    flags = []
    if parsed.scheme.lower() != "https":
        flags.append({"severity": "MEDIUM", "title": "Plain HTTP", "detail": "The URL uses HTTP rather than HTTPS."})
    if parsed.username is not None or parsed.password is not None:
        flags.append({"severity": "HIGH", "title": "Credentials in URL", "detail": "The URL contains user-info. Avoid sharing it; credentials are omitted from the report."})
    if host.startswith("xn--") or ".xn--" in host:
        flags.append({"severity": "INFO", "title": "Internationalized hostname", "detail": "Review the Unicode/punycode display carefully for lookalike characters."})
    if "@" in parsed.path:
        flags.append({"severity": "INFO", "title": "At-sign in path", "detail": "An @ character appears in the path; inspect the final hostname carefully."})
    if "\\" in raw:
        flags.append({"severity": "MEDIUM", "title": "Backslash in URL", "detail": "Backslashes can be interpreted differently by browsers and URL parsers."})
    if _BAD_PERCENT.search(parsed.path):
        flags.append({"severity": "LOW", "title": "Malformed percent escape", "detail": "The path contains a malformed percent escape; different parsers may interpret it differently."})
    notes = ["URL query strings, fragments, and credentials are not copied into the report target.", "A syntax hint is not proof that a URL is malicious or safe."]
    if not flags:
        notes.append("No basic syntax warning was detected. This is not a safety verdict.")
    safe_host = f"[{host}]" if ":" in host else host
    safe_target = f"{parsed.scheme.lower()}://{safe_host}" + (f":{port}" if port else "") + (parsed.path or "/")
    data = {"scheme": parsed.scheme.lower(), "hostname": host, "port": port, "path": parsed.path or "/", "query_present": bool(parsed.query), "fragment_present": bool(parsed.fragment), "userinfo_omitted": parsed.username is not None or parsed.password is not None, "network_request_made": False}
    return make_report("URL Inspection", safe_target, "warning" if any(x["severity"] in {"HIGH", "MEDIUM"} for x in flags) else "ok", "Parsed URL syntax without visiting the page.", data, findings=flags, notes=notes)
