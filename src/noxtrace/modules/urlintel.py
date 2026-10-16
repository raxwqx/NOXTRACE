"""Static URL parsing and risk hints. This module never opens the URL."""

from __future__ import annotations
from urllib.parse import urlsplit
from noxtrace.reporting import make_report


def analyze_url(value: str) -> dict:
    raw = value.strip()
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        return make_report("URL Inspection", raw, "error", f"URL could not be parsed: {exc}")
    if parsed.scheme.lower() not in {"http", "https"} or not host:
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
    if not flags:
        flags.append({"severity": "INFO", "title": "No basic syntax warning", "detail": "This is not a reputation or malware verdict."})
    safe_host = f"[{host}]" if ":" in host else host
    safe_target = f"{parsed.scheme.lower()}://{safe_host}" + (f":{port}" if port else "") + (parsed.path or "/")
    data = {"scheme": parsed.scheme.lower(), "hostname": host, "port": port, "path": parsed.path or "/", "query_present": bool(parsed.query), "fragment_present": bool(parsed.fragment), "userinfo_omitted": parsed.username is not None or parsed.password is not None, "network_request_made": False}
    return make_report("URL Inspection", safe_target, "warning" if any(x["severity"] in {"HIGH", "MEDIUM"} for x in flags) else "ok", "Parsed URL syntax without visiting the page.", data, findings=flags, notes=["URL query strings, fragments, and credentials are not copied into the report target.", "A syntax hint is not proof that a URL is malicious or safe."])
