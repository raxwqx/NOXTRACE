"""Single-request HTTP header review; no payload injection and no redirect following."""

from __future__ import annotations

import http.client
import re
import socket
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit
from noxtrace.modules.urlintel import normalize_url_host
from noxtrace.reporting import make_report

SECURITY_HEADERS = {
    "content-security-policy": ("MEDIUM", "Content Security Policy can reduce some content-injection impact."),
    "x-content-type-options": ("LOW", "X-Content-Type-Options: nosniff helps prevent MIME sniffing."),
    "referrer-policy": ("LOW", "Referrer-Policy controls referrer information sent to other sites."),
    "permissions-policy": ("INFO", "Permissions-Policy can limit browser feature access."),
    "x-frame-options": ("LOW", "X-Frame-Options or CSP frame-ancestors can help mitigate clickjacking."),
}
_CONTROL = re.compile(r"[\x00-\x20\x7f-\x9f]")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def audit_url(url: str, timeout: float = 5.0) -> dict:
    raw = url.strip() if isinstance(url, str) else ""
    if not raw:
        return make_report("Web Security Audit", "", "error", "Enter an absolute HTTP or HTTPS URL.")
    if _CONTROL.search(raw):
        return make_report("Web Security Audit", "[invalid URL]", "error", "URL must not contain whitespace or terminal control characters.")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        return make_report("Web Security Audit", raw, "error", "Timeout must be numeric.")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
        host = normalize_url_host(parsed.hostname or "")
    except ValueError as exc:
        return make_report("Web Security Audit", "[invalid URL]", "error", f"Invalid URL: {exc}")
    if parsed.scheme.lower() not in {"http", "https"}:
        return make_report("Web Security Audit", raw, "error", "Enter an absolute HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        return make_report("Web Security Audit", f"{parsed.scheme.lower()}://{host}", "error", "URLs with embedded credentials are rejected.")
    safe_host = f"[{host}]" if ":" in host else host
    safe_path = quote(parsed.path or "/", safe="/:@!$&'()*+,;=-._~%")
    target = f"{parsed.scheme.lower()}://{safe_host}" + (f":{port}" if port else "") + safe_path
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "NOXTRACE-Defensive-Audit/0.1", "Accept": "*/*"}, method="HEAD")
        opener = urllib.request.build_opener(_NoRedirect())
    except (ValueError, http.client.InvalidURL) as exc:
        return make_report("Web Security Audit", target, "error", f"Invalid URL: {exc}")
    response = None
    code = None
    headers = None
    try:
        response = opener.open(req, timeout=max(1.0, min(timeout, 10.0)))
        code, headers = response.status, response.headers
    except urllib.error.HTTPError as exc:
        code, headers = exc.code, exc.headers
        exc.close()
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError, http.client.InvalidURL, ValueError, UnicodeError) as exc:
        reason = getattr(exc, "reason", exc)
        return make_report("Web Security Audit", target, "error", f"HEAD request failed: {type(reason).__name__}: {reason}", notes=["Only one HEAD request was attempted; no redirects were followed and no exploit payloads were sent."])
    finally:
        if response is not None:
            response.close()
    header_data = {key.lower(): value for key, value in headers.items()} if headers else {}
    findings = []
    for header, (severity, detail) in SECURITY_HEADERS.items():
        if header not in header_data:
            if header == "x-frame-options" and "content-security-policy" in header_data and "frame-ancestors" in header_data["content-security-policy"].lower():
                continue
            findings.append({"severity": severity, "title": f"Missing {header}", "detail": detail})
    if parsed.scheme.lower() == "https" and "strict-transport-security" not in header_data:
        findings.append({"severity": "MEDIUM", "title": "Missing Strict-Transport-Security", "detail": "HSTS can help browsers remember to use HTTPS. Confirm deployment requirements before enabling it."})
    cookies = [value for key, value in headers.items() if key.lower() == "set-cookie"] if headers else []
    cookie_review = []
    for index, cookie in enumerate(cookies, 1):
        lowered = cookie.lower()
        flags = {"secure": "; secure" in f";{lowered}", "httponly": "; httponly" in f";{lowered}", "samesite_present": "; samesite=" in f";{lowered}"}
        cookie_review.append(flags)
        if parsed.scheme.lower() == "https" and not flags["secure"]:
            findings.append({"severity": "MEDIUM", "title": f"Cookie {index} missing Secure", "detail": "Review whether this cookie should only be sent over HTTPS."})
        if not flags["httponly"]:
            findings.append({"severity": "LOW", "title": f"Cookie {index} missing HttpOnly", "detail": "If JavaScript does not need this cookie, consider the HttpOnly flag."})
        if not flags["samesite_present"]:
            findings.append({"severity": "LOW", "title": f"Cookie {index} missing SameSite", "detail": "Review whether SameSite=Lax or Strict is appropriate for this cookie."})
    server_value = header_data.get("server")
    status = "warning" if any(f["severity"] in {"HIGH", "MEDIUM"} for f in findings) else "ok"
    notes = ["Single non-invasive HEAD request. No JavaScript, exploit payload, crawling, login attempt, or redirect following.", "Missing headers are review prompts, not proof of an exploitable vulnerability."]
    if server_value:
        notes.append("The server advertises a Server header; consider avoiding unnecessary version details.")
    return make_report("Web Security Audit", target, status, f"Received HTTP status {code}; reviewed response headers only.", {"http_status": code, "security_headers": {key: header_data.get(key) for key in SECURITY_HEADERS if key in header_data}, "hsts_present": "strict-transport-security" in header_data, "server_header_present": bool(server_value), "set_cookie_count": len(cookies), "cookie_flags": cookie_review, "request_method": "HEAD", "redirects_followed": False}, findings, notes)
