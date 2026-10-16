"""Single-request HTTP header review; no payload injection and no redirect following."""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from noxtrace.reporting import make_report

SECURITY_HEADERS = {
    "content-security-policy": ("MEDIUM", "Content Security Policy can reduce some content-injection impact."),
    "x-content-type-options": ("LOW", "X-Content-Type-Options: nosniff helps prevent MIME sniffing."),
    "referrer-policy": ("LOW", "Referrer-Policy controls referrer information sent to other sites."),
    "permissions-policy": ("INFO", "Permissions-Policy can limit browser feature access."),
    "x-frame-options": ("LOW", "X-Frame-Options or CSP frame-ancestors can help mitigate clickjacking."),
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def audit_url(url: str, timeout: float = 5.0) -> dict:
    raw = url.strip()
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        return make_report("Web Security Audit", raw, "error", f"Invalid URL: {exc}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return make_report("Web Security Audit", raw, "error", "Enter an absolute HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        credential_host = f"[{parsed.hostname}]" if parsed.hostname and ":" in parsed.hostname else (parsed.hostname or "unknown")
        return make_report("Web Security Audit", f"{parsed.scheme}://{credential_host}", "error", "URLs with embedded credentials are rejected.")
    safe_host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    target = f"{parsed.scheme}://{safe_host}" + (f":{port}" if port else "") + (parsed.path or "/")
    req = urllib.request.Request(target, headers={"User-Agent": "NOXTRACE-Defensive-Audit/0.1", "Accept": "*/*"}, method="HEAD")
    opener = urllib.request.build_opener(_NoRedirect())
    response = None
    code = None
    headers = None
    try:
        response = opener.open(req, timeout=max(1.0, min(timeout, 10.0)))
        code, headers = response.status, response.headers
    except urllib.error.HTTPError as exc:
        code, headers = exc.code, exc.headers
        exc.close()
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
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
    if parsed.scheme == "https" and "strict-transport-security" not in header_data:
        findings.append({"severity": "MEDIUM", "title": "Missing Strict-Transport-Security", "detail": "HSTS can help browsers remember to use HTTPS. Confirm deployment requirements before enabling it."})
    cookies = [value for key, value in headers.items() if key.lower() == "set-cookie"] if headers else []
    cookie_review = []
    for index, cookie in enumerate(cookies, 1):
        lowered = cookie.lower()
        flags = {"secure": "; secure" in f";{lowered}", "httponly": "; httponly" in f";{lowered}", "samesite_present": "; samesite=" in f";{lowered}"}
        cookie_review.append(flags)
        if parsed.scheme == "https" and not flags["secure"]:
            findings.append({"severity": "MEDIUM", "title": f"Cookie {index} missing Secure", "detail": "Review whether this cookie should only be sent over HTTPS."})
        if not flags["httponly"]:
            findings.append({"severity": "LOW", "title": f"Cookie {index} missing HttpOnly", "detail": "If JavaScript does not need this cookie, consider the HttpOnly flag."})
        if not flags["samesite_present"]:
            findings.append({"severity": "LOW", "title": f"Cookie {index} missing SameSite", "detail": "Review whether SameSite=Lax or Strict is appropriate for this cookie."})
    server_value = header_data.get("server")
    if server_value:
        findings.append({"severity": "INFO", "title": "Server header present", "detail": "The server advertises a Server header; consider avoiding unnecessary version details."})
    status = "warning" if any(f["severity"] in {"HIGH", "MEDIUM"} for f in findings) else "ok"
    return make_report("Web Security Audit", target, status, f"Received HTTP status {code}; reviewed response headers only.", {"http_status": code, "security_headers": {key: header_data.get(key) for key in SECURITY_HEADERS if key in header_data}, "hsts_present": "strict-transport-security" in header_data, "server_header_present": bool(server_value), "set_cookie_count": len(cookies), "cookie_flags": cookie_review, "request_method": "HEAD", "redirects_followed": False}, findings, ["Single non-invasive HEAD request. No JavaScript, exploit payload, crawling, login attempt, or redirect following.", "Missing headers are review prompts, not proof of an exploitable vulnerability."])
