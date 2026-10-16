"""TLS handshake and certificate validation using Python's trusted CA store."""

from __future__ import annotations
import socket
import ssl
from datetime import datetime, timezone
from noxtrace.reporting import make_report


def inspect_tls(host: str, port: int = 443, timeout: float = 4.0) -> dict:
    hostname = host.strip().strip("[]")
    if not hostname or any(ch.isspace() for ch in hostname) or not 1 <= port <= 65535:
        return make_report("TLS Inspection", host, "error", "Provide a hostname/IP and a port in range 1-65535.")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=max(1.0, min(timeout, 10.0))) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as secured:
                cert = secured.getpeercert()
                data = {"port": port, "tls_version": secured.version(), "cipher": secured.cipher()[0] if secured.cipher() else None, "certificate_verified": True, "subject": cert.get("subject"), "issuer": cert.get("issuer"), "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter"), "alpn_protocol": secured.selected_alpn_protocol()}
                findings = []
                version = secured.version() or ""
                if version in {"TLSv1", "TLSv1.1", "SSLv3"}:
                    findings.append({"severity": "HIGH", "title": "Legacy TLS version", "detail": version})
                if not findings:
                    findings.append({"severity": "INFO", "title": "Certificate verified", "detail": "The TLS peer certificate validated against the local trusted CA store."})
                return make_report("TLS Inspection", f"{hostname}:{port}", "warning" if findings[0]["severity"] == "HIGH" else "ok", "TLS handshake completed with certificate validation enabled.", data, findings, ["The result reflects this machine's trust store and current network path."])
    except ssl.SSLCertVerificationError as exc:
        return make_report("TLS Inspection", f"{hostname}:{port}", "warning", "TLS certificate validation failed.", {"port": port, "certificate_verified": False, "error": str(exc)}, [{"severity": "HIGH", "title": "Certificate validation failed", "detail": str(exc)}], ["Check hostname, expiry, trust chain, and local clock. NOXTRACE does not silently disable validation."])
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return make_report("TLS Inspection", f"{hostname}:{port}", "error", f"TLS connection failed: {type(exc).__name__}: {exc}", {"port": port})


def _is_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
