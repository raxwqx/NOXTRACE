"""Offline password-strength heuristics; never stores or transmits the supplied value."""

from __future__ import annotations
import math
import string
from noxtrace.reporting import make_report


def audit_password(value: str) -> dict:
    if not value:
        return make_report("Password Audit", "provided value (redacted)", "error", "Enter a non-empty test value.")
    pool = 0
    groups = {"lowercase": any(c in string.ascii_lowercase for c in value), "uppercase": any(c in string.ascii_uppercase for c in value), "digits": any(c in string.digits for c in value), "symbols": any(c in string.punctuation or c.isspace() for c in value)}
    pool += 26 * groups["lowercase"] + 26 * groups["uppercase"] + 10 * groups["digits"] + 33 * groups["symbols"]
    estimate = round(len(value) * math.log2(pool), 1) if pool else 0.0
    findings = []
    if len(value) < 12:
        findings.append({"severity": "MEDIUM", "title": "Short length", "detail": "Consider a longer unique passphrase, ideally at least 14 characters."})
    if sum(groups.values()) < 3:
        findings.append({"severity": "LOW", "title": "Limited character variety", "detail": "A long, unique passphrase is often more useful than forced complexity rules."})
    if value.lower() in {"password", "password123", "qwerty123", "letmein", "admin123"}:
        findings.append({"severity": "HIGH", "title": "Common example password", "detail": "This value matches a common example pattern and should not be used."})
    status = "warning" if findings else "ok"
    data = {"length": len(value), "character_groups": groups, "rough_entropy_bits": estimate, "secret_saved": False, "secret_transmitted": False}
    # Intentionally never include the raw value, a prefix, or a digest of the supplied password.
    return make_report("Password Audit", "provided value (redacted)", status, "Calculated a rough local heuristic; this is not a password-cracking result.", data, findings, ["Do not enter a real or reused password into any tool you do not fully trust. Estimated entropy is only a simplified heuristic."])
