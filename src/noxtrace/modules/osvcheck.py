"""Explicit opt-in lookup of known open-source package vulnerabilities via OSV.dev."""

from __future__ import annotations
import json
import re
import urllib.error
import urllib.request
from noxtrace import __version__
from noxtrace.reporting import make_report

OSV_ENDPOINT = "https://api.osv.dev/v1/query"
MAX_RESPONSE_BYTES = 1_000_000
SUPPORTED_ECOSYSTEMS = ("PyPI", "npm", "Go", "crates.io", "Maven", "RubyGems", "NuGet", "Packagist", "Hex", "Pub")
_CONTROL = re.compile(r"[\x00-\x20\x7f-\x9f]")


def check_osv(package: str, version: str, ecosystem: str = "PyPI", timeout: float = 8.0) -> dict:
    name = package.strip() if isinstance(package, str) else ""
    release = version.strip() if isinstance(version, str) else ""
    eco = ecosystem.strip() if isinstance(ecosystem, str) else ""
    target = f"{eco}:{name}@{release}"
    if not name or not release or not eco or len(name) > 200 or len(release) > 100:
        return make_report("OSV Vulnerability Lookup", target, "error", "Package, version, and ecosystem must be valid non-empty values.")
    if _CONTROL.search(name) or _CONTROL.search(release) or _CONTROL.search(eco):
        return make_report("OSV Vulnerability Lookup", target, "error", "Package, version, and ecosystem must not contain whitespace or control characters.")
    if eco not in SUPPORTED_ECOSYSTEMS:
        return make_report("OSV Vulnerability Lookup", target, "error", f"Unsupported OSV ecosystem: {eco}.", notes=[f"Supported ecosystems: {', '.join(SUPPORTED_ECOSYSTEMS)}"])
    payload = json.dumps({"package": {"name": name, "ecosystem": eco}, "version": release}).encode("utf-8")
    request = urllib.request.Request(OSV_ENDPOINT, data=payload, headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": f"NOXTRACE/{__version__}"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=max(2.0, min(timeout, 12.0))) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            return make_report("OSV Vulnerability Lookup", target, "error", "OSV response exceeded the 1 MB safety cap.")
        result = json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return make_report("OSV Vulnerability Lookup", target, "error", f"OSV returned HTTP {exc.code}.", notes=["Check internet access, ecosystem spelling, and the OSV service status."])
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return make_report("OSV Vulnerability Lookup", target, "error", f"Could not reach OSV: {type(reason).__name__}: {reason}", notes=["This feature needs internet access. No target system is contacted."])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return make_report("OSV Vulnerability Lookup", target, "error", f"OSV returned invalid JSON: {type(exc).__name__}.")
    if not isinstance(result, dict):
        return make_report("OSV Vulnerability Lookup", target, "error", "OSV returned an unexpected JSON structure.")
    vulns = result.get("vulns") or []
    if not isinstance(vulns, list):
        return make_report("OSV Vulnerability Lookup", target, "error", "OSV returned an unexpected vulnerability list.")
    findings = []
    advisories = []
    malformed_records = 0
    for item in vulns[:500]:
        if not isinstance(item, dict):
            malformed_records += 1
            continue
        identifier = str(item.get("id") or "OSV record without ID")[:200]
        summary = str(item.get("summary") or "No summary supplied")[:500]
        raw_aliases = item.get("aliases")
        aliases = [value for value in raw_aliases[:20] if isinstance(value, str)] if isinstance(raw_aliases, list) else []
        raw_severity = item.get("severity")
        scores = []
        if isinstance(raw_severity, list):
            for entry in raw_severity[:20]:
                if isinstance(entry, dict) and entry.get("score") is not None:
                    scores.append(str(entry["score"])[:80])
        modified = item.get("modified")
        advisory = {"id": identifier, "summary": summary, "aliases": aliases, "modified": str(modified)[:80] if modified is not None else None, "severity_scores": scores}
        advisories.append(advisory)
        findings.append({"severity": "REVIEW", "title": identifier, "detail": summary + (f" Aliases: {', '.join(aliases)}." if aliases else "")})
    status = "warning" if advisories or malformed_records else "ok"
    if advisories:
        summary = f"OSV returned {len(advisories)} usable vulnerability record(s) for the supplied package/version."
    elif malformed_records:
        summary = f"OSV returned {len(vulns)} record(s), but none could be parsed as a usable advisory."
    else:
        summary = "OSV returned no matching vulnerability record for this package/version."
    notes = ["Package name, version, and ecosystem were sent to the public OSV API because this query was explicitly requested.", "A positive result needs manual applicability review; an empty result does not prove the package is vulnerability-free.", "Advisory coverage and version matching depend on upstream records and ecosystem metadata."]
    if malformed_records:
        notes.append(f"Skipped {malformed_records} malformed advisory record(s) returned by OSV.")
    return make_report("OSV Vulnerability Lookup", target, status, summary, {"package": name, "version": release, "ecosystem": eco, "vulnerability_count": len(vulns), "parsed_advisories": len(advisories), "malformed_records": malformed_records, "advisories": advisories, "source": OSV_ENDPOINT, "network_lookup_performed": True}, findings, notes)
