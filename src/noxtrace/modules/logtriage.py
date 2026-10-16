"""Local log triage: return line numbers and rule names, not full sensitive log lines."""

from __future__ import annotations
import re
from pathlib import Path
from noxtrace.reporting import make_report

_RULES = [
    ("auth_failure", re.compile(r"failed password|authentication failure|invalid user|login failed", re.I), "Authentication failure indicator"),
    ("privilege_use", re.compile(r"sudo:.*COMMAND=|polkit.*authentication", re.I), "Privilege-use event"),
    ("account_change", re.compile(r"useradd|adduser|passwd.*changed|new user", re.I), "Account-change indicator"),
    ("service_error", re.compile(r"segfault|fatal error|service failed|kernel panic", re.I), "Service/system error"),
    ("permission_denied", re.compile(r"permission denied|access denied|unauthorized", re.I), "Access-control failure"),
    ("suspicious_shell", re.compile(r"\b(curl|wget)\b.*\|\s*(sh|bash)|base64\s+-d|/dev/tcp/", re.I), "Command pattern for manual review"),
]


def triage_log(path_value: str, max_lines: int = 200_000) -> dict:
    path = Path(path_value).expanduser()
    if not path.is_file():
        return make_report("Log Triage", str(path), "error", "Log path is not a regular file.")
    results = []
    scanned = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line_number, line in enumerate(stream, 1):
                if line_number > max_lines:
                    return make_report("Log Triage", str(path), "warning", f"Stopped at the safety limit of {max_lines} lines.", {"lines_scanned": scanned, "matches": results})
                scanned = line_number
                for rule_id, pattern, label in _RULES:
                    if pattern.search(line):
                        results.append({"line": line_number, "rule": rule_id, "title": label})
                        break
    except OSError as exc:
        return make_report("Log Triage", str(path), "error", f"Could not read log: {exc}")
    findings = [{"severity": "REVIEW", "title": item["title"], "detail": f"Rule {item['rule']} matched at line {item['line']}."} for item in results[:1000]]
    status = "warning" if results else "ok"
    return make_report("Log Triage", str(path), status, f"Scanned {scanned} lines and found {len(results)} rule match(es).", {"lines_scanned": scanned, "match_count": len(results), "matches": results[:1000]}, findings, ["Only matching line numbers and rule names are reported to reduce exposure of sensitive log content.", "Heuristic matches require analyst review and are not proof of compromise."])
