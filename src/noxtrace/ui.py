"""Dark terminal renderer using black, white, graphite, and electric-blue colors."""

from __future__ import annotations

import os
import re
import sys
from typing import Any

from noxtrace import __version__

_ANSI_SEQUENCE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_TERMINAL_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


class Palette:
    def __init__(self) -> None:
        active = sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
        self.blue = "\033[38;5;75m" if active else ""
        self.white = "\033[97m" if active else ""
        self.gray = "\033[90m" if active else ""
        self.bold = "\033[1m" if active else ""
        self.reset = "\033[0m" if active else ""


P = Palette()


def _safe_text(value: Any) -> str:
    """Render untrusted report text without terminal escape sequences."""
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    text = _ANSI_SEQUENCE.sub("", text)
    return _TERMINAL_CONTROL.sub("\uFFFD", text)


def banner() -> None:
    art = r'''
                  _________
               .-'         '-.
             .'    .----.     '.
            /     / o  o \     \____
           |     |   ^^   |     / __ `~\
           |     |  \__/ |    | /  \   |
            \     \____/     \_\__/__/
             '._           _.'
                |  |___|  |          /~~~~\
               /|  |___|  |\________/      \
              /_|_______|_|\        \______/
                \_______/  \
    '''
    print(f"{P.blue}{P.bold}{art}{P.reset}")
    print(f"{P.white}{P.bold}  NOXTRACE{P.reset} {P.gray}SECURITY WORKBENCH  |  v{__version__}{P.reset}")
    print(f"{P.gray}  Black / White / Graphite / Electric Blue{P.reset}")
    print(f"{P.gray}  Defensive analysis only. Active tests require authorization.{P.reset}\n")


def print_report(report: dict[str, Any]) -> None:
    status = _safe_text(report.get("status", "unknown")).upper()
    color = P.blue if status in {"OK", "WARNING"} else P.white
    print(f"\n{P.blue}{P.bold}[ {_safe_text(report.get('module', 'REPORT')).upper()} ]{P.reset}")
    print(f"{P.gray}{'-' * 62}{P.reset}")
    print(f"  Target  : {_safe_text(report.get('target', '-'))}")
    print(f"  Status  : {color}{status}{P.reset}")
    print(f"  Summary : {_safe_text(report.get('summary', '-'))}")
    findings = report.get("findings") or []
    for item in findings:
        if not isinstance(item, dict):
            print(f"  [{P.white}REVIEW{P.reset}] {_safe_text(item)}")
            continue
        severity = _safe_text(item.get("severity", "INFO")).upper()
        label = _safe_text(item.get("title", item.get("check", "Finding")))
        detail = _safe_text(item.get("detail", item.get("evidence", "")))
        print(f"  [{severity:<8}] {label}: {detail}")
    data = report.get("data") or {}
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                value = str(value)
            print(f"  {_safe_text(key).replace('_', ' ').capitalize():<22}: {_safe_text(value)}")
    for note in report.get("notes") or []:
        print(f"  {P.gray}Note: {_safe_text(note)}{P.reset}")
    print(f"  {P.gray}UTC: {_safe_text(report.get('timestamp_utc', '-'))}{P.reset}\n")


def prompt_authorization() -> bool:
    """Interactive authorization confirmation for active network actions."""
    answer = input("  Confirm you own this target or have written authorization [type YES]: ").strip()
    return answer == "YES"
