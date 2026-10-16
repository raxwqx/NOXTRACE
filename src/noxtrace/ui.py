"""Dark terminal renderer using black, white, graphite, and electric-blue colors."""

from __future__ import annotations

import os
import sys
from typing import Any

from noxtrace import __version__


class Palette:
    def __init__(self) -> None:
        active = sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
        self.blue = "\033[38;5;75m" if active else ""
        self.white = "\033[97m" if active else ""
        self.gray = "\033[90m" if active else ""
        self.bold = "\033[1m" if active else ""
        self.reset = "\033[0m" if active else ""


P = Palette()


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
    status = str(report.get("status", "unknown")).upper()
    color = P.blue if status in {"OK", "WARNING"} else P.white
    print(f"\n{P.blue}{P.bold}[ {report.get('module', 'REPORT').upper()} ]{P.reset}")
    print(f"{P.gray}{'-' * 62}{P.reset}")
    print(f"  Target  : {report.get('target', '-')}")
    print(f"  Status  : {color}{status}{P.reset}")
    print(f"  Summary : {report.get('summary', '-')}")
    findings = report.get("findings") or []
    for item in findings:
        severity = str(item.get("severity", "INFO")).upper()
        label = item.get("title", item.get("check", "Finding"))
        detail = item.get("detail", item.get("evidence", ""))
        print(f"  [{severity:<8}] {label}: {detail}")
    data = report.get("data") or {}
    for key, value in data.items():
        if isinstance(value, (dict, list)):
            value = str(value)
        print(f"  {key.replace('_', ' ').capitalize():<22}: {value}")
    for note in report.get("notes") or []:
        print(f"  {P.gray}Note: {note}{P.reset}")
    print(f"  {P.gray}UTC: {report.get('timestamp_utc', '-')}{P.reset}\n")


def prompt_authorization() -> bool:
    """Interactive authorization confirmation for active network actions."""
    answer = input("  Confirm you own this target or have written authorization [type YES]: ").strip()
    return answer == "YES"
