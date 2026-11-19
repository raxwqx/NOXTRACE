"""Structured research notes; redact sensitive information before exporting."""

from __future__ import annotations
import re
from noxtrace.reporting import make_report

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
MAX_CASE_NAME = 120
MAX_OBSERVATION = 10_000


def create_case_note(case_name: str, observation: str) -> dict:
    case = case_name.strip() if isinstance(case_name, str) else ""
    note = observation.strip() if isinstance(observation, str) else ""
    if not case or not note:
        return make_report("Case Note", case or "unspecified", "error", "Case name and observation are both required.")
    if len(case) > MAX_CASE_NAME or len(note) > MAX_OBSERVATION:
        return make_report("Case Note", case[:MAX_CASE_NAME], "error", f"Case name must be at most {MAX_CASE_NAME} characters and observation at most {MAX_OBSERVATION} characters.")
    if (
        _CONTROL.search(case) or "\r" in case or "\n" in case or "\t" in case
        or _CONTROL.search(note) or "\r" in note
    ):
        return make_report("Case Note", case[:MAX_CASE_NAME], "error", "Case name and observation must not contain terminal control characters. Line breaks and tabs are allowed in the observation only.")
    return make_report("Case Note", case, "ok", "Created a researcher-authored observation note.", {"case_name": case, "observation": note, "automated_verdict": False}, notes=["Review notes for personal data, passwords, tokens, and other secrets before sharing."])
