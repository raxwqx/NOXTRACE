"""Structured research notes; redact sensitive information before exporting."""

from __future__ import annotations
from noxtrace.reporting import make_report


def create_case_note(case_name: str, observation: str) -> dict:
    case = case_name.strip()
    note = observation.strip()
    if not case or not note:
        return make_report("Case Note", case or "unspecified", "error", "Case name and observation are both required.")
    return make_report("Case Note", case, "ok", "Created a researcher-authored observation note.", {"case_name": case, "observation": note, "automated_verdict": False}, notes=["Review notes for personal data, passwords, tokens, and other secrets before sharing."])
