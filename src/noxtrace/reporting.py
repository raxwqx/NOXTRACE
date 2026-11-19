"""Consistent report creation, JSON output, and a self-contained HTML report."""

from __future__ import annotations

import html
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from noxtrace import __version__


class ReportWriteError(OSError):
    """Raised when a report cannot be serialized or written safely."""


def make_report(
    module: str,
    target: str,
    status: str,
    summary: str,
    data: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    """Create a stable report object suitable for text, JSON, or HTML rendering."""
    return {
        "tool": "NOXTRACE",
        "version": __version__,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "module": module,
        "target": target,
        "status": status,
        "summary": summary,
        "findings": findings or [],
        "data": data or {},
        "notes": notes or [],
    }


def json_text(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=False)


def _atomic_write(destination: str | Path, payload: str) -> Path:
    """Write a report atomically and return the resolved destination path."""
    temporary: Path | None = None
    try:
        path = Path(destination).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".noxtrace-report-", suffix=".tmp", dir=str(path.parent)
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        return path.resolve()
    except ReportWriteError:
        raise
    except (OSError, ValueError, RuntimeError, TypeError) as exc:
        raise ReportWriteError(f"could not write report to {str(destination)!r}: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def write_json(report: dict[str, Any], destination: str | Path) -> Path:
    """Write a JSON report atomically and return the resolved path."""
    return _atomic_write(destination, json_text(report) + "\n")


def write_html(report: dict[str, Any], destination: str | Path) -> Path:
    """Write a self-contained report page atomically. All report text is escaped."""
    payload = html.escape(json_text(report))
    title = html.escape(f"NOXTRACE report: {report.get('module', 'analysis')}")
    status = html.escape(str(report.get("status", "unknown")).upper())
    summary = html.escape(str(report.get("summary", "")))
    page = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>
:root{{--bg:#080b10;--panel:#111722;--line:#263244;--fg:#edf2f7;--muted:#9aa8b9;--blue:#60a5fa;}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1000px;margin:40px auto;padding:0 18px}}header,section{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;margin-bottom:16px}}
h1{{margin:0;color:var(--blue);letter-spacing:.08em}}.muted{{color:var(--muted)}}.status{{display:inline-block;border:1px solid var(--line);border-radius:20px;padding:2px 10px;color:var(--blue);font-weight:700}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#090d13;border:1px solid var(--line);border-radius:10px;padding:16px;color:#d7e1ee}}
</style></head><body><main><header><h1>NOXTRACE</h1><p>{title}</p><span class="status">{status}</span><p>{summary}</p><p class="muted">Generated locally. Review before sharing.</p></header><section><h2>Full report</h2><pre>{payload}</pre></section></main></body></html>'''
    return _atomic_write(destination, page)
