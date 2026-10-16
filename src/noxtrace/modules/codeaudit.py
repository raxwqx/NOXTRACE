"""Offline source-code pattern review across common languages; results need human validation."""

from __future__ import annotations
import re
from pathlib import Path
from noxtrace.reporting import make_report

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "target", "__pycache__", ".mypy_cache", ".pytest_cache"}
EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs", ".c", ".h", ".cpp", ".cc", ".sh", ".bash", ".php", ".rb", ".yml", ".yaml", ".toml"}
RULES = [
    ("HIGH", "Dynamic code evaluation", re.compile(r"\b(eval|exec)\s*\("), "Dynamic evaluation can execute strings as code; review input trust and alternatives."),
    ("HIGH", "Shell invocation", re.compile(r"\bsubprocess\.(run|call|Popen|check_output)\s*\([^\n]*shell\s*=\s*True|\bos\.system\s*\("), "Review command construction and untrusted input; prefer argument arrays and avoid shell interpretation."),
    ("HIGH", "Unsafe object deserialization", re.compile(r"\bpickle\.(load|loads)\s*\("), "Do not deserialize untrusted pickle data."),
    ("HIGH", "TLS verification disabled", re.compile(r"\bverify\s*=\s*False\b|CERT[_]NONE"), "Certificate verification should not be disabled in production code."),
    ("MEDIUM", "Hard-coded secret-like assignment", re.compile(r"(?i)\b(password|passwd|api[_-]?key|secret|access[_-]?token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "Move real credentials to a secure secret store or environment configuration."),
    ("MEDIUM", "Potentially weak digest", re.compile(r"(?i)\b(md5|sha1)\s*\("), "MD5/SHA-1 are unsuitable for modern security-sensitive integrity/signature uses."),
    ("MEDIUM", "Unsafe YAML loader", re.compile(r"\byaml\.load\s*\("), "Use a safe loader for untrusted YAML and confirm the selected API's behavior."),
    ("MEDIUM", "Potential DOM injection sink", re.compile(r"\binnerHTML\s*=|dangerouslySet(?:InnerHTML)"), "Confirm the value is safely encoded or sanitized before it reaches an HTML sink."),
    ("MEDIUM", "Potential SQL query concatenation", re.compile(r"\b(execute|executemany)\s*\([^\n]*\+"), "Prefer parameterized SQL queries rather than string concatenation."),
    ("LOW", "Debug mode enabled", re.compile(r"\bDEBUG\s*=\s*True\b|\bdebug\s*=\s*True\b"), "Ensure debug settings are not enabled in production deployments."),
]


def _source_files(root: Path, max_files: int):
    if root.is_file():
        return [root] if root.suffix.lower() in EXTENSIONS else []
    found = []
    for current, dirs, files in __import__("os").walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            path = Path(current) / name
            if path.is_symlink():
                continue
            if path.suffix.lower() in EXTENSIONS:
                found.append(path)
                if len(found) > max_files:
                    return found
    return found


def audit_source(path_value: str, max_files: int = 5000, max_file_bytes: int = 2_000_000) -> dict:
    root = Path(path_value).expanduser().resolve()
    if max_files < 1 or max_file_bytes < 1:
        return make_report("Source Code Audit", str(root), "error", "File and byte limits must be positive integers.")
    if not root.exists():
        return make_report("Source Code Audit", str(root), "error", "Path does not exist.")
    if not root.is_file() and not root.is_dir():
        return make_report("Source Code Audit", str(root), "error", "Path must be a source file or directory.")
    files = _source_files(root, max_files)
    if len(files) > max_files:
        return make_report("Source Code Audit", str(root), "error", f"Source file count exceeds the safety cap of {max_files}.")
    matches = []
    scanned_files = 0
    skipped_large = 0
    for path in files:
        try:
            if path.stat().st_size > max_file_bytes:
                skipped_large += 1
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned_files += 1
        for line_number, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "/*", "*", "<!--")):
                continue
            for severity, title, pattern, detail in RULES:
                if pattern.search(line):
                    try:
                        display_path = str(path.relative_to(root if root.is_dir() else root.parent))
                    except ValueError:
                        display_path = path.name
                    matches.append({"severity": severity, "title": title, "file": display_path, "line": line_number, "rule_id": re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_"), "detail": detail})
                    break
            if len(matches) >= 1000:
                break
        if len(matches) >= 1000:
            break
    findings = [{"severity": item["severity"], "title": item["title"], "detail": f"{item['file']}:{item['line']} — {item['detail']}"} for item in matches]
    status = "warning" if matches or skipped_large else "ok"
    summary = f"Reviewed {scanned_files} source file(s), found {len(matches)} pattern match(es)."
    notes = ["Static pattern review only: matches can be false positives and clean results do not prove code is secure.", "Source-line text is not copied into the report, which helps reduce accidental disclosure of secrets."]
    if skipped_large:
        notes.append(f"Skipped {skipped_large} file(s) larger than {max_file_bytes} bytes.")
    return make_report("Source Code Audit", str(root), status, summary, {"files_scanned": scanned_files, "matches_count": len(matches), "skipped_large_files": skipped_large, "max_file_bytes": max_file_bytes, "matches": matches}, findings, notes)
