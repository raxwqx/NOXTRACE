"""Local, read-only file fingerprinting."""

from __future__ import annotations
import hashlib
from pathlib import Path
from noxtrace.reporting import make_report


def analyze_file(path_value: str) -> dict:
    path = Path(path_value).expanduser()
    if not path.exists() or not path.is_file():
        return make_report("File Fingerprint", str(path), "error", "Path does not point to an existing regular file.")
    algorithms = {"sha256": hashlib.sha256(), "sha512": hashlib.sha512(), "blake2b": hashlib.blake2b()}
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                for digest in algorithms.values():
                    digest.update(chunk)
        stat = path.stat()
    except OSError as exc:
        return make_report("File Fingerprint", str(path), "error", f"Could not read file: {exc}")
    data = {"size_bytes": stat.st_size, "sha256": algorithms["sha256"].hexdigest(), "sha512": algorithms["sha512"].hexdigest(), "blake2b": algorithms["blake2b"].hexdigest(), "modified_time_ns": stat.st_mtime_ns, "uploaded": False, "modified": False}
    return make_report("File Fingerprint", str(path), "ok", "Computed local hashes without modifying or uploading the file.", data)
