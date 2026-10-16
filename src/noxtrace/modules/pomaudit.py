"""Offline Maven pom.xml dependency inventory and risky-version-pattern hints."""

from __future__ import annotations
from pathlib import Path
import xml.etree.ElementTree as ET
from noxtrace.reporting import make_report


def audit_pom(path_value: str) -> dict:
    path = Path(path_value).expanduser()
    if not path.is_file():
        return make_report("Java Dependency Review", str(path), "error", "pom.xml path is not a regular file.")
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        return make_report("Java Dependency Review", str(path), "error", f"Could not parse XML: {exc}")

    def child_text(element, name: str) -> str | None:
        for child in element:
            if child.tag.rsplit("}", 1)[-1] == name:
                return (child.text or "").strip() or None
        return None

    deps = []
    findings = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "dependency":
            continue
        group = child_text(element, "groupId")
        artifact = child_text(element, "artifactId")
        version = child_text(element, "version")
        if not group and not artifact:
            continue
        row = {"group_id": group, "artifact_id": artifact, "version": version}
        deps.append(row)
        coordinate = f"{group or '?' }:{artifact or '?'}"
        if not version:
            findings.append({"severity": "REVIEW", "title": "Version not explicit", "detail": f"{coordinate} has no version directly declared; it may be inherited from dependencyManagement."})
        elif "SNAPSHOT" in version.upper() or version.upper() in {"LATEST", "RELEASE"} or version.startswith("[") or version.startswith("("):
            findings.append({"severity": "MEDIUM", "title": "Non-fixed version pattern", "detail": f"{coordinate}:{version} may not be a fixed release reference."})
    return make_report("Java Dependency Review", str(path), "warning" if findings else "ok", f"Read {len(deps)} dependency entries from local Maven XML.", {"dependency_count": len(deps), "dependencies": deps, "network_queries_performed": False}, findings, ["This is an offline inventory, not a CVE scan. Version patterns can be intentional; review findings manually."])
