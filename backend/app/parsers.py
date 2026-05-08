from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import DependencyComponent


def parse_project_dependencies(project_path: str) -> list[DependencyComponent]:
    root = Path(project_path)
    components: list[DependencyComponent] = []

    for file_path in root.rglob("pom.xml"):
        components.extend(_parse_pom(file_path, root))

    for file_path in root.rglob("package.json"):
        components.extend(_parse_package_json(file_path, root))

    for file_path in root.rglob("requirements.txt"):
        components.extend(_parse_requirements(file_path, root))

    deduped: dict[str, DependencyComponent] = {}
    for component in components:
        deduped[component.component_id] = component
    return list(deduped.values())


def _service_name(file_path: Path, root: Path) -> str:
    try:
        relative = file_path.parent.relative_to(root)
        return relative.parts[0] if relative.parts else file_path.parent.name
    except ValueError:
        return file_path.parent.name


def _parse_pom(file_path: Path, root: Path) -> list[DependencyComponent]:
    service = _service_name(file_path, root)
    try:
        tree = ET.parse(file_path)
    except ET.ParseError:
        return []

    ns = {"mvn": "http://maven.apache.org/POM/4.0.0"}
    dependencies = tree.findall(".//mvn:dependency", ns)
    components: list[DependencyComponent] = []
    for dependency in dependencies:
        artifact = dependency.findtext("mvn:artifactId", default="", namespaces=ns).strip()
        version = dependency.findtext("mvn:version", default="unknown", namespaces=ns).strip()
        scope = dependency.findtext("mvn:scope", default="direct", namespaces=ns).strip()
        if artifact:
            components.append(
                DependencyComponent(
                    name=artifact,
                    version=version,
                    language="java",
                    service=service,
                    dependency_type=scope,
                    source_file=str(file_path),
                )
            )
    return components


def _parse_package_json(file_path: Path, root: Path) -> list[DependencyComponent]:
    service = _service_name(file_path, root)
    try:
        content = json.loads(file_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    components: list[DependencyComponent] = []
    for dep_type in ("dependencies", "devDependencies"):
        for name, version in content.get(dep_type, {}).items():
            components.append(
                DependencyComponent(
                    name=name,
                    version=_clean_js_version(version),
                    language="javascript",
                    service=service,
                    dependency_type=dep_type,
                    source_file=str(file_path),
                )
            )
    return components


def _parse_requirements(file_path: Path, root: Path) -> list[DependencyComponent]:
    service = _service_name(file_path, root)
    components: list[DependencyComponent] = []
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        match = re.match(r"([A-Za-z0-9_.-]+)\s*([=<>!~]+)\s*([A-Za-z0-9_.-]+)", line)
        if match:
            name, _, version = match.groups()
        else:
            name, version = line, "unknown"

        components.append(
            DependencyComponent(
                name=name,
                version=version,
                language="python",
                service=service,
                dependency_type="direct",
                source_file=str(file_path),
            )
        )
    return components


def _clean_js_version(version: str) -> str:
    return version.lstrip("^~><= ").strip() or "unknown"

