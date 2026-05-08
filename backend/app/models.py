from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class DependencyComponent:
    name: str
    version: str
    language: str
    service: str
    dependency_type: str
    source_file: str

    @property
    def component_id(self) -> str:
        return f"component:{self.service}:{self.language}:{self.name}:{self.version}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["component_id"] = self.component_id
        return data


@dataclass(slots=True)
class VulnerabilityRecord:
    cve_id: str
    component_name: str
    language: str
    severity: str
    description: str
    fixed_version: str
    affected_versions: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class MatchResult:
    component: DependencyComponent
    vulnerability: VulnerabilityRecord

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component.to_dict(),
            "vulnerability": self.vulnerability.to_dict(),
        }


@dataclass(slots=True)
class AnalysisResult:
    project_name: str
    project_path: str
    scanned_at: str
    components: list[dict[str, Any]] = field(default_factory=list)
    graph: dict[str, Any] = field(default_factory=dict)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    risk_summary: list[dict[str, Any]] = field(default_factory=list)
    affected_services: list[str] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)
    reports: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
