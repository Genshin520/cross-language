from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from .analysis import analyze_blast_radius
from .graph_builder import build_dependency_graph, graph_to_payload
from .parsers import parse_project_dependencies
from .report_generator import export_reports
from .repositories import save_scan_record
from .risk_evaluator import evaluate_risk
from .vulnerability_matcher import match_vulnerabilities


def run_project_scan(project_path: str) -> dict[str, Any]:
    path = Path(project_path).resolve()
    components = parse_project_dependencies(str(path))
    service_relations = _load_service_relations(path)
    graph = build_dependency_graph(components, service_relations=service_relations)
    matches = match_vulnerabilities(components)
    blast_radius = analyze_blast_radius(graph, matches)
    risk_summary = evaluate_risk(blast_radius)
    vulnerable_nodes = {item["component_id"] for item in blast_radius}

    result: dict[str, Any] = {
        "project_name": path.name,
        "project_path": str(path),
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H-%M-%S"),
        "components": [component.to_dict() for component in components],
        "service_relations": service_relations,
        "graph": graph_to_payload(graph, vulnerable_nodes=vulnerable_nodes),
        "vulnerabilities": blast_radius,
        "risk_summary": risk_summary,
        "affected_services": sorted({service for item in blast_radius for service in item["affected_services"]}),
        "statistics": _build_statistics(components, blast_radius, risk_summary),
    }
    result["insights"] = _build_insights(components, blast_radius, risk_summary)
    result["remediation"] = _build_remediation_plan(blast_radius, risk_summary)
    result["reports"] = export_reports(result)
    save_scan_record(result)
    return result


def _load_service_relations(project_path: Path) -> list[dict]:
    topology_file = project_path / "service-map.json"
    if not topology_file.exists():
        return []

    try:
        payload = json.loads(topology_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    relations: list[dict] = []
    for item in payload.get("relations", []):
        source = item.get("source")
        target = item.get("target")
        if source and target:
            relations.append(
                {
                    "source": source,
                    "target": target,
                    "relation": item.get("relation", "service_call"),
                }
            )
    return relations


def _build_statistics(components: list, blast_radius: list[dict], risk_summary: list[dict]) -> dict:
    language_distribution = dict(Counter(component.language for component in components))
    service_distribution = dict(Counter(component.service for component in components))
    risk_distribution = dict(Counter(item["risk_level"] for item in risk_summary))

    return {
        "component_count": len(components),
        "service_count": len(service_distribution),
        "vulnerable_component_count": len(blast_radius),
        "affected_service_count": len({service for item in blast_radius for service in item["affected_services"]}),
        "language_distribution": language_distribution,
        "service_distribution": service_distribution,
        "risk_distribution": risk_distribution,
    }


def _build_insights(components: list, blast_radius: list[dict], risk_summary: list[dict]) -> dict:
    component_count = len(components)
    vulnerable_count = len(blast_radius)
    vulnerable_ratio = round((vulnerable_count / component_count) * 100, 1) if component_count else 0

    top_risk = max(risk_summary, key=lambda item: item["score"], default=None)
    deepest_spread = max(blast_radius, key=lambda item: item["max_depth"], default=None)

    service_heat = []
    for service in sorted({component.service for component in components}):
        service_heat.append(
            {
                "service": service,
                "component_count": sum(1 for component in components if component.service == service),
                "vulnerability_count": sum(1 for item in blast_radius if item["service"] == service),
            }
        )

    service_heat.sort(key=lambda item: (item["vulnerability_count"], item["component_count"]), reverse=True)

    return {
        "vulnerable_ratio": vulnerable_ratio,
        "top_risk_component": top_risk,
        "deepest_spread_component": deepest_spread,
        "service_heat": service_heat,
    }


def _build_remediation_plan(blast_radius: list[dict], risk_summary: list[dict]) -> list[dict]:
    risk_by_component = {item["component_id"]: item for item in risk_summary}
    items = []
    for issue in blast_radius:
        risk = risk_by_component.get(issue["component_id"], {})
        fixed_versions = sorted({vuln["fixed_version"] for vuln in issue["vulnerabilities"] if vuln.get("fixed_version")})
        cve_ids = [vuln["cve_id"] for vuln in issue["vulnerabilities"]]
        items.append(
            {
                "component_id": issue["component_id"],
                "component_name": issue["component_name"],
                "current_version": issue["component_version"],
                "target_version": fixed_versions[-1] if fixed_versions else "请参考官方安全公告",
                "service": issue["service"],
                "affected_services": issue["affected_services"],
                "cve_ids": cve_ids,
                "risk_level": risk.get("risk_level", "待评估"),
                "score": risk.get("score", 0),
                "priority": _repair_priority(risk.get("risk_level", ""), len(issue["affected_services"])),
                "suggestion": _repair_suggestion(issue, risk),
            }
        )

    return sorted(items, key=lambda item: (item["priority"], item["score"]), reverse=True)


def _repair_priority(risk_level: str, affected_service_count: int) -> int:
    base = {"严重风险": 4, "高风险": 3, "中风险": 2, "低风险": 1}.get(risk_level, 1)
    return base + (1 if affected_service_count > 1 else 0)


def _repair_suggestion(issue: dict, risk: dict) -> str:
    if risk.get("risk_level") in {"严重风险", "高风险"}:
        return "建议优先安排修复，升级后重新扫描确认影响范围。"
    if issue["affected_services"]:
        return "建议纳入近期迭代修复，并关注受影响服务的回归测试。"
    return "建议持续跟踪版本公告，结合业务暴露面决定修复窗口。"
