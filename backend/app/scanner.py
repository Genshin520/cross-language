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
    result["architecture_profile"] = _build_architecture_profile(components, service_relations)
    result["module_impacts"] = _build_module_impacts(blast_radius, service_relations)
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


def _build_architecture_profile(components: list, service_relations: list[dict]) -> dict:
    services = sorted({component.service for component in components})
    language_distribution = Counter(component.language for component in components)
    frontend_services = _match_services(services, ("frontend", "portal", "admin", "web", "ui"))
    gateway_services = _match_services(services, ("gateway", "api-gateway"))
    data_services = _match_services(services, ("analytics", "data", "report"))
    backend_services = sorted(set(services) - set(frontend_services) - set(data_services))

    dominant_languages = sorted(language_distribution, key=language_distribution.get, reverse=True)
    has_frontend = bool(frontend_services) or "javascript" in language_distribution
    has_backend = bool({"java", "python"} & set(language_distribution))
    has_gateway = bool(gateway_services)
    relation_count = len(service_relations)

    if has_frontend and has_backend and has_gateway:
        architecture_type = "多语言前后端分离微服务架构"
    elif has_frontend and has_backend:
        architecture_type = "前后端分离的多语言 Web 应用架构"
    elif has_backend and relation_count:
        architecture_type = "后端服务化架构"
    elif "java" in language_distribution:
        architecture_type = "Java 后端依赖项目"
    elif "python" in language_distribution:
        architecture_type = "Python 后端依赖项目"
    elif "javascript" in language_distribution:
        architecture_type = "JavaScript 前端依赖项目"
    else:
        architecture_type = "通用多组件依赖项目"

    description = (
        f"系统识别到 {len(services)} 个模块/服务，涉及 {', '.join(dominant_languages) or '未知语言'}。"
        f"其中前端入口模块 {len(frontend_services)} 个，后端/业务模块 {len(backend_services)} 个，"
        f"服务调用关系 {relation_count} 条。"
    )

    return {
        "architecture_type": architecture_type,
        "description": description,
        "frontend_modules": frontend_services,
        "backend_modules": backend_services,
        "gateway_modules": gateway_services,
        "data_modules": data_services,
        "languages": dict(language_distribution),
        "service_count": len(services),
        "relation_count": relation_count,
        "evidence": [
            f"语言分布：{', '.join(f'{language} {count} 个组件' for language, count in language_distribution.items())}",
            f"服务模块：{', '.join(services)}",
            f"服务关系数量：{relation_count}",
        ],
    }


def _build_module_impacts(blast_radius: list[dict], service_relations: list[dict]) -> list[dict]:
    callers_by_service: dict[str, set[str]] = {}
    callees_by_service: dict[str, set[str]] = {}
    for relation in service_relations:
        source = relation["source"]
        target = relation["target"]
        callers_by_service.setdefault(target, set()).add(source)
        callees_by_service.setdefault(source, set()).add(target)

    impacts = []
    for issue in blast_radius:
        service = issue["service"]
        upstream_modules = sorted(set(issue.get("affected_services", [])) - {service})
        direct_callers = sorted(callers_by_service.get(service, set()))
        downstream_modules = sorted(_collect_downstream_services(service, callees_by_service))
        readable_paths = [_readable_path(path) for path in issue.get("shortest_paths", []) or issue.get("paths", [])]
        cve_ids = [vulnerability["cve_id"] for vulnerability in issue.get("vulnerabilities", [])]

        impacts.append(
            {
                "component_id": issue["component_id"],
                "component_name": issue["component_name"],
                "component_version": issue["component_version"],
                "service": service,
                "language": issue["language"],
                "cve_ids": cve_ids,
                "upstream_modules": upstream_modules,
                "direct_callers": direct_callers,
                "downstream_modules": downstream_modules,
                "affected_modules": issue.get("affected_services", []),
                "impact_scope": _impact_scope(len(upstream_modules), len(downstream_modules)),
                "impact_summary": _impact_summary(issue, upstream_modules, downstream_modules),
                "readable_paths": readable_paths,
                "raw_paths": issue.get("shortest_paths", []) or issue.get("paths", []),
            }
        )
    return sorted(impacts, key=lambda item: (len(item["affected_modules"]), len(item["downstream_modules"])), reverse=True)


def _match_services(services: list[str], keywords: tuple[str, ...]) -> list[str]:
    return [service for service in services if any(keyword in service.lower() for keyword in keywords)]


def _collect_downstream_services(service: str, callees_by_service: dict[str, set[str]]) -> set[str]:
    visited: set[str] = set()
    stack = list(callees_by_service.get(service, set()))
    while stack:
        current = stack.pop()
        if current in visited:
            continue
        visited.add(current)
        stack.extend(callees_by_service.get(current, set()) - visited)
    return visited


def _readable_path(path: list[str]) -> str:
    return " -> ".join(_readable_node(node) for node in path)


def _readable_node(node: str) -> str:
    if node.startswith("service:"):
        return f"服务模块 {node.removeprefix('service:')}"
    parts = node.split(":")
    if len(parts) >= 5 and parts[0] == "component":
        return f"依赖组件 {parts[3]} {parts[4]}"
    return node


def _impact_scope(upstream_count: int, downstream_count: int) -> str:
    total = upstream_count + downstream_count
    if total >= 6:
        return "跨多模块高影响"
    if total >= 3:
        return "中等范围模块影响"
    if total >= 1:
        return "局部模块影响"
    return "单模块影响"


def _impact_summary(issue: dict, upstream_modules: list[str], downstream_modules: list[str]) -> str:
    upstream_text = "、".join(upstream_modules) if upstream_modules else "暂无明显上游调用模块"
    downstream_text = "、".join(downstream_modules) if downstream_modules else "暂无明显下游依赖模块"
    return (
        f"{issue['service']} 中的 {issue['component_name']} {issue['component_version']} 命中漏洞后，"
        f"可能影响上游模块：{upstream_text}；同时需要关注其下游依赖/调用模块：{downstream_text}。"
    )


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
