from __future__ import annotations


SEVERITY_SCORE = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def evaluate_risk(analysis_results: list[dict]) -> list[dict]:
    reports: list[dict] = []
    for item in analysis_results:
        highest_severity = max(
            (SEVERITY_SCORE.get(vuln["severity"].lower(), 1) for vuln in item["vulnerabilities"]),
            default=1,
        )
        service_count = len(item["affected_services"])
        depth = item["max_depth"]
        propagation_score = item.get("propagation_score", 0)

        score = round(highest_severity * 1.6 + service_count + depth * 0.8 + propagation_score * 0.2, 2)
        reports.append(
            {
                "component_id": item["component_id"],
                "component_name": item["component_name"],
                "score": score,
                "risk_level": _risk_level(score),
                "affected_services": item["affected_services"],
                "propagation_score": propagation_score,
                "reason": _risk_reason(highest_severity, service_count, depth, propagation_score),
            }
        )
    return reports


def _risk_level(score: float) -> str:
    if score >= 9:
        return "严重风险"
    if score >= 7:
        return "高风险"
    if score >= 4:
        return "中风险"
    return "低风险"


def _risk_reason(severity: int, service_count: int, depth: int, propagation_score: float) -> str:
    parts = []
    if severity >= 4:
        parts.append("漏洞严重等级高")
    if service_count > 1:
        parts.append("影响多个服务")
    if depth > 1:
        parts.append("存在较深传播路径")
    if propagation_score >= 5:
        parts.append("综合传播评分较高")
    return "、".join(parts) if parts else "影响范围较小"
