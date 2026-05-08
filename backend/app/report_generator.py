from __future__ import annotations

import json
import re

from .config import REPORT_DIR


def export_reports(result: dict) -> dict[str, str]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = _safe_filename(result["project_name"])
    timestamp = _safe_filename(result["scanned_at"])

    json_path = REPORT_DIR / f"{safe_name}_{timestamp}.json"
    txt_path = REPORT_DIR / f"{safe_name}_{timestamp}.txt"
    html_path = REPORT_DIR / f"{safe_name}_{timestamp}.html"

    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    txt_path.write_text(_build_text_report(result), encoding="utf-8")
    html_path.write_text(_build_html_report(result), encoding="utf-8")

    return {"json": json_path.name, "txt": txt_path.name, "html": html_path.name}


def _safe_filename(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return normalized.strip("_") or "scan_report"


def _build_text_report(result: dict) -> str:
    lines = [
        f"项目名称: {result['project_name']}",
        f"扫描时间: {result['scanned_at']}",
        f"组件总数: {result['statistics']['component_count']}",
        f"漏洞组件数: {result['statistics']['vulnerable_component_count']}",
        f"受影响服务数: {result['statistics']['affected_service_count']}",
        "",
        "漏洞分析结果:",
    ]
    for item in result["vulnerabilities"]:
        cve_ids = ", ".join(v["cve_id"] for v in item["vulnerabilities"])
        services = ", ".join(item["affected_services"]) or "无"
        lines.extend(
            [
                f"- 组件: {item['component_name']} {item['component_version']}",
                f"  漏洞: {cve_ids}",
                f"  受影响服务: {services}",
                f"  传播深度: {item['max_depth']}",
            ]
        )
    return "\n".join(lines)


def _build_html_report(result: dict) -> str:
    stats = result["statistics"]
    vuln_items = "".join(
        (
            "<li>"
            f"<strong>{item['component_name']} {item['component_version']}</strong> - "
            f"影响服务: {', '.join(item['affected_services']) or '无'}"
            "</li>"
        )
        for item in result["vulnerabilities"]
    )
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>分析报告 - {result['project_name']}</title>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; margin: 40px; background: #f5f7fb; color: #172033; }}
    .card {{ background: white; border-radius: 16px; padding: 24px; margin-bottom: 20px; box-shadow: 0 12px 30px rgba(23, 32, 51, 0.08); }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{result['project_name']}</h1>
    <p>扫描时间：{result['scanned_at']}</p>
    <p>组件总数：{stats['component_count']} | 漏洞组件数：{stats['vulnerable_component_count']} | 受影响服务数：{stats['affected_service_count']}</p>
  </div>
  <div class="card">
    <h2>漏洞清单</h2>
    <ul>{vuln_items}</ul>
  </div>
</body>
</html>"""
