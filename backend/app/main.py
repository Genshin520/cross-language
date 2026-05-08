from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_from_directory

from .config import REPORT_DIR, SAMPLE_PROJECT_DIR
from .repositories import fetch_recent_scan_details, fetch_scan_detail, fetch_scan_history, init_db
from .scanner import run_project_scan


def register_routes(app: Flask) -> None:
    init_db()

    @app.get("/")
    def index():
        return render_template("home.html", page="home")

    @app.get("/analysis")
    def analysis_page():
        return render_template("analysis.html", page="analysis")

    @app.get("/risk")
    def risk_page():
        return render_template("risk.html", page="risk")

    @app.get("/graph")
    def graph_page():
        return render_template("graph.html", page="graph")

    @app.get("/history")
    def history_page():
        return render_template("history.html", page="history")

    @app.get("/reports")
    def reports_page():
        return render_template("reports.html", page="reports")

    @app.get("/remediation")
    def remediation_page():
        return render_template("remediation.html", page="remediation")

    @app.get("/compare")
    def compare_page():
        return render_template("compare.html", page="compare")

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/api/history")
    def history():
        return jsonify({"items": fetch_scan_history()})

    @app.get("/api/compare/latest")
    def compare_latest():
        scans = fetch_recent_scan_details(2)
        if len(scans) < 2:
            return _json_error("至少需要两次扫描记录才能进行对比", 404)
        return jsonify(_compare_scans(scans[1], scans[0]))

    @app.get("/api/history/<int:scan_id>")
    def history_detail(scan_id: int):
        item = fetch_scan_detail(scan_id)
        if item is None:
            return _json_error("未找到对应的扫描记录", 404)
        return jsonify(item)

    @app.get("/api/sample")
    def sample():
        return jsonify(run_project_scan(str(SAMPLE_PROJECT_DIR)))

    @app.get("/api/reports/<path:filename>")
    def report_file(filename: str):
        if Path(filename).name != filename:
            return _json_error("报告文件名不合法", 400)
        report_path = REPORT_DIR / filename
        if not report_path.exists():
            return _json_error("报告文件不存在", 404)
        return send_from_directory(REPORT_DIR, filename, as_attachment=True)

    @app.post("/api/scan")
    def scan():
        payload = request.get_json(silent=True) or {}
        project_path = payload.get("project_path", "").strip()
        validation_error = _validate_project_path(project_path)
        if validation_error:
            return validation_error
        return jsonify(run_project_scan(project_path))


def _validate_project_path(project_path: str):
    if not project_path:
        return _json_error("项目路径不能为空", 400)

    path = Path(project_path)
    if not path.exists():
        return _json_error("项目路径不存在", 404)
    if not path.is_dir():
        return _json_error("项目路径必须是一个目录", 400)
    return None


def _json_error(message: str, status_code: int):
    return jsonify({"error": message}), status_code


def _compare_scans(previous: dict, current: dict) -> dict:
    previous_vulns = {item["component_id"]: item for item in previous.get("vulnerabilities", [])}
    current_vulns = {item["component_id"]: item for item in current.get("vulnerabilities", [])}
    previous_components = {item["component_id"]: item for item in previous.get("components", [])}
    current_components = {item["component_id"]: item for item in current.get("components", [])}

    new_risks = sorted(set(current_vulns) - set(previous_vulns))
    resolved_risks = sorted(set(previous_vulns) - set(current_vulns))
    unchanged_risks = sorted(set(previous_vulns) & set(current_vulns))

    return {
        "previous": _scan_snapshot(previous),
        "current": _scan_snapshot(current),
        "delta": {
            "component_count": current["statistics"]["component_count"] - previous["statistics"]["component_count"],
            "vulnerability_count": current["statistics"]["vulnerable_component_count"] - previous["statistics"]["vulnerable_component_count"],
            "affected_service_count": current["statistics"]["affected_service_count"] - previous["statistics"]["affected_service_count"],
        },
        "new_risks": [_component_label(current_components, current_vulns, component_id) for component_id in new_risks],
        "resolved_risks": [_component_label(previous_components, previous_vulns, component_id) for component_id in resolved_risks],
        "unchanged_risks": [_component_label(current_components, current_vulns, component_id) for component_id in unchanged_risks],
    }


def _scan_snapshot(scan: dict) -> dict:
    return {
        "project_name": scan["project_name"],
        "scanned_at": scan["scanned_at"],
        "component_count": scan["statistics"]["component_count"],
        "vulnerability_count": scan["statistics"]["vulnerable_component_count"],
        "affected_service_count": scan["statistics"]["affected_service_count"],
    }


def _component_label(components: dict, vulnerabilities: dict, component_id: str) -> dict:
    component = components.get(component_id, {})
    vulnerability = vulnerabilities.get(component_id, {})
    return {
        "component_id": component_id,
        "name": component.get("name") or vulnerability.get("component_name") or component_id,
        "version": component.get("version") or vulnerability.get("component_version") or "",
        "service": component.get("service") or vulnerability.get("service") or "",
    }


if __name__ == "__main__":
    from . import create_app

    application = create_app()
    application.run(debug=True, port=int(os.environ.get("PORT", "5000")))
