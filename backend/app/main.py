from __future__ import annotations

import os
import shutil
import uuid
import zipfile
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_from_directory, session
from werkzeug.utils import secure_filename

from .config import REPORT_DIR, SAMPLE_PROJECT_DIR, UPLOAD_DIR
from .repositories import (
    authenticate_user,
    create_user,
    fetch_scan_detail,
    fetch_scan_history,
    fetch_recent_scan_details,
    fetch_vulnerability_library,
    fetch_vulnerability_sources,
    init_db,
)
from .scanner import run_project_scan
from .vulnerability_sync import sync_nvd_for_components, sync_oss_index_for_components, sync_vulnerability_sources


def register_routes(app: Flask) -> None:
    init_db()

    @app.get("/")
    def index():
        return render_template("login.html", page="login")

    @app.get("/home")
    def home_page():
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

    @app.get("/visualization")
    def visualization_page():
        return render_template("visualization.html", page="visualization")

    @app.get("/history")
    def history_page():
        return render_template("history.html", page="history")

    @app.get("/reports")
    def reports_page():
        return render_template("reports.html", page="reports")

    @app.get("/remediation")
    def remediation_page():
        return render_template("remediation.html", page="remediation")

    @app.get("/vulnerabilities")
    def vulnerabilities_page():
        return render_template("vulnerabilities.html", page="vulnerabilities")

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/api/session")
    def current_session():
        return jsonify({"authenticated": "user" in session, "user": session.get("user")})

    @app.post("/api/register")
    def register():
        payload = request.get_json(silent=True) or {}
        user, error = create_user(
            payload.get("username", ""),
            payload.get("email", ""),
            payload.get("password", ""),
        )
        if error:
            return _json_error(error, 400)
        session["user"] = user
        return jsonify({"user": user})

    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        user, error = authenticate_user(payload.get("account", ""), payload.get("password", ""))
        if error:
            return _json_error(error, 400)
        session["user"] = user
        return jsonify({"user": user})

    @app.post("/api/logout")
    def logout():
        session.pop("user", None)
        return jsonify({"ok": True})

    @app.get("/api/history")
    def history():
        return jsonify({"items": fetch_scan_history()})

    @app.get("/api/vulnerability-sources")
    def vulnerability_sources():
        return jsonify({"items": fetch_vulnerability_sources()})

    @app.get("/api/vulnerabilities")
    def vulnerabilities():
        return jsonify(fetch_vulnerability_library())

    @app.post("/api/vulnerabilities/sync")
    def sync_vulnerabilities():
        try:
            components = _components_for_sync(request.get_json(silent=True) or {})
            result = sync_vulnerability_sources(components)
            return jsonify(result)
        except Exception as exc:
            return _json_error(f"漏洞源同步失败：{exc}", 500)

    @app.post("/api/vulnerabilities/sync/<source_name>")
    def sync_vulnerability_source(source_name: str):
        try:
            components = _components_for_sync(request.get_json(silent=True) or {})
            if source_name == "nvd":
                result = sync_nvd_for_components(components)
            elif source_name == "oss":
                result = sync_oss_index_for_components(components)
            else:
                return _json_error("未知漏洞源", 400)
            return jsonify(result)
        except Exception as exc:
            return _json_error(f"漏洞源同步失败：{exc}", 500)

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

    @app.post("/api/scan-upload")
    def scan_upload():
        files = request.files.getlist("files")
        archive = request.files.get("archive")
        if not files and not archive:
            return _json_error("请先选择项目文件夹或 ZIP 项目包", 400)

        upload_root = UPLOAD_DIR / uuid.uuid4().hex
        upload_root.mkdir(parents=True, exist_ok=True)
        try:
            if archive and archive.filename:
                target = upload_root / secure_filename(archive.filename)
                archive.save(target)
                if target.suffix.lower() != ".zip" or not zipfile.is_zipfile(target):
                    return _json_error("当前仅支持上传 ZIP 项目包", 400)
                extract_dir = upload_root / "project"
                extract_dir.mkdir(parents=True, exist_ok=True)
                _safe_extract_zip(target, extract_dir)
                project_path = _first_project_directory(extract_dir)
            else:
                project_path = upload_root / "project"
                project_path.mkdir(parents=True, exist_ok=True)
                for file in files:
                    relative_name = file.filename or secure_filename(file.name or "uploaded-file")
                    destination = _safe_upload_path(project_path, relative_name)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    file.save(destination)
            return jsonify(run_project_scan(str(project_path)))
        except ValueError as exc:
            return _json_error(str(exc), 400)
        except Exception as exc:
            shutil.rmtree(upload_root, ignore_errors=True)
            return _json_error(f"上传扫描失败：{exc}", 500)


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


def _components_for_sync(payload: dict) -> list[dict]:
    component_names = [name.strip() for name in payload.get("components", []) if str(name).strip()]
    latest = fetch_recent_scan_details(1)
    if component_names:
        latest_components = latest[0].get("components", []) if latest else []
        by_name = {item.get("name", ""): item for item in latest_components}
        return [by_name.get(name, {"name": name}) for name in component_names]
    return latest[0].get("components", []) if latest else []


def _safe_upload_path(root: Path, relative_name: str) -> Path:
    safe_parts = [secure_filename(part) for part in Path(relative_name).parts if part not in {"", ".", ".."}]
    if not safe_parts:
        raise ValueError("上传文件名不合法")
    destination = root.joinpath(*safe_parts).resolve()
    if not str(destination).startswith(str(root.resolve())):
        raise ValueError("上传路径不合法")
    return destination


def _safe_extract_zip(zip_path: Path, target_dir: Path) -> None:
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            destination = (target_dir / member.filename).resolve()
            if not str(destination).startswith(str(target_dir.resolve())):
                raise ValueError("ZIP 文件包含不安全路径")
        archive.extractall(target_dir)


def _first_project_directory(root: Path) -> Path:
    children = [item for item in root.iterdir() if item.is_dir()]
    files = [item for item in root.iterdir() if item.is_file()]
    return children[0] if len(children) == 1 and not files else root


if __name__ == "__main__":
    from . import create_app

    application = create_app()
    application.run(debug=True, port=int(os.environ.get("PORT", "5000")))
