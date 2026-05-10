from __future__ import annotations

import json
import sqlite3
from typing import Any

from werkzeug.security import check_password_hash, generate_password_hash

from .config import DB_PATH, REPORT_DIR, VULNERABILITY_DB_PATH


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _create_schema(connection)
        _migrate_scan_records(connection)
        _seed_vulnerability_sources(connection)


def save_scan_record(result: dict) -> int:
    risk_levels = [item["risk_level"] for item in result["risk_summary"]]
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _create_schema(connection)
        _migrate_scan_records(connection)
        _seed_vulnerability_sources(connection)

        project_id = _upsert_project(connection, result)
        scan_id = _insert_scan_record(connection, project_id, result, risk_levels)
        _sync_services(connection, scan_id, result)
        _sync_components(connection, scan_id, result)
        _sync_service_relations(connection, scan_id, result)
        _sync_vulnerabilities(connection, scan_id, result)
        _sync_risk_assessments(connection, scan_id, result)
        _sync_propagation_paths(connection, scan_id, result)
        _sync_remediation(connection, scan_id, result)
        _sync_reports(connection, scan_id, result)
        _sync_graph(connection, scan_id, result)
        _sync_statistics(connection, scan_id, result)
        _sync_analysis_methods(connection, scan_id, result)
        _sync_architecture(connection, scan_id, result)
        _sync_module_impacts(connection, scan_id, result)
        return scan_id


def fetch_scan_history(limit: int = 10) -> list[dict]:
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT id, project_name, project_path, scanned_at, vulnerability_count, affected_service_count, risk_levels, report_files
            FROM scan_records
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    items = [dict(row) for row in rows]
    for item in items:
        item["risk_levels"] = json.loads(item["risk_levels"])
        item["report_files"] = json.loads(item["report_files"])
    return items


def fetch_scan_detail(scan_id: int) -> dict | None:
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT result_payload
            FROM scan_records
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()

    if row is None:
        return None
    return json.loads(row["result_payload"])


def fetch_recent_scan_details(limit: int = 2) -> list[dict]:
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT result_payload
            FROM scan_records
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [json.loads(row["result_payload"]) for row in rows]


def fetch_external_vulnerability_records() -> list[dict]:
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        _create_schema(connection)
        rows = connection.execute(
            """
            SELECT source_name, cve_id, component_name, language, severity, cvss_score,
                   description, fixed_version, affected_versions, published_at, last_modified_at
            FROM external_vulnerabilities
            ORDER BY synced_at DESC, cve_id
            """
        ).fetchall()
    records = []
    for row in rows:
        item = dict(row)
        item["affected_versions"] = json.loads(item["affected_versions"] or "[]")
        item["source"] = item.pop("source_name")
        records.append(item)
    return records


def fetch_vulnerability_library(limit: int = 200) -> dict:
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        _create_schema(connection)
        _seed_vulnerability_sources(connection)
        rows = connection.execute(
            """
            SELECT source_name, cve_id, component_name, language, severity, cvss_score,
                   description, fixed_version, affected_versions, published_at, last_modified_at, synced_at
            FROM external_vulnerabilities
            ORDER BY synced_at DESC, cvss_score DESC, cve_id
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        local_count = len(json.loads(VULNERABILITY_DB_PATH.read_text(encoding="utf-8")))
        external_count = connection.execute("SELECT COUNT(*) FROM external_vulnerabilities").fetchone()[0]
    items = []
    for row in rows:
        item = dict(row)
        item["affected_versions"] = json.loads(item["affected_versions"] or "[]")
        items.append(item)
    return {"local_count": local_count, "external_count": external_count, "items": items}


def fetch_vulnerability_sources() -> list[dict]:
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        _create_schema(connection)
        _seed_vulnerability_sources(connection)
        rows = connection.execute(
            """
            SELECT source_name, api_url, enabled, last_synced_at, last_status, last_message
            FROM vulnerability_sources
            ORDER BY source_name
            """
        ).fetchall()
    return [dict(row) for row in rows]


def upsert_external_vulnerabilities(records: list[dict]) -> int:
    if not records:
        return 0
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _create_schema(connection)
        saved = 0
        for item in records:
            connection.execute(
                """
                INSERT INTO external_vulnerabilities (
                    source_name, cve_id, component_name, language, severity, cvss_score,
                    description, fixed_version, affected_versions, references_json,
                    published_at, last_modified_at, raw_payload, synced_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
                ON CONFLICT(source_name, cve_id, component_name, language) DO UPDATE SET
                    severity = excluded.severity,
                    cvss_score = excluded.cvss_score,
                    description = excluded.description,
                    fixed_version = excluded.fixed_version,
                    affected_versions = excluded.affected_versions,
                    references_json = excluded.references_json,
                    published_at = excluded.published_at,
                    last_modified_at = excluded.last_modified_at,
                    raw_payload = excluded.raw_payload,
                    synced_at = excluded.synced_at
                """,
                (
                    item.get("source_name", "NVD"),
                    item["cve_id"],
                    item["component_name"],
                    item.get("language", "unknown"),
                    item.get("severity", "unknown"),
                    item.get("cvss_score", 0),
                    item.get("description", ""),
                    item.get("fixed_version", ""),
                    _to_json(item.get("affected_versions", [])),
                    _to_json(item.get("references", [])),
                    item.get("published_at", ""),
                    item.get("last_modified_at", ""),
                    _to_json(item.get("raw_payload", {})),
                ),
            )
            saved += 1
    return saved


def record_vulnerability_sync(source_name: str, status: str, message: str, record_count: int = 0) -> None:
    with sqlite3.connect(DB_PATH) as connection:
        _create_schema(connection)
        _seed_vulnerability_sources(connection)
        connection.execute(
            """
            UPDATE vulnerability_sources
            SET last_synced_at = datetime('now', 'localtime'), last_status = ?, last_message = ?
            WHERE source_name = ?
            """,
            (status, message, source_name),
        )
        connection.execute(
            """
            INSERT INTO vulnerability_sync_logs (source_name, status, message, record_count, created_at)
            VALUES (?, ?, ?, ?, datetime('now', 'localtime'))
            """,
            (source_name, status, message, record_count),
        )


def create_user(username: str, email: str, password: str) -> tuple[dict | None, str | None]:
    username = username.strip()
    email = email.strip().lower()
    if not username or not email or not password:
        return None, "用户名、邮箱和密码不能为空"
    if len(password) < 6:
        return None, "密码长度至少为 6 位"

    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        _create_schema(connection)
        existing = connection.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email),
        ).fetchone()
        if existing:
            return None, "用户名或邮箱已存在"
        cursor = connection.execute(
            """
            INSERT INTO users (username, email, password_hash, role, status, created_at, updated_at)
            VALUES (?, ?, ?, 'student', 'active', datetime('now', 'localtime'), datetime('now', 'localtime'))
            """,
            (username, email, generate_password_hash(password)),
        )
        user = _fetch_user_by_id(connection, cursor.lastrowid)
        _insert_login_event(connection, cursor.lastrowid, "register", "success")
    return user, None


def authenticate_user(account: str, password: str) -> tuple[dict | None, str | None]:
    account = account.strip().lower()
    if not account or not password:
        return None, "账号和密码不能为空"

    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        _create_schema(connection)
        row = connection.execute(
            """
            SELECT id, username, email, password_hash, role, status, created_at, last_login_at
            FROM users
            WHERE lower(username) = ? OR lower(email) = ?
            """,
            (account, account),
        ).fetchone()
        if row is None or not check_password_hash(row["password_hash"], password):
            if row is not None:
                _insert_login_event(connection, row["id"], "login", "failed")
            return None, "账号或密码错误"
        if row["status"] != "active":
            _insert_login_event(connection, row["id"], "login", "blocked")
            return None, "账号已停用"
        connection.execute(
            "UPDATE users SET last_login_at = datetime('now', 'localtime'), updated_at = datetime('now', 'localtime') WHERE id = ?",
            (row["id"],),
        )
        _insert_login_event(connection, row["id"], "login", "success")
        user = _fetch_user_by_id(connection, row["id"])
    return user, None


def fetch_database_overview() -> dict:
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        tables = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        ).fetchall()
        items = []
        for row in tables:
            table_name = row["name"]
            columns = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
            count = connection.execute(f"SELECT COUNT(*) AS total FROM {table_name}").fetchone()["total"]
            items.append(
                {
                    "name": table_name,
                    "column_count": len(columns),
                    "row_count": count,
                    "columns": [column["name"] for column in columns],
                }
            )
    return {"table_count": len(items), "tables": items}


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_login_at TEXT
        );

        CREATE TABLE IF NOT EXISTS user_login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            event_status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS vulnerability_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT NOT NULL UNIQUE,
            api_url TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_synced_at TEXT,
            last_status TEXT NOT NULL DEFAULT 'pending',
            last_message TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS external_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            component_name TEXT NOT NULL,
            language TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss_score REAL NOT NULL DEFAULT 0,
            description TEXT NOT NULL,
            fixed_version TEXT NOT NULL DEFAULT '',
            affected_versions TEXT NOT NULL,
            references_json TEXT NOT NULL DEFAULT '[]',
            published_at TEXT NOT NULL DEFAULT '',
            last_modified_at TEXT NOT NULL DEFAULT '',
            raw_payload TEXT NOT NULL DEFAULT '{}',
            synced_at TEXT NOT NULL,
            UNIQUE(source_name, cve_id, component_name, language)
        );

        CREATE TABLE IF NOT EXISTS vulnerability_sync_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT NOT NULL,
            status TEXT NOT NULL,
            message TEXT NOT NULL,
            record_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_name TEXT NOT NULL,
            project_path TEXT NOT NULL UNIQUE,
            first_seen_at TEXT NOT NULL,
            last_scanned_at TEXT NOT NULL,
            scan_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS scan_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            project_name TEXT NOT NULL,
            project_path TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            vulnerability_count INTEGER NOT NULL,
            affected_service_count INTEGER NOT NULL,
            component_count INTEGER NOT NULL DEFAULT 0,
            service_count INTEGER NOT NULL DEFAULT 0,
            graph_node_count INTEGER NOT NULL DEFAULT 0,
            graph_edge_count INTEGER NOT NULL DEFAULT 0,
            risk_levels TEXT NOT NULL,
            report_files TEXT NOT NULL DEFAULT '{}',
            result_payload TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(project_id) REFERENCES projects(id)
        );

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            service_name TEXT NOT NULL,
            component_count INTEGER NOT NULL,
            vulnerability_count INTEGER NOT NULL,
            language_set TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_records(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS components (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            component_uid TEXT NOT NULL,
            component_name TEXT NOT NULL,
            version TEXT NOT NULL,
            language TEXT NOT NULL,
            service_name TEXT NOT NULL,
            dependency_type TEXT NOT NULL,
            source_file TEXT NOT NULL,
            is_vulnerable INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(scan_id) REFERENCES scan_records(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS service_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            source_service TEXT NOT NULL,
            target_service TEXT NOT NULL,
            relation_type TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_records(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL UNIQUE,
            component_name TEXT NOT NULL,
            language TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            fixed_version TEXT NOT NULL,
            affected_versions TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            component_uid TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            component_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            service_name TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            score REAL NOT NULL,
            propagation_score REAL NOT NULL,
            affected_service_count INTEGER NOT NULL,
            max_depth INTEGER NOT NULL,
            centrality REAL NOT NULL,
            importance REAL NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_records(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS propagation_paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            component_uid TEXT NOT NULL,
            path_type TEXT NOT NULL,
            path_index INTEGER NOT NULL,
            path_nodes TEXT NOT NULL,
            affected_service TEXT NOT NULL,
            depth INTEGER NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_records(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS risk_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            component_uid TEXT NOT NULL,
            component_name TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            score REAL NOT NULL,
            propagation_score REAL NOT NULL,
            affected_services TEXT NOT NULL,
            reason TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_records(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS remediation_suggestions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            component_uid TEXT NOT NULL,
            component_name TEXT NOT NULL,
            current_version TEXT NOT NULL,
            target_version TEXT NOT NULL,
            service_name TEXT NOT NULL,
            priority INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            score REAL NOT NULL,
            cve_ids TEXT NOT NULL,
            affected_services TEXT NOT NULL,
            suggestion TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_records(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            report_type TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_records(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS graph_nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            node_uid TEXT NOT NULL,
            label TEXT NOT NULL,
            node_type TEXT NOT NULL,
            language TEXT NOT NULL,
            service_name TEXT NOT NULL,
            version TEXT NOT NULL,
            is_vulnerable INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(scan_id) REFERENCES scan_records(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS graph_edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            source_uid TEXT NOT NULL,
            target_uid TEXT NOT NULL,
            relation_type TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_records(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scan_statistics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            metric_group TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            metric_value TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_records(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS analysis_methods (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            component_uid TEXT NOT NULL,
            method_name TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_records(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS architecture_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            architecture_type TEXT NOT NULL,
            description TEXT NOT NULL,
            frontend_modules TEXT NOT NULL,
            backend_modules TEXT NOT NULL,
            gateway_modules TEXT NOT NULL,
            data_modules TEXT NOT NULL,
            languages TEXT NOT NULL,
            service_count INTEGER NOT NULL,
            relation_count INTEGER NOT NULL,
            evidence TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_records(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS module_impacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            component_uid TEXT NOT NULL,
            component_name TEXT NOT NULL,
            component_version TEXT NOT NULL,
            service_name TEXT NOT NULL,
            language TEXT NOT NULL,
            cve_ids TEXT NOT NULL,
            upstream_modules TEXT NOT NULL,
            direct_callers TEXT NOT NULL,
            downstream_modules TEXT NOT NULL,
            affected_modules TEXT NOT NULL,
            impact_scope TEXT NOT NULL,
            impact_summary TEXT NOT NULL,
            readable_paths TEXT NOT NULL,
            raw_paths TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_records(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_components_scan_id ON components(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scan_vulnerabilities_scan_id ON scan_vulnerabilities(scan_id);
        CREATE INDEX IF NOT EXISTS idx_paths_scan_id ON propagation_paths(scan_id);
        CREATE INDEX IF NOT EXISTS idx_risk_scan_id ON risk_assessments(scan_id);
        CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);
        CREATE INDEX IF NOT EXISTS idx_architecture_scan_id ON architecture_profiles(scan_id);
        CREATE INDEX IF NOT EXISTS idx_module_impacts_scan_id ON module_impacts(scan_id);
        CREATE INDEX IF NOT EXISTS idx_user_login_events_user_id ON user_login_events(user_id);
        CREATE INDEX IF NOT EXISTS idx_external_vuln_component ON external_vulnerabilities(component_name, language);
        CREATE INDEX IF NOT EXISTS idx_sync_logs_source ON vulnerability_sync_logs(source_name);
        """
    )


def _migrate_scan_records(connection: sqlite3.Connection) -> None:
    columns = {row[1] for row in connection.execute("PRAGMA table_info(scan_records)").fetchall()}
    migrations = {
        "project_id": "INTEGER",
        "component_count": "INTEGER NOT NULL DEFAULT 0",
        "service_count": "INTEGER NOT NULL DEFAULT 0",
        "graph_node_count": "INTEGER NOT NULL DEFAULT 0",
        "graph_edge_count": "INTEGER NOT NULL DEFAULT 0",
        "report_files": "TEXT NOT NULL DEFAULT '{}'",
        "result_payload": "TEXT NOT NULL DEFAULT '{}'",
    }
    for column, ddl in migrations.items():
        if column not in columns:
            connection.execute(f"ALTER TABLE scan_records ADD COLUMN {column} {ddl}")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_scan_records_project_id ON scan_records(project_id)")


def _seed_vulnerability_sources(connection: sqlite3.Connection) -> None:
    defaults = [
        ("NVD", "https://services.nvd.nist.gov/rest/json/cves/2.0", 1, "pending", "等待同步"),
        ("OSS Index", "https://api.guide.sonatype.com/api/v3/component-report", 1, "pending", "已接入，请配置 OSS_INDEX_USERNAME 与 OSS_INDEX_TOKEN 启用实时同步"),
    ]
    for source in defaults:
        connection.execute(
            """
            INSERT OR IGNORE INTO vulnerability_sources (source_name, api_url, enabled, last_status, last_message)
            VALUES (?, ?, ?, ?, ?)
            """,
            source,
        )
    connection.execute(
        """
        UPDATE vulnerability_sources
        SET enabled = 1,
            api_url = 'https://api.guide.sonatype.com/api/v3/component-report',
            last_message = CASE
                WHEN last_status = 'pending' THEN '已接入，请配置 OSS_INDEX_USERNAME 与 OSS_INDEX_TOKEN 启用实时同步'
                ELSE last_message
            END
        WHERE source_name = 'OSS Index'
        """
    )


def _fetch_user_by_id(connection: sqlite3.Connection, user_id: int) -> dict:
    row = connection.execute(
        """
        SELECT id, username, email, role, status, created_at, last_login_at
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()
    return dict(row)


def _insert_login_event(connection: sqlite3.Connection, user_id: int, event_type: str, event_status: str) -> None:
    connection.execute(
        """
        INSERT INTO user_login_events (user_id, event_type, event_status, created_at)
        VALUES (?, ?, ?, datetime('now', 'localtime'))
        """,
        (user_id, event_type, event_status),
    )


def _upsert_project(connection: sqlite3.Connection, result: dict) -> int:
    row = connection.execute(
        "SELECT id FROM projects WHERE project_path = ?",
        (result["project_path"],),
    ).fetchone()
    if row:
        project_id = row[0]
        connection.execute(
            """
            UPDATE projects
            SET project_name = ?, last_scanned_at = ?, scan_count = scan_count + 1
            WHERE id = ?
            """,
            (result["project_name"], result["scanned_at"], project_id),
        )
        return project_id

    cursor = connection.execute(
        """
        INSERT INTO projects (project_name, project_path, first_seen_at, last_scanned_at, scan_count)
        VALUES (?, ?, ?, ?, 1)
        """,
        (result["project_name"], result["project_path"], result["scanned_at"], result["scanned_at"]),
    )
    return int(cursor.lastrowid)


def _insert_scan_record(connection: sqlite3.Connection, project_id: int, result: dict, risk_levels: list[str]) -> int:
    graph = result.get("graph", {})
    stats = result.get("statistics", {})
    cursor = connection.execute(
        """
        INSERT INTO scan_records (
            project_id,
            project_name,
            project_path,
            scanned_at,
            vulnerability_count,
            affected_service_count,
            component_count,
            service_count,
            graph_node_count,
            graph_edge_count,
            risk_levels,
            report_files,
            result_payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id,
            result["project_name"],
            result["project_path"],
            result["scanned_at"],
            stats.get("vulnerable_component_count", 0),
            stats.get("affected_service_count", 0),
            stats.get("component_count", 0),
            stats.get("service_count", 0),
            len(graph.get("nodes", [])),
            len(graph.get("edges", [])),
            _to_json(risk_levels),
            _to_json(result.get("reports", {})),
            _to_json(result),
        ),
    )
    return int(cursor.lastrowid)


def _sync_services(connection: sqlite3.Connection, scan_id: int, result: dict) -> None:
    components = result.get("components", [])
    vulnerabilities = result.get("vulnerabilities", [])
    service_names = sorted({item["service"] for item in components} | set(result.get("affected_services", [])))
    for service in service_names:
        service_components = [item for item in components if item["service"] == service]
        languages = sorted({item["language"] for item in service_components})
        vulnerability_count = sum(1 for item in vulnerabilities if item["service"] == service)
        connection.execute(
            """
            INSERT INTO services (scan_id, service_name, component_count, vulnerability_count, language_set)
            VALUES (?, ?, ?, ?, ?)
            """,
            (scan_id, service, len(service_components), vulnerability_count, _to_json(languages)),
        )


def _sync_components(connection: sqlite3.Connection, scan_id: int, result: dict) -> None:
    vulnerable = {item["component_id"] for item in result.get("vulnerabilities", [])}
    for item in result.get("components", []):
        connection.execute(
            """
            INSERT INTO components (
                scan_id, component_uid, component_name, version, language, service_name, dependency_type, source_file, is_vulnerable
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                item["component_id"],
                item["name"],
                item["version"],
                item["language"],
                item["service"],
                item["dependency_type"],
                item["source_file"],
                int(item["component_id"] in vulnerable),
            ),
        )


def _sync_service_relations(connection: sqlite3.Connection, scan_id: int, result: dict) -> None:
    for item in result.get("service_relations", []):
        connection.execute(
            """
            INSERT INTO service_relations (scan_id, source_service, target_service, relation_type)
            VALUES (?, ?, ?, ?)
            """,
            (scan_id, item["source"], item["target"], item.get("relation", "service_call")),
        )


def _sync_vulnerabilities(connection: sqlite3.Connection, scan_id: int, result: dict) -> None:
    risk_by_component = {item["component_id"]: item for item in result.get("risk_summary", [])}
    for issue in result.get("vulnerabilities", []):
        risk = risk_by_component.get(issue["component_id"], {})
        for vulnerability in issue.get("vulnerabilities", []):
            connection.execute(
                """
                INSERT OR IGNORE INTO vulnerabilities (
                    cve_id, component_name, language, severity, description, fixed_version, affected_versions
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vulnerability["cve_id"],
                    vulnerability["component_name"],
                    vulnerability["language"],
                    vulnerability["severity"],
                    vulnerability["description"],
                    vulnerability.get("fixed_version", ""),
                    _to_json(vulnerability.get("affected_versions", [])),
                ),
            )
            connection.execute(
                """
                INSERT INTO scan_vulnerabilities (
                    scan_id,
                    component_uid,
                    cve_id,
                    component_name,
                    severity,
                    service_name,
                    risk_level,
                    score,
                    propagation_score,
                    affected_service_count,
                    max_depth,
                    centrality,
                    importance
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    issue["component_id"],
                    vulnerability["cve_id"],
                    issue["component_name"],
                    vulnerability["severity"],
                    issue["service"],
                    risk.get("risk_level", ""),
                    _as_number(risk.get("score", 0)),
                    _as_number(issue.get("propagation_score", 0)),
                    len(issue.get("affected_services", [])),
                    int(issue.get("max_depth", 0)),
                    _as_number(issue.get("centrality", 0)),
                    _as_number(issue.get("importance", 0)),
                ),
            )


def _sync_risk_assessments(connection: sqlite3.Connection, scan_id: int, result: dict) -> None:
    for item in result.get("risk_summary", []):
        connection.execute(
            """
            INSERT INTO risk_assessments (
                scan_id, component_uid, component_name, risk_level, score, propagation_score, affected_services, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                item["component_id"],
                item["component_name"],
                item["risk_level"],
                _as_number(item.get("score", 0)),
                _as_number(item.get("propagation_score", 0)),
                _to_json(item.get("affected_services", [])),
                item.get("reason", ""),
            ),
        )


def _sync_propagation_paths(connection: sqlite3.Connection, scan_id: int, result: dict) -> None:
    for item in result.get("vulnerabilities", []):
        for path_type in ("paths", "shortest_paths"):
            for index, path in enumerate(item.get(path_type, []), start=1):
                affected_service = _last_service_node(path)
                connection.execute(
                    """
                    INSERT INTO propagation_paths (
                        scan_id, component_uid, path_type, path_index, path_nodes, affected_service, depth
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        item["component_id"],
                        path_type,
                        index,
                        _to_json(path),
                        affected_service,
                        max(len(path) - 1, 0),
                    ),
                )


def _sync_remediation(connection: sqlite3.Connection, scan_id: int, result: dict) -> None:
    for item in result.get("remediation", []):
        connection.execute(
            """
            INSERT INTO remediation_suggestions (
                scan_id,
                component_uid,
                component_name,
                current_version,
                target_version,
                service_name,
                priority,
                risk_level,
                score,
                cve_ids,
                affected_services,
                suggestion
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                item["component_id"],
                item["component_name"],
                item["current_version"],
                item["target_version"],
                item["service"],
                int(item.get("priority", 0)),
                item.get("risk_level", ""),
                _as_number(item.get("score", 0)),
                _to_json(item.get("cve_ids", [])),
                _to_json(item.get("affected_services", [])),
                item.get("suggestion", ""),
            ),
        )


def _sync_reports(connection: sqlite3.Connection, scan_id: int, result: dict) -> None:
    for report_type, filename in result.get("reports", {}).items():
        connection.execute(
            """
            INSERT INTO reports (scan_id, report_type, filename, file_path, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (scan_id, report_type, filename, str(REPORT_DIR / filename), result["scanned_at"]),
        )


def _sync_graph(connection: sqlite3.Connection, scan_id: int, result: dict) -> None:
    graph = result.get("graph", {})
    for node in graph.get("nodes", []):
        connection.execute(
            """
            INSERT INTO graph_nodes (
                scan_id, node_uid, label, node_type, language, service_name, version, is_vulnerable
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                node["id"],
                node.get("label", node["id"]),
                node.get("node_type", ""),
                node.get("language", ""),
                node.get("service", ""),
                node.get("version", ""),
                int(node.get("vulnerable", False)),
            ),
        )
    for edge in graph.get("edges", []):
        connection.execute(
            """
            INSERT INTO graph_edges (scan_id, source_uid, target_uid, relation_type)
            VALUES (?, ?, ?, ?)
            """,
            (scan_id, edge["source"], edge["target"], edge.get("relation", "")),
        )


def _sync_statistics(connection: sqlite3.Connection, scan_id: int, result: dict) -> None:
    for group, value in result.get("statistics", {}).items():
        if isinstance(value, dict):
            for metric_name, metric_value in value.items():
                _insert_stat(connection, scan_id, group, metric_name, metric_value)
        else:
            _insert_stat(connection, scan_id, "summary", group, value)

    insights = result.get("insights", {})
    _insert_stat(connection, scan_id, "insights", "vulnerable_ratio", insights.get("vulnerable_ratio", 0))
    for item in insights.get("service_heat", []):
        _insert_stat(connection, scan_id, "service_heat", item["service"], item)


def _sync_analysis_methods(connection: sqlite3.Connection, scan_id: int, result: dict) -> None:
    for issue in result.get("vulnerabilities", []):
        for method in issue.get("analysis_methods", []):
            connection.execute(
                """
                INSERT INTO analysis_methods (scan_id, component_uid, method_name)
                VALUES (?, ?, ?)
                """,
                (scan_id, issue["component_id"], method),
            )


def _sync_architecture(connection: sqlite3.Connection, scan_id: int, result: dict) -> None:
    profile = result.get("architecture_profile") or {}
    if not profile:
        return
    connection.execute(
        """
        INSERT INTO architecture_profiles (
            scan_id,
            architecture_type,
            description,
            frontend_modules,
            backend_modules,
            gateway_modules,
            data_modules,
            languages,
            service_count,
            relation_count,
            evidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            profile.get("architecture_type", ""),
            profile.get("description", ""),
            _to_json(profile.get("frontend_modules", [])),
            _to_json(profile.get("backend_modules", [])),
            _to_json(profile.get("gateway_modules", [])),
            _to_json(profile.get("data_modules", [])),
            _to_json(profile.get("languages", {})),
            int(profile.get("service_count", 0)),
            int(profile.get("relation_count", 0)),
            _to_json(profile.get("evidence", [])),
        ),
    )


def _sync_module_impacts(connection: sqlite3.Connection, scan_id: int, result: dict) -> None:
    for item in result.get("module_impacts", []):
        connection.execute(
            """
            INSERT INTO module_impacts (
                scan_id,
                component_uid,
                component_name,
                component_version,
                service_name,
                language,
                cve_ids,
                upstream_modules,
                direct_callers,
                downstream_modules,
                affected_modules,
                impact_scope,
                impact_summary,
                readable_paths,
                raw_paths
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                item["component_id"],
                item["component_name"],
                item["component_version"],
                item["service"],
                item["language"],
                _to_json(item.get("cve_ids", [])),
                _to_json(item.get("upstream_modules", [])),
                _to_json(item.get("direct_callers", [])),
                _to_json(item.get("downstream_modules", [])),
                _to_json(item.get("affected_modules", [])),
                item.get("impact_scope", ""),
                item.get("impact_summary", ""),
                _to_json(item.get("readable_paths", [])),
                _to_json(item.get("raw_paths", [])),
            ),
        )


def _insert_stat(connection: sqlite3.Connection, scan_id: int, group: str, metric_name: str, value: Any) -> None:
    connection.execute(
        """
        INSERT INTO scan_statistics (scan_id, metric_group, metric_name, metric_value)
        VALUES (?, ?, ?, ?)
        """,
        (scan_id, group, str(metric_name), _to_json(value) if isinstance(value, (dict, list)) else str(value)),
    )


def _last_service_node(path: list[str]) -> str:
    for node in reversed(path):
        if node.startswith("service:"):
            return node.removeprefix("service:")
    return ""


def _as_number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)
