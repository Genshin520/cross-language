from __future__ import annotations

import json
import sqlite3

from .config import DB_PATH


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_name TEXT NOT NULL,
                project_path TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                vulnerability_count INTEGER NOT NULL,
                affected_service_count INTEGER NOT NULL,
                risk_levels TEXT NOT NULL
            )
            """
        )
        _ensure_column(connection, "scan_records", "report_files", "TEXT NOT NULL DEFAULT '{}'")
        _ensure_column(connection, "scan_records", "result_payload", "TEXT NOT NULL DEFAULT '{}'")


def save_scan_record(result: dict) -> None:
    risk_levels = [item["risk_level"] for item in result["risk_summary"]]
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            INSERT INTO scan_records (
                project_name,
                project_path,
                scanned_at,
                vulnerability_count,
                affected_service_count,
                risk_levels,
                report_files,
                result_payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["project_name"],
                result["project_path"],
                result["scanned_at"],
                result["statistics"]["vulnerable_component_count"],
                result["statistics"]["affected_service_count"],
                json.dumps(risk_levels, ensure_ascii=False),
                json.dumps(result["reports"], ensure_ascii=False),
                json.dumps(result, ensure_ascii=False),
            ),
        )


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


def _ensure_column(connection: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
