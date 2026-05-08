from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "backend" / "data"
REPORT_DIR = BASE_DIR / "reports"
DB_PATH = BASE_DIR / "backend" / "data" / "scan_history.sqlite3"
SAMPLE_PROJECT_DIR = BASE_DIR / "sample_project"
VULNERABILITY_DB_PATH = DATA_DIR / "vulnerability_db.json"

