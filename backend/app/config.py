from pathlib import Path
import os


BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "backend" / "data"
REPORT_DIR = BASE_DIR / "reports"
DB_PATH = BASE_DIR / "backend" / "data" / "scan_history.sqlite3"
SAMPLE_PROJECT_DIR = BASE_DIR / "sample_project"
VULNERABILITY_DB_PATH = DATA_DIR / "vulnerability_db.json"
UPLOAD_DIR = DATA_DIR / "uploaded_projects"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_REQUEST_TIMEOUT = 20
OSS_INDEX_API_URL = os.environ.get("OSS_INDEX_API_URL", "https://api.guide.sonatype.com/api/v3/component-report")
OSS_INDEX_USERNAME = os.environ.get("OSS_INDEX_USERNAME", "")
OSS_INDEX_TOKEN = os.environ.get("OSS_INDEX_TOKEN", "")
