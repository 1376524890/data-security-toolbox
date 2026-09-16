import os
import tempfile
from pathlib import Path

# Tests must never inherit the operator's production .env. The API middleware
# switches to strict admin auth when APP_ENV=production and the probe
# registration endpoint requires the real bootstrap token, so both are pinned
# to isolated test values before any application module is imported.
_TEST_ROOT = Path(tempfile.gettempdir()) / "dst-test-runtime"
_TEST_ROOT.mkdir(parents=True, exist_ok=True)

os.environ["APP_ENV"] = "development"
os.environ["PROBE_BOOTSTRAP_TOKEN"] = ""
os.environ["DATABASE_URL"] = "sqlite:///./data/test.db"
os.environ["STORAGE_DIR"] = "./data/test_storage"
os.environ["REPORT_DIR"] = "./data/test_reports"
os.environ["INTEGRATION_DIR"] = str(_TEST_ROOT / "integrations")
os.environ["OFFLINE_DIR"] = str(_TEST_ROOT / "offline")
# Presidio stays at its normal default: the optional NLP dependency is absent in
# the test environment, which is exactly the degradation path we want covered.
os.environ["ADMIN_PASSWORD"] = "test-admin-password"

Path("./data").mkdir(parents=True, exist_ok=True)
Path("./data/test.db").unlink(missing_ok=True)

from app.core.database import engine  # noqa: E402
from app.models import Base  # noqa: E402

Base.metadata.create_all(bind=engine)
