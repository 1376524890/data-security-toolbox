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

# The free-space floor is a property of the machine running the tests, not of
# the code: without this pin, a host whose data partition happens to be nearly
# full would refuse every upload, so the ingest tests would fail on disk state
# instead of exercising the path they are about. The guard has its own tests
# that drive ``partition_usage`` directly.
os.environ["PCAP_STORAGE_MIN_FREE_GB"] = "0"
os.environ["PCAP_STORAGE_MIN_FREE_PERCENT"] = "0"

Path("./data").mkdir(parents=True, exist_ok=True)
Path("./data/test.db").unlink(missing_ok=True)

from app.core.database import engine  # noqa: E402
from app.models import Base  # noqa: E402

Base.metadata.create_all(bind=engine)
