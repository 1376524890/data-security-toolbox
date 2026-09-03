import os
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///./data/test.db"
os.environ["STORAGE_DIR"] = "./data/test_storage"
os.environ["REPORT_DIR"] = "./data/test_reports"

Path("./data").mkdir(parents=True, exist_ok=True)
Path("./data/test.db").unlink(missing_ok=True)

from app.core.database import engine  # noqa: E402
from app.models import Base  # noqa: E402

Base.metadata.create_all(bind=engine)
