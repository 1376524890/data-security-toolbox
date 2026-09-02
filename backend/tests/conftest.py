import os
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///./data/test.db"
os.environ["STORAGE_DIR"] = "./data/test_storage"
os.environ["REPORT_DIR"] = "./data/test_reports"

Path("./data").mkdir(parents=True, exist_ok=True)

