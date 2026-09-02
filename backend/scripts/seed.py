#!/usr/bin/env python3
"""Seed the database with default settings and admin placeholder."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.database import SessionLocal
from app.models import SystemSetting, User
from sqlalchemy import select


def main() -> None:
    with SessionLocal() as db:
        if not db.scalar(select(User).where(User.username == "admin")):
            db.add(User(username="admin", role="admin"))
        if not db.scalar(select(SystemSetting).where(SystemSetting.key == "platform")):
            db.add(SystemSetting(key="platform", value={"name": "Data Security Toolbox", "version": "v1.0"}))
        db.commit()
    print("seed complete")


if __name__ == "__main__":
    main()
