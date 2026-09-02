#!/usr/bin/env python3
"""Build offline bundle documentation and image save script."""

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    target = ROOT / "dist-offline"
    target.mkdir(parents=True, exist_ok=True)
    data_dir = ROOT / "backend" / "app" / "integrations" / "offline_data"
    if data_dir.exists():
        shutil.copytree(data_dir, target / "data", dirs_exist_ok=True)
    readme = target / "README.txt"
    readme.write_text(
        "Data Security Toolbox offline bundle\n"
        "1. docker compose build\n"
        "2. docker compose --profile integrations build\n"
        "3. docker save -o security-toolbox-images.tar postgres:16-alpine redis:7-alpine mher/flower:2.0 security-toolbox-backend security-toolbox-frontend\n"
        "4. copy security-toolbox-images.tar, dist-offline, compose files, .env to target\n"
        "5. docker compose --profile integrations up -d\n"
        "6. docker compose exec backend python -c \"from app.core.database import SessionLocal; from app.integrations.offline_manager import import_offline_path; import pathlib; db=SessionLocal(); print(import_offline_path(db, pathlib.Path('/app/data/offline'), resource_type=None, name='bundle', version='1.0').to_dict()); db.close()\"\n",
        encoding="utf-8",
    )
    print(f"offline instructions written to {target}")


if __name__ == "__main__":
    main()
