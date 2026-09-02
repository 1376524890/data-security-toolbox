#!/usr/bin/env python3
"""Build offline bundle documentation and image save script."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    target = ROOT / "dist-offline"
    target.mkdir(parents=True, exist_ok=True)
    readme = target / "README.txt"
    readme.write_text(
        "Data Security Toolbox offline bundle\n"
        "1. docker compose build\n"
        "2. docker save -o security-toolbox-images.tar postgres:16-alpine redis:7-alpine mher/flower:2.0 security-toolbox-backend security-toolbox-frontend\n"
        "3. copy security-toolbox-images.tar, dist-offline, compose files, .env to target\n",
        encoding="utf-8",
    )
    print(f"offline instructions written to {target}")


if __name__ == "__main__":
    main()

