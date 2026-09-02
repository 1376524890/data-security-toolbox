from __future__ import annotations

import tarfile
import tempfile
from pathlib import Path
from typing import Any

from app.integrations.suricata.parser import parse_rule_dir, parse_rule_file

DEFAULT_ET_OPEN_URL = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz"
DEFAULT_RULE_DIR = Path(__file__).resolve().parent / "rules" / "et_open"


def import_et_open_rules(path: str | Path | None = None, output_dir: str | Path | None = None) -> list[dict[str, Any]]:
    path = Path(path) if path else DEFAULT_RULE_DIR
    output_dir = Path(output_dir) if output_dir else DEFAULT_RULE_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    if path.is_dir():
        rules = parse_rule_dir(path)
    elif path.is_file() and path.suffix == ".rules":
        rules = parse_rule_file(path)
    else:
        rules = _download_and_extract(path, output_dir)
    return rules


def _download_and_extract(archive_path: Path, output_dir: Path) -> list[dict[str, Any]]:
    import requests

    response = requests.get(DEFAULT_ET_OPEN_URL, timeout=60)
    response.raise_for_status()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        archive = tmp / "et.rules.tar.gz"
        archive.write_bytes(response.content)
        with tarfile.open(archive, "r:gz") as handle:
            handle.extractall(output_dir)
    return parse_rule_dir(output_dir)
