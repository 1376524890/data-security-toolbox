from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from app.integrations.suricata.parser import parse_eve_file


def run_suricata(pcap_path: Path, output_dir: Path, binary: str = "", timeout: int = 300, rules_dir: Path | None = None) -> list[dict[str, Any]]:
    pcap_path = Path(pcap_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    binary = binary or shutil.which("suricata") or ""
    if not binary:
        return []
    command = [binary, "-r", str(pcap_path), "-l", str(output_dir), "-q"]
    if rules_dir and rules_dir.exists():
        rule_files = sorted(rules_dir.glob("*.rules"))
        if rule_files:
            command = [binary, "-r", str(pcap_path), "-l", str(output_dir), "-q", "-S", ",".join(str(path) for path in rule_files)]
    try:
        subprocess.run(command, check=False, timeout=timeout, capture_output=True)
    except Exception:
        return []
    eve = output_dir / "eve.json"
    return parse_eve_file(eve) if eve.exists() else []
