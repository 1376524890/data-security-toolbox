from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from app.integrations.suricata.parser import parse_eve_file


def run_suricata(pcap_path: Path, output_dir: Path, binary: str = "", timeout: int = 300) -> list[dict[str, Any]]:
    pcap_path = Path(pcap_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    binary = binary or shutil.which("suricata") or ""
    if not binary:
        return []
    try:
        subprocess.run([binary, "-r", str(pcap_path), "-l", str(output_dir), "-q"], check=False, timeout=timeout, capture_output=True)
    except Exception:
        return []
    eve = output_dir / "eve.json"
    return parse_eve_file(eve) if eve.exists() else []
