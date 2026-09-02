from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from app.integrations.zeek.parser import parse_zeek_dir


def run_zeek(pcap_path: Path, output_dir: Path, binary: str = "", timeout: int = 300) -> list[dict[str, Any]]:
    pcap_path = Path(pcap_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    binary = binary or shutil.which("zeek") or ""
    if not binary:
        return []
    command = [binary, "-C", "-r", str(pcap_path), "local"]
    # Zeek accepts LogAscii::use_json=T to emit JSON logs on recent versions.
    if shutil.which("zeek"):
        command = [binary, "-C", "-r", str(pcap_path), "-e", "LogAscii::use_json=T", "local"]
    try:
        subprocess.run(command, cwd=str(output_dir), check=False, timeout=timeout, capture_output=True)
    except Exception:
        return []
    return parse_zeek_dir(output_dir)


def run_zeek_payload(payload: dict[str, Any], output_dir: Path) -> list[dict[str, Any]]:
    pcap = payload.get("pcap") or payload.get("path")
    if not pcap:
        return []
    return run_zeek(Path(pcap), output_dir, str(payload.get("binary", "")))
