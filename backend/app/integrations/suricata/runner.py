from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import dpkt

from app.integrations.suricata.parser import parse_eve_file
from app.rules.library import rule_files as library_rule_files


def compatible_capture(path: Path, output_dir: Path) -> Path:
    """Translate cooked-v2 headers for Suricata 7, preserving captured payloads."""
    if not path.is_file():
        return path
    with path.open('rb') as handle:
        try:
            reader = dpkt.pcap.Reader(handle)
        except ValueError:
            handle.seek(0)
            reader = dpkt.pcapng.Reader(handle)
        if reader.datalink() != dpkt.pcap.DLT_LINUX_SLL2:
            return path
        converted = output_dir / 'suricata-compatible.pcap'
        with converted.open('wb') as target:
            writer = dpkt.pcap.Writer(target, linktype=dpkt.pcap.DLT_LINUX_SLL, nano=True)
            for timestamp, raw in reader:
                header = dpkt.sll2.SLL2(raw)
                cooked = dpkt.sll.SLL(type=header.type, hrd=header.hrd, hlen=header.hlen,
                                      hdr=header.hdr, ethtype=header.ethtype)
                writer.writepkt(cooked.pack_hdr() + raw[20:], ts=timestamp)
        return converted


def run_suricata(pcap_path: Path, output_dir: Path, binary: str = "", timeout: int = 300, rules_dir: Path | None = None) -> list[dict[str, Any]]:
    pcap_path = Path(pcap_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    binary = binary or shutil.which("suricata") or ""
    if not binary:
        return []
    pcap_path = compatible_capture(pcap_path, output_dir)
    # -q selects NFQUEUE; it is not a quiet flag and conflicts with PCAP replay.
    command = [binary, "-r", str(pcap_path), "-l", str(output_dir),
               '--runmode', 'single', '--set', 'unix-command.enabled=no']
    rule_files = library_rule_files('suricata')
    if rules_dir and rules_dir.exists():
        rule_files += sorted(rules_dir.rglob('*.rules'))
    if rule_files:
        # One merged input is supported consistently across installed engine versions.
        merged = output_dir / 'active.rules'
        merged.write_text('\n'.join(path.read_text(encoding='utf-8') for path in dict.fromkeys(rule_files)), encoding='utf-8')
        command += ['-S', str(merged)]
    completed = subprocess.run(command, check=False, timeout=timeout, capture_output=True)
    if getattr(completed, 'returncode', 0):
        error = completed.stderr.decode('utf-8', errors='replace')[-1500:]
        raise RuntimeError(f'Suricata analysis failed: {error}')
    eve = output_dir / "eve.json"
    return parse_eve_file(eve) if eve.exists() else []
