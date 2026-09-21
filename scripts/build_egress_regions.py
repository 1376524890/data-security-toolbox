"""Build the offline CIDR→country table the egress report classifies against.

Source: the five RIR ``delegated-*-latest`` files (authoritative registry
allocations, not a scraped guess). Only ``ipv4`` + ``allocated``/``assigned``
records are kept, grouped by country code so a country appears once instead of
once per range — the difference between a usable file and a 15 MB one.

The output is *data*, not a fact the code invents: regenerate it whenever the
registry files are refreshed and commit the result next to the reader.

    python scripts/build_egress_regions.py /tmp/rir-*.txt
"""
from __future__ import annotations

import ipaddress
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "backend/app/services/data/egress_regions.json"


def _ranges(count: int, start: int):
    """Split an RIR ``count`` of addresses into aligned power-of-two blocks."""
    while count > 0:
        size = 1 << (count.bit_length() - 1)
        while start % size:
            size >>= 1
        yield start, size
        start += size
        count -= size


def main(paths: list[str]) -> int:
    regions: dict[str, list[str]] = {}
    total = 0
    for raw in paths:
        path = Path(raw)
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split("|")
            if len(parts) < 7 or parts[2] != "ipv4" or parts[6] not in {"allocated", "assigned"}:
                continue
            country, start, count = parts[1].strip().upper(), parts[3], parts[4]
            if len(country) != 2 or not count.isdigit():
                continue
            try:
                base = int(ipaddress.IPv4Address(start))
            except ipaddress.AddressValueError:
                continue
            bucket = regions.setdefault(country, [])
            for offset, size in _ranges(int(count), base):
                prefix = 32 - (size.bit_length() - 1)
                bucket.append(str(ipaddress.IPv4Network((offset, prefix))))
                total += 1
    for bucket in regions.values():
        bucket.sort(key=lambda cidr: int(ipaddress.IPv4Network(cidr).network_address))
    payload = {
        "version": datetime.now(UTC).strftime("%Y-%m-%d"),
        "source": "RIR delegated stats (arin/ripencc/apnic/lacnic/afrinic)",
        "count": total,
        "regions": regions,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"{len(regions)} countries, {total} CIDRs, {OUT.stat().st_size / 1e6:.1f} MB -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
