"""Fetch the third-party binaries the images bake in, once per build machine.

The backend image installs ``nuclei`` (the active vulnerability scanner the
network-scan pipeline drives). It used to be downloaded from GitHub on *every*
image build, which made each build depend on that network path. The archive now
lives in the build context, so a build is offline; this script is the one place
that goes to the network, and it only has to run when the file is missing or the
pinned version moves.

    python scripts/fetch_third_party.py            # both architectures
    python scripts/fetch_third_party.py --arch amd64

SHA256 is recorded next to the artefacts and verified on every later run, so a
silently corrupted download is caught instead of being baked into an image.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.request
from pathlib import Path

#: Keep in step with the Dockerfile's NUCLEI_VERSION.
NUCLEI_VERSION = "3.11.1"
ARCHES = ("amd64", "arm64")
DEST = Path(__file__).resolve().parents[1] / "backend" / "third_party" / "nuclei"
SUMS = DEST / "SHA256SUMS"


def _url(arch: str) -> str:
    return (f"https://github.com/projectdiscovery/nuclei/releases/download/"
            f"v{NUCLEI_VERSION}/nuclei_{NUCLEI_VERSION}_linux_{arch}.zip")


def _digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            sha.update(block)
    return sha.hexdigest()


def _recorded() -> dict[str, str]:
    if not SUMS.is_file():
        return {}
    out: dict[str, str] = {}
    for line in SUMS.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2:
            out[parts[1]] = parts[0]
    return out


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=(*ARCHES, "all"), default="all")
    parser.add_argument("--force", action="store_true", help="re-download even if present")
    args = parser.parse_args(argv)

    DEST.mkdir(parents=True, exist_ok=True)
    known = _recorded()
    wanted = ARCHES if args.arch == "all" else (args.arch,)
    lines = dict(known)
    for arch in wanted:
        name = f"nuclei_{NUCLEI_VERSION}_linux_{arch}.zip"
        target = DEST / name
        if target.is_file() and not args.force:
            size = target.stat().st_size
            if known.get(name) and known[name] != _digest(target):
                print(f"{name}: checksum mismatch, re-downloading", file=sys.stderr)
            else:
                print(f"{name}: already present ({size} bytes)")
                lines[name] = _digest(target)
                continue
        print(f"{name}: downloading {_url(arch)}")
        # Download to a temporary name and only then rename: a half-written file
        # must never look like a finished artefact, because the image build keys
        # off the file existing.
        staging = target.with_suffix(target.suffix + ".part")
        with urllib.request.urlopen(_url(arch), timeout=600) as response:
            payload = response.read()
        staging.write_bytes(payload)
        if len(payload) < 1_000_000 or not payload.startswith(b"PK"):
            staging.unlink(missing_ok=True)
            raise SystemExit(f"{name}: download does not look like a zip ({len(payload)} bytes)")
        staging.replace(target)
        digest = _digest(target)
        lines[name] = digest
        print(f"{name}: {len(payload)} bytes sha256={digest[:16]}...")

    SUMS.write_text("".join(f"{lines[name]}  {name}\n" for name in sorted(lines)),
                    encoding="utf-8")
    print(f"wrote {SUMS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
