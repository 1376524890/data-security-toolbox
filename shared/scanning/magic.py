"""File type identification from a bounded probe, not from the extension alone.

Extensions lie, so the probe reads a small head (and for archives a few
signature bytes) and combines that with the extension. A binary file is never
force-decoded and scanned as text; when nothing matches, the file is listed with
its metadata only.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

#: How much of the head is inspected. Bounded, and charged to the scan budget.
PROBE_BYTES = 4096

KIND_TEXT = "text"
KIND_TABLE = "table"
KIND_ARCHIVE = "archive"
KIND_XLSX = "xlsx"
KIND_SQL_GZ = "sql_gz"
KIND_BINARY = "binary"
KIND_UNKNOWN = "unknown"

TEXT_EXTENSIONS = frozenset({
    ".csv", ".tsv", ".txt", ".log", ".sql", ".json", ".jsonl", ".ndjson", ".xml", ".yaml", ".yml",
    ".ini", ".conf", ".cfg", ".env", ".md", ".rst", ".properties", ".dat", ".dump", ".data",
})
#: Extensions that reach GenericTextParser even though they look unusual. The
#: content probe still decides: a binary .dat is listed, never decoded.
TEXT_LIKE_UNKNOWN = frozenset({".dat", ".dump", ".data", ".customer", ".list", ".out", ".trace"})
ARCHIVE_EXTENSIONS = frozenset({".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz"})
TABLE_EXTENSIONS = frozenset({".csv", ".tsv", ".sql", ".json", ".jsonl", ".ndjson", ".xlsx", ".xlsm"})
XLSX_EXTENSIONS = frozenset({".xlsx", ".xlsm"})

MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"SQLite format 3\x00", "sqlite"),
    (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"%PDF-", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
    (b"\xd0\xcf\x11\xe0", "ole2"),
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
)


@dataclass(slots=True)
class FileType:
    """The decision plus how it was reached, so the report can explain itself."""

    kind: str
    parser: str
    magic: str = ""
    is_text: bool = False
    confidence: float = 0.0
    reason: str = ""

    def as_evidence(self) -> dict[str, object]:
        return {"kind": self.kind, "parser": self.parser, "magic": self.magic,
                "confidence": self.confidence, "reason": self.reason}


def _looks_like_text(head: bytes) -> bool:
    """Cheap binary detector: NUL bytes or a high share of control characters."""
    if not head:
        return False
    if b"\x00" in head:
        return False
    sample = head[:PROBE_BYTES]
    control = sum(1 for byte in sample if byte < 9 or (13 < byte < 32))
    return control / len(sample) < 0.10


def detect(suffix: str, head: bytes, *, name: str = "") -> FileType:
    """Classify a file from its extension and a bounded head probe."""
    lowered = name.lower()
    if lowered.endswith(".sql.gz"):
        return FileType(KIND_SQL_GZ, "sql_gz", magic="gzip", is_text=True, confidence=0.95,
                        reason="extension+magic")
    magic = next((label for signature, label in MAGIC_SIGNATURES if head.startswith(signature)), "")
    sample = head[:PROBE_BYTES]
    text = _looks_like_text(sample)

    if suffix in XLSX_EXTENSIONS:
        # An .xlsx is a ZIP container; trusting the extension here is honest
        # because the parser itself re-validates the container.
        return FileType(KIND_XLSX, "xlsx", magic=magic or "zip", is_text=False, confidence=0.9,
                        reason="extension")
    if suffix == ".json" or suffix in {".jsonl", ".ndjson"}:
        return FileType(KIND_TABLE, "json_like", magic=magic, is_text=text, confidence=0.9,
                        reason="extension")
    if suffix in {".csv", ".tsv"}:
        return FileType(KIND_TABLE, "csv_tsv", magic=magic, is_text=text, confidence=0.9,
                        reason="extension")
    if suffix == ".sql":
        return FileType(KIND_TABLE, "sql", magic=magic, is_text=text, confidence=0.9, reason="extension")
    if magic in {"zip", "rar", "7z", "gzip", "bzip2", "xz"} and suffix in ARCHIVE_EXTENSIONS:
        return FileType(KIND_ARCHIVE, "", magic=magic, is_text=False, confidence=0.8,
                        reason="archive is listed, not unpacked")
    if magic in {"png", "jpeg", "gif", "pdf", "pe", "elf", "ole2", "sqlite"}:
        return FileType(KIND_BINARY, "", magic=magic, is_text=False, confidence=0.85, reason="magic")
    if suffix in TEXT_EXTENSIONS or suffix in TEXT_LIKE_UNKNOWN or not suffix:
        if text:
            return FileType(KIND_TEXT, "generic_text", magic=magic, is_text=True, confidence=0.7,
                            reason="content_probe")
        return FileType(KIND_BINARY, "", magic=magic, is_text=False, confidence=0.6,
                        reason="content_probe")
    if text:
        return FileType(KIND_TEXT, "generic_text", magic=magic, is_text=True, confidence=0.5,
                        reason="content_probe")
    return FileType(KIND_BINARY, "", magic=magic, is_text=False, confidence=0.5, reason="content_probe")


def probe_head(path: Path, limit: int = PROBE_BYTES) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except OSError:
        return b""
