"""Report-ready coverage for every collection path the platform runs.

``asset_instances`` is the one table the file-share scan, the probe's data-asset
inventory and the direct database scan all write, and it carries the two columns
that answer "did we actually look at this?". Reading them back per source is
what turns a console-only detail into a statement the delivered report can make.

Two decisions this module exists to hold:

**One grouped query, not one row per asset.** The counts come from
``GROUP BY source_kind, coverage, termination_reason`` - eleven groups here stand
for fifteen thousand instances - so generating a report does not load the
inventory into memory. Only the bounded "what did we miss" sample is read as
rows, because that list is useless without the paths.

**The network axis is reported beside the asset axis, never inside it.** A
TLS stream the passive capture could not read and a binary file the parser could
not decode are different units; averaging them into one percentage would hide
whichever number is worse, and the platform does not decrypt TLS at all
(``dlp_transfers`` already returns ``tls_decryption: False``), so the encrypted
count is a capability limit, not an incident.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AnalysisResult, AssetInstance, Task
from shared import coverage as terms

#: ``asset_instances.source_kind`` -> the collection path that wrote the row.
#: These are the values the writers actually use (``data_objects/ingestion.py``,
#: ``file_scan/ingest.py``, ``database_scan/ingest.py``); an unrecognised value
#: still gets a block, so a new collector shows up instead of disappearing.
SOURCE_LABELS: dict[str, str] = {
    "file": "探针数据资产盘点",
    "file_share": "文件来源扫描",
    "database": "数据库直连盘点",
}


#: The one value an operator can select that is not a stored status.
INCOMPLETE = "incomplete"


def coverage_clause(value: str) -> Any:
    """The ``AssetInstance.coverage`` filter for a console-selected value.

    ``incomplete`` answers "what did we not read?", which no single status does:
    only ``complete`` means the content was read in full, so everything else
    answers it. Defined here, next to the vocabulary, instead of in the route.
    """
    text = str(value or "").strip().lower()
    if text == INCOMPLETE:
        return AssetInstance.coverage != terms.COMPLETE
    return AssetInstance.coverage == text


def source_label(source_kind: str | None) -> str:
    return SOURCE_LABELS.get(str(source_kind or ""), "其他来源")


def _samples(db: Session, source_kind: str, limit: int) -> list[dict[str, Any]]:
    """The rows that were not fully read, newest first, bounded."""
    rows = db.execute(
        select(AssetInstance.name, AssetInstance.path, AssetInstance.coverage,
               AssetInstance.termination_reason)
        .where(AssetInstance.source_kind == source_kind,
               AssetInstance.coverage != terms.COMPLETE)
        .order_by(AssetInstance.id.desc())
        .limit(limit)
    ).all()
    return [
        {"name": name or path, "coverage": status, "termination_reason": reason}
        for name, path, status, reason in rows
    ]


def asset_sources(db: Session, *, sample: int = 5) -> list[dict[str, Any]]:
    """One coverage block per collection path, ordered as the writers are."""
    grouped = db.execute(
        select(AssetInstance.source_kind, AssetInstance.coverage,
               AssetInstance.termination_reason, func.count())
        .group_by(AssetInstance.source_kind, AssetInstance.coverage,
                  AssetInstance.termination_reason)
    ).all()
    buckets: dict[str, list[tuple[str, str, int]]] = {}
    for source_kind, status, reason, count in grouped:
        buckets.setdefault(str(source_kind or ""), []).append(
            (str(status or ""), str(reason or ""), int(count or 0))
        )
    blocks: list[dict[str, Any]] = []
    for source_kind in sorted(buckets, key=lambda key: (source_label(key) == "其他来源", key)):
        block = terms.summarize_counts(
            buckets[source_kind],
            samples=_samples(db, source_kind, sample) if sample else None,
        )
        block["key"] = source_kind
        block["label"] = source_label(source_kind)
        # ``merge`` concatenates the samples of every source into the one list
        # the report prints, so each row has to carry where it came from - a
        # path without its collector does not tell an operator whom to ask.
        for entry in block["samples"]:
            entry["source"] = block["label"]
        blocks.append(block)
    return blocks


def network(db: Session, *, limit: int = 50) -> dict[str, Any]:
    """The traffic axis: what the passive capture could and could not read."""
    rows = db.execute(
        select(Task.payload["pcap_id"].as_integer(), AnalysisResult.content)
        .join(Task, AnalysisResult.task_id == Task.id)
        .where(AnalysisResult.module == "dlp")
        .order_by(AnalysisResult.id.desc())
        .limit(limit)
    ).all()
    seen: set[Any] = set()
    encrypted = objects = captures = 0
    for index, (pcap_id, content) in enumerate(rows):
        key = pcap_id if pcap_id is not None else f"#{index}"
        if key in seen:
            continue
        seen.add(key)
        payload = content or {}
        encrypted += int((payload.get("coverage") or {}).get("encrypted_streams") or 0)
        objects += len(payload.get("objects") or [])
    captures = len(seen)
    # The label already states the capability ("不解密 TLS"), so the note only
    # has to say what that cost this run.
    note = ""
    if encrypted:
        note = ("这些加密流的内容没有参与检测，也不代表其中没有敏感数据，按未检查计。")
    return {
        "key": "network",
        "label": "网络流量（被动采集，不解密 TLS）",
        "captures": captures,
        "extracted_objects": objects,
        "encrypted_streams": encrypted,
        "tls_decryption": False,
        "note": note,
    }


def report(db: Session, *, sample: int = 5) -> dict[str, Any]:
    """The whole coverage section: one headline, one block per path, network apart."""
    sources = asset_sources(db, sample=sample)
    return {
        "overall": terms.merge(sources),
        "sources": sources,
        "network": network(db),
    }
