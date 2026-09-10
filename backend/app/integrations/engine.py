from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult
from app.integrations.base import IntegrationAdapter


class IntegrationAdapterEngine(DetectionEngine):
    """Bridge an IntegrationAdapter into the existing DetectionEngine pipeline."""

    def __init__(self, adapter: IntegrationAdapter, payload_key: str = "adapter_payload") -> None:
        self.adapter = adapter
        self.payload_key = payload_key
        self.name = adapter.name
        self.version = adapter.version

    def analyze(self, context: DetectionContext) -> list[DetectionResult]:
        if not self.adapter.supports(context):
            return []
        payload = context.data.get(self.payload_key, {})
        workspace: Path | None = None
        if context.target_type == "pcap" and context.path and context.path.exists():
            # Per-analysis workspace so concurrent workers never share the same
            # /integrations/zeek or /integrations/suricata directory.
            analysis_run_id = uuid.uuid4().hex
            workspace = settings.integration_dir / "runs" / analysis_run_id
            output_dir = workspace / self.adapter.name
            output_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "pcap": str(context.path),
                "path": str(context.path),
                "output_dir": str(output_dir),
                "analysis_run_id": analysis_run_id,
            }
            if self.adapter.name == "suricata":
                rules_dir = context.data.get("suricata_rules_dir")
                if rules_dir:
                    payload["rules_dir"] = str(rules_dir)
        elif not payload and context.path:
            payload = {"path": str(context.path), "context": context.to_dict()}
        elif not payload:
            payload = {"context": context.to_dict()}
        try:
            adapter_result = self.adapter.adapt(payload, context)
            self._persist_extracted_files(adapter_result, workspace)
            context.data.setdefault("adapter_records", {})[self.adapter.name] = adapter_result.records
            return adapter_result.findings
        finally:
            # Successful runs drop the transient raw logs; normalized records are
            # already captured in adapter_result / context.data. Keep the
            # workspace on failure for debug retention.
            if workspace and workspace.exists():
                shutil.rmtree(workspace, ignore_errors=True)

    def _persist_extracted_files(self, adapter_result: Any, workspace: Path | None) -> None:
        """Copy extracted network files out of the transient analysis workspace.

        Zeek/Suricata write extracted payloads into the per-analysis run dir,
        which is deleted on success. Persist them under ``storage/network_files``
        and rewrite each record's ``storage_path`` so the file-download endpoint
        can serve the bytes later (otherwise it 404s on the deleted workspace).
        """
        if not workspace:
            return
        run_dir = workspace / self.adapter.name
        dest_dir = settings.storage_dir / "network_files"
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return
        for record in getattr(adapter_result, "records", []) or []:
            if not isinstance(record, dict):
                continue
            storage = record.get("storage_path") or record.get("extracted_path") or record.get("path")
            fuid = str(record.get("fuid") or record.get("id") or "")
            candidate: Path | None = None
            if storage and Path(str(storage)).is_file():
                candidate = Path(str(storage))
            elif fuid and (run_dir / fuid).is_file():
                candidate = run_dir / fuid
            elif fuid and (workspace / fuid).is_file():
                candidate = workspace / fuid
            if not candidate:
                continue
            name = record.get("filename") or record.get("name") or candidate.name
            safe = Path(str(name)).name.replace("..", "") or "extracted.bin"
            dest = dest_dir / f"{fuid or candidate.stem}_{safe}"
            try:
                if candidate.resolve() != dest.resolve():
                    shutil.copy2(candidate, dest)
                record["storage_path"] = str(dest)
                record["persisted"] = True
            except OSError:
                continue

    def metadata(self) -> dict[str, Any]:
        return {**self.adapter.metadata(), "bridge": "IntegrationAdapterEngine"}
