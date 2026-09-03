from __future__ import annotations

import threading
from pathlib import Path

from app.core.config import settings
from app.engine.core.context import DetectionContext
from app.integrations.base import AdapterResult, IntegrationAdapter
from app.integrations.engine import IntegrationAdapterEngine


class MarkerAdapter(IntegrationAdapter):
    name = "marker"
    version = "1.0.0"

    def supports(self, context: DetectionContext | None = None) -> bool:
        return bool(context and context.target_type == "pcap" and context.path and context.path.exists())

    def adapt(self, payload, context: DetectionContext | None = None) -> AdapterResult:
        output_dir = Path(payload["output_dir"])
        marker = context.data.get("marker", "")
        (output_dir / "marker.txt").write_text(marker)
        # Simulate reading a tool that would otherwise share a directory: the
        # marker written here must belong only to this run.
        return AdapterResult(self.name, [{"marker": marker, "dir": str(output_dir)}], [])


def test_concurrent_analysis_workspace_isolation(tmp_path: Path) -> None:
    runs_root = settings.integration_dir / "runs"
    # Clean any leftover runs.
    import shutil
    shutil.rmtree(runs_root, ignore_errors=True)
    engine = IntegrationAdapterEngine(MarkerAdapter())
    a = tmp_path / "a.pcap"
    b = tmp_path / "b.pcap"
    a.write_bytes(b"fake-a")
    b.write_bytes(b"fake-b")
    ctx_a = DetectionContext(target_type="pcap", target_id="1", path=a, data={"marker": "A-UNIQUE-2026"})
    ctx_b = DetectionContext(target_type="pcap", target_id="2", path=b, data={"marker": "B-UNIQUE-2026"})
    results: dict[str, list] = {}
    errors: list[Exception] = []

    def run(name: str, ctx: DetectionContext) -> None:
        try:
            results[name] = engine.analyze(ctx)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=run, args=("a", ctx_a)), threading.Thread(target=run, args=("b", ctx_b))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    # Each result must only ever contain its own marker.
    rec_a = ctx_a.data["adapter_records"]["marker"]
    rec_b = ctx_b.data["adapter_records"]["marker"]
    assert rec_a[0]["marker"] == "A-UNIQUE-2026"
    assert rec_b[0]["marker"] == "B-UNIQUE-2026"
    assert "B-UNIQUE-2026" not in str(rec_a)
    assert "A-UNIQUE-2026" not in str(rec_b)
    # The output dirs are distinct.
    assert rec_a[0]["dir"] != rec_b[0]["dir"]
    # Transient workspaces are cleaned up after a successful run.
    assert not runs_root.exists() or not list(runs_root.glob("*/*"))
