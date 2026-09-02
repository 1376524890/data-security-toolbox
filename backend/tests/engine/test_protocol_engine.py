from pathlib import Path

from app.engine.core.context import DetectionContext
from app.engine.protocol_engine.engine import ProtocolEngine


def test_protocol_engine_runs_on_fixture() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "sample.pcap"
    if not fixture.exists():
        return
    context = DetectionContext(target_type="pcap", path=fixture, flows=[], packets=[])
    findings = ProtocolEngine().analyze(context)
    assert isinstance(findings, list)
    assert context.data.get("tcp_streams")

