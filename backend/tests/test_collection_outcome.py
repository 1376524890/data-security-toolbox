from app.api.task_presenter import serialize_task
from app.models import Task
from app.services.data_objects.progress import collection_outcome


def test_old_failed_report_does_not_appear_complete():
    task = Task(kind="data_asset_scan", status="Failed", current_stage="采集完成",
                error="目录不存在", result={"coverage": {"termination_reason": "complete"}})
    result = serialize_task(task)
    assert result["current_stage"] == "探针数据资产采集失败"
    assert result["error"] == "目录不存在"
    assert task.current_stage == "采集完成"  # Presentation does not mutate history.


def test_partial_budget_reason_is_visible_for_old_reports():
    stage, reason = collection_outcome("Partial", {"budget": {
        "termination_reason": "row_budget", "termination_detail": "20797 rows"}})
    assert stage == "探针数据资产采集部分完成"
    assert reason == "达到读取行数上限：20797 rows"


def test_unknown_partial_reason_is_not_hidden():
    assert collection_outcome("Partial", {})[1] == "采集范围未完整覆盖"
    assert collection_outcome("Partial", {"coverage": {
        "termination_reason": "future_limit"}})[1] == "future_limit"


def test_content_truncation_is_not_worded_like_a_missing_directory():
    """A walk that finished must not be described as a scope that was not walked."""
    stage, reason = collection_outcome("Partial", {"coverage": {
        "termination_reason": "row_budget", "termination_detail": "20797 rows",
        "enumeration_complete": True, "content_complete": False}})
    assert stage == "探针数据资产采集部分完成"
    assert reason == "部分文件内容达到读取行数上限：20797 rows"


def test_an_unfinished_walk_keeps_the_budget_wording():
    """No enumeration flag (an older report) keeps the original message."""
    assert collection_outcome("Partial", {"coverage": {"termination_reason": "row_budget"}})[1] == \
        "达到读取行数上限"
    assert collection_outcome("Partial", {"coverage": {
        "termination_reason": "row_budget", "enumeration_complete": False,
        "content_complete": False}})[1] == "达到读取行数上限"


def test_other_task_kinds_keep_their_stage_and_error():
    task = Task(kind="pcap", status="Failed", current_stage="解析失败", error="bad pcap")
    assert serialize_task(task)["current_stage"] == "解析失败"
    assert serialize_task(task)["error"] == "bad pcap"


def test_pipeline_keeps_document_scan_status(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from app.application import analysis
    from app.core.database import SessionLocal
    from app.engine.core.context import DetectionContext
    from app.integrations import offline_manager
    from app.models import DataAsset

    monkeypatch.setattr(analysis.pipeline, "run", lambda context: SimpleNamespace(findings=[]))
    monkeypatch.setattr(analysis, "_run_correlations_and_alerts", lambda *args: [])
    monkeypatch.setattr(analysis, "build_graph", lambda *args: [])
    monkeypatch.setattr(offline_manager, "resolve_active_suricata_rules_dir", lambda db: tmp_path)
    context = DetectionContext(target_type="file", data={"data_assets": [{
        "name": "unsupported.bin", "scan_status": "unsupported",
        "scan_reason": "unsupported_format", "extra": {"file_id": 123}}]})
    with SessionLocal() as db:
        analysis.run_pipeline(context, 1, db)
        row = next(row for row in db.new if isinstance(row, DataAsset))
        assert row.extra == {"file_id": 123, "scan_status": "unsupported",
                             "scan_reason": "unsupported_format"}
        db.rollback()
