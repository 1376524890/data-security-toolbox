"""数据安全综合驾驶舱 aggregates: posture score, compliance board, focus, status.

The console homepage answers "how is our data security today" with four boards,
and every one of them is derived from rows the platform already stores. Two
rules keep the page honest:

* A dimension without a denominator is *unavailable*, not zero. The overall
  score then renormalises over the dimensions that do have one, and a page with
  nothing to score reports ``None`` so the view can print "—" instead of a
  fabricated 0.
* Every sub-score carries its own numerator and denominator, so the page can
  print the arithmetic next to the number instead of asking for trust.

Scoring rules (0-100 each, stated because the number drives a human judgement):

* 资产安全 = 100 x (1 - 高风险资产 / 资产总数), 高风险 = risk_level Critical/High
* 数据防护 = 100 x (1 - 高敏对象 / 数据对象总数), 高敏 = 分级 L3/L4
* 检测响应 = 100 x 已处置告警 / 告警总数, 已处置 = 状态不是初始的 new
* 合规管理 = 四项合规检查完成度的算术平均（每项检查的分子分母见合规看板）

The compliance board's four checks are coverage ratios over real collections -
数据分类分级 (已分级对象/对象), 敏感数据保护 (高敏实例采集完整/高敏实例),
权限管理 (已上报权限实例/实例), 数据出境 (已判定去向的非内网会话/非内网会话).
They measure "can the platform already answer this question for the estate",
not a pass/fail ruling on the customer, which is what a delivery or audit reader
needs from the board.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.core.datetimes import aware
from app.models import (
    Alert,
    Asset,
    AssetInstance,
    DataObject,
    DetectionFinding,
    Flow,
    Probe,
    Task,
)
from app.services import egress_regions
from app.services.probe_task_service import COLLECTION_TASK_KINDS

#: The two levels that mean "material" everywhere else in the console.
HIGH_SEVERITIES = ("Critical", "High")

#: 已处置 = anything past the initial "new" state.
HANDLED_ALERT_STATUSES = ("acknowledged", "resolved", "suppressed")

#: Task states whose run produced a usable result. ``Partial`` counts: the
#: collection stopped at a budget or an unreachable entry, but what it read was
#: stored and is in the inventory.
DONE_TASK_STATUSES = ("Completed", "Success", "Partial")

WEEK = timedelta(days=7)

#: Equal weights. The four dimensions describe different controls and the
#: platform has no evidence that one matters more; they are renormalised over
#: the dimensions that actually have a denominator.
WEIGHTS: dict[str, float] = {
    "asset_safety": 0.25,
    "data_protection": 0.25,
    "detection_response": 0.25,
    "compliance": 0.25,
}

#: Score band -> the word the ring shows under the number.
GRADES: tuple[tuple[float, str], ...] = (
    (90, "优秀"),
    (80, "良好"),
    (70, "一般"),
    (60, "待改进"),
    (0, "风险较高"),
)


def _count(db: Session, model: Any, *conditions: Any) -> int:
    return int(db.scalar(select(func.count(model.id)).where(*conditions)) or 0)


def _utc(value: Any) -> datetime | None:
    """A row timestamp as an aware UTC datetime, or ``None`` when unusable."""
    moment = aware(value)
    if isinstance(moment, datetime):
        return moment if moment.tzinfo else moment.replace(tzinfo=UTC)
    return None


def _score(good: int, total: int) -> float | None:
    """A 0-100 sub-score, or ``None`` when there is nothing to measure."""
    if total <= 0:
        return None
    return round(max(0.0, min(100.0, good * 100 / total)), 1)


def _delta(current: int, previous: int) -> int | None:
    """Week-over-week change in percent.

    ``None`` when the previous week has no rows: a percentage against zero reads
    as "+100%" or "+∞%", and both would be wrong. The view falls back to showing
    the raw count.
    """
    if not previous:
        return None
    return round((current - previous) * 100 / previous)


def week_pair(db: Session, model: Any, now: datetime, *conditions: Any) -> dict[str, Any]:
    """Rows created in the last 7 days against the 7 days before that.

    ``conditions`` narrow the model the same way on both sides (a risk level, a
    provenance), so one card's "较上周" is computed over the same rows as its
    total instead of over a different collection.
    """
    current_start = now - WEEK
    previous_start = current_start - WEEK
    current = _count(db, model, *conditions, model.created_at >= current_start)
    previous = _count(db, model, *conditions, model.created_at >= previous_start,
                      model.created_at < current_start)
    return {"week": current, "prev_week": previous, "delta_pct": _delta(current, previous)}


def _classifier(db: Session):
    """A memoised ``ip -> direction`` callable built from the current policy."""
    policy = egress_regions.policy(db)
    memo: dict[str, str] = {}

    def direction_of(ip: str) -> str:
        if ip not in memo:
            memo[ip] = egress_regions.direction_of(egress_regions.classify(
                ip,
                blacklist=policy["blacklist"],
                whitelist=policy["whitelist"],
                internal=policy["internal_cidrs"],
            )["bucket"])
        return memo[ip]

    return direction_of


def _empty_totals() -> dict[str, dict[str, int]]:
    return {name: {"sessions": 0, "bytes": 0, "destinations": 0}
            for name in egress_regions.DIRECTIONS}


def flow_summary(db: Session, now: datetime) -> dict[str, Any]:
    """Sessions and bytes per direction, plus the week-over-week egress counts.

    Grouping by ``dst_ip`` before classifying keeps this cheap on a table with
    tens of thousands of sessions, and it is exact: every session to one address
    gets the same verdict, so the classifier runs once per destination.
    """
    direction_of = _classifier(db)
    totals = _empty_totals()
    rows = db.execute(
        select(Flow.dst_ip, func.count(Flow.id), func.coalesce(func.sum(Flow.bytes), 0))
        .group_by(Flow.dst_ip)
    ).all()
    for ip, sessions, size in rows:
        bucket = totals[direction_of(str(ip or ""))]
        bucket["sessions"] += int(sessions or 0)
        bucket["bytes"] += int(size or 0)
        bucket["destinations"] += 1

    current_start = now - WEEK
    previous_start = current_start - WEEK
    weekly: dict[str, dict[str, Any]] = {}
    for name in egress_regions.DIRECTIONS:
        weekly[name] = {"week": 0, "prev_week": 0, "delta_pct": None}
    # The two-week window is summed per destination in SQL. Pulling every recent
    # session into Python just to compare two timestamps made this the cost of
    # the whole overview (all 36k rows of a live capture set), while the
    # classifier only ever needs one verdict per address.
    in_week = func.sum(case((Flow.start_time >= current_start.timestamp(), 1), else_=0))
    in_previous = func.sum(case((Flow.start_time < current_start.timestamp(), 1), else_=0))
    stamped = db.execute(
        select(Flow.dst_ip, in_week, in_previous)
        .where(Flow.start_time >= previous_start.timestamp())
        .group_by(Flow.dst_ip)
    ).all()
    for ip, week, previous in stamped:
        window = weekly[direction_of(str(ip or ""))]
        window["week"] += int(week or 0)
        window["prev_week"] += int(previous or 0)
    for window in weekly.values():
        window["delta_pct"] = _delta(window["week"], window["prev_week"])
    return {"totals": totals, "weekly": weekly}


def flow_daily(db: Session, days: int, now: datetime) -> list[dict[str, Any]]:
    """Sessions per day and direction over a zero-filled window.

    A day with no capture stays in the series as a real zero: the axis is the
    requested window, not just the days that happen to have rows.
    """
    direction_of = _classifier(db)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days - 1)
    # ``start_time`` is a UTC epoch second, so a bucket is the epoch divided by
    # the bucket length - the same day ``datetime.fromtimestamp`` would have
    # produced, counted in SQL instead of by pulling every session into Python
    # (36k rows on a live set). ``floor`` exists in PostgreSQL and in SQLite.
    step = 86400 if days > 1 else 3600
    keys = [(start + timedelta(days=offset)).strftime("%Y-%m-%d") for offset in range(days)]
    items = {key: {name: 0 for name in egress_regions.DIRECTIONS} for key in keys}
    bucket = func.floor(Flow.start_time / step)
    rows = db.execute(
        select(Flow.dst_ip, bucket, func.count(Flow.id))
        .where(Flow.start_time >= start.timestamp())
        .group_by(Flow.dst_ip, bucket)
    ).all()
    for ip, index, sessions in rows:
        key = datetime.fromtimestamp(float(index) * step, tz=UTC).strftime("%Y-%m-%d")
        if key in items:
            items[key][direction_of(str(ip or ""))] += int(sessions or 0)
    return [{"time": key, **value} for key, value in items.items()]


def health(db: Session, checks: list[dict[str, Any]]) -> dict[str, Any]:
    """The 数据安全健康度 ring: four named sub-scores and their arithmetic."""
    total_assets = _count(db, Asset)
    risky_assets = _count(db, Asset, Asset.risk_level.in_(HIGH_SEVERITIES))
    asset_safety = _score(total_assets - risky_assets, total_assets)

    total_objects = _count(db, DataObject)
    sensitive_objects = _count(db, DataObject, DataObject.sensitivity.in_(HIGH_SEVERITIES))
    data_protection = _score(total_objects - sensitive_objects, total_objects)

    total_alerts = _count(db, Alert)
    handled_alerts = _count(db, Alert, Alert.status.in_(HANDLED_ALERT_STATUSES))
    detection_response = _score(handled_alerts, total_alerts)

    rates = [item["rate"] for item in checks if item["rate"] is not None]
    compliance = round(sum(rates) / len(rates), 1) if rates else None

    components = [
        {
            "key": "asset_safety",
            "label": "资产安全",
            "score": asset_safety,
            "numerator": total_assets - risky_assets,
            "denominator": total_assets,
            "detail": f"非高风险资产 {total_assets - risky_assets} / 资产 {total_assets}",
        },
        {
            "key": "data_protection",
            "label": "数据防护",
            "score": data_protection,
            "numerator": total_objects - sensitive_objects,
            "denominator": total_objects,
            "detail": f"非高敏对象 {total_objects - sensitive_objects} / 数据对象 {total_objects}",
        },
        {
            "key": "detection_response",
            "label": "检测响应",
            "score": detection_response,
            "numerator": handled_alerts,
            "denominator": total_alerts,
            "detail": f"已处置告警 {handled_alerts} / 告警 {total_alerts}",
        },
        {
            # A mean of four rates has no single numerator: the four collections
            # it averages count objects, instances and sessions, and adding them
            # would be a unit error dressed as arithmetic. The board beside the
            # ring carries each check's own pair instead.
            "key": "compliance",
            "label": "合规管理",
            "score": compliance,
            "numerator": None,
            "denominator": None,
            "detail": f"四项检查完成度均值（{len(rates)} 项有分母）",
        },
    ]

    measured = [(key, weight) for key, weight in WEIGHTS.items()
                if next(item["score"] for item in components if item["key"] == key) is not None]
    score: float | None = None
    if measured:
        total_weight = sum(weight for _key, weight in measured)
        score = round(sum(next(item["score"] for item in components if item["key"] == key) * weight
                          for key, weight in measured) / total_weight, 1)
    grade = next((label for floor, label in GRADES if score is not None and score >= floor), "")
    return {"score": score, "grade": grade, "components": components,
            "weights": {key: weight for key, weight in measured}}


def compliance(db: Session, flows: dict[str, Any]) -> dict[str, Any]:
    """The four coverage checks behind 合规检查完成情况."""
    total_objects = _count(db, DataObject)
    graded = 0
    for categories in db.scalars(select(DataObject.categories)).all():
        if categories:
            graded += 1

    sensitive_instances = _count(db, AssetInstance,
                                 AssetInstance.sensitivity.in_(HIGH_SEVERITIES))
    complete_instances = _count(db, AssetInstance,
                                AssetInstance.sensitivity.in_(HIGH_SEVERITIES),
                                AssetInstance.coverage == "complete")

    total_instances = _count(db, AssetInstance)
    reported = _count(db, AssetInstance, AssetInstance.permission != "")

    external = int(flows["totals"]["external"]["sessions"])
    needing_verdict = external + int(flows["totals"]["unknown"]["sessions"])

    specs = (
        ("classification", "数据分类分级", graded, total_objects, "命中敏感类目并完成分级的对象"),
        ("sensitive_protection", "敏感数据保护", complete_instances, sensitive_instances,
         "高敏实例中采集覆盖完整的"),
        ("egress", "数据出境", external, needing_verdict, "非内网会话中已判定去向的"),
        ("permission", "权限管理", reported, total_instances, "已上报文件权限的实例"),
    )
    checks = [
        {"key": key, "label": label, "numerator": good, "denominator": total,
         "rate": _score(good, total), "detail": detail}
        for key, label, good, total, detail in specs
    ]
    rates = [item["rate"] for item in checks if item["rate"] is not None]
    return {
        "rate": round(sum(rates) / len(rates), 1) if rates else None,
        "passed": sum(1 for rate in rates if rate >= 100),
        "measured": len(rates),
        "checks": checks,
    }


def focus(*, high_risk_total: int, high_risk: dict[str, Any], incidents: dict[str, Any],
          egress: dict[str, Any], unhandled: int,
          board: dict[str, Any]) -> list[dict[str, Any]]:
    """本周重点关注: the rows a 负责人 has to act on.

    A pure projection over the week windows the caller already computed - the
    list itself adds no query, so a row can never disagree with the card above
    it that shows the same window.
    """
    pending = sum(1 for item in board["checks"]
                  if item["rate"] is not None and item["rate"] < 100)
    return [
        {"key": "high_risk", "label": "高风险项", "value": high_risk_total, "unit": "项",
         "hint": "需立即处理", "delta_pct": high_risk["delta_pct"]},
        {"key": "incidents", "label": "新增安全事件", "value": incidents["week"], "unit": "条",
         "hint": _week_hint(incidents), "delta_pct": incidents["delta_pct"]},
        {"key": "egress", "label": "数据外发事件", "value": egress["week"], "unit": "个",
         "hint": _week_hint(egress), "delta_pct": egress["delta_pct"]},
        {"key": "alerts", "label": "未处理告警", "value": unhandled, "unit": "条",
         "hint": "需及时处理", "delta_pct": None},
        {"key": "compliance", "label": "合规检查完成率",
         "value": board["rate"], "unit": "%",
         "hint": f"仍有 {pending} 项未达 100%" if pending else "四项检查均已覆盖",
         "delta_pct": None},
    ]


def _week_hint(window: dict[str, Any]) -> str:
    delta = window.get("delta_pct")
    if delta is None:
        return f"本周 {window.get('week', 0)} 条（上周无数据）"
    return f"较上周 {delta:+d}%"


def status(db: Session, now: datetime, integrations: dict[str, Any]) -> list[dict[str, Any]]:
    """探针与引擎状态: four rows, each a real up/total pair."""
    probes = [{"status": item.status} for item in db.scalars(select(Probe)).all()]
    online = sum(1 for item in probes if item["status"] == "online")

    engines_total = len(engine_names())
    producing = len({name for name in db.scalars(
        select(DetectionFinding.engine)
        .where(DetectionFinding.created_at >= now - WEEK)
        .distinct()
    ).all() if name})

    window_tasks = db.execute(
        select(Task.status, func.count(Task.id))
        .where(Task.kind.in_(COLLECTION_TASK_KINDS), Task.created_at >= now - WEEK)
        .group_by(Task.status)
    ).all()
    collection_total = sum(int(count) for _status, count in window_tasks)
    collection_ok = sum(int(count) for state, count in window_tasks
                        if state in DONE_TASK_STATUSES)

    return [
        _status_row("probes", "探针状态", online, len(probes), "在线探针"),
        _status_row("integrations", "集成组件", integrations["healthy"], integrations["total"],
                    "健康适配器"),
        _status_row("engines", "检测引擎", producing, engines_total, "近 7 天有产出的引擎"),
        _status_row("collection", "数据采集", collection_ok, collection_total,
                    "近 7 天采集任务完成"),
    ]


def _status_row(key: str, label: str, up: int, total: int, detail: str) -> dict[str, Any]:
    return {"key": key, "label": label, "up": up, "total": total,
            "rate": _score(up, total), "detail": detail}


def engine_names() -> list[str]:
    """The registered detection engines, read from the registry (one source)."""
    from app.engine import registry

    return [engine.name for engine in registry.all()]


__all__ = [
    "COLLECTION_TASK_KINDS",
    "DONE_TASK_STATUSES",
    "compliance",
    "engine_names",
    "flow_daily",
    "flow_summary",
    "focus",
    "health",
    "status",
    "week_pair",
]
