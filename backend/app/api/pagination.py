from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session


def paginate(session: Session, query: Any, page: int, page_size: int) -> dict[str, Any]:
    page = max(1, int(page))
    page_size = max(1, min(200, int(page_size)))
    count_query = select(func.count()).select_from(query.subquery())
    total = int(session.scalar(count_query) or 0)
    items = list(session.scalars(query.offset((page - 1) * page_size).limit(page_size)).all())
    return {"items": items, "page": page, "page_size": page_size, "total": total}


def page_response(items: list[Any], page: int, page_size: int, total: int) -> dict[str, Any]:
    return {"items": items, "page": max(1, int(page)), "page_size": max(1, min(200, int(page_size))), "total": int(total)}
