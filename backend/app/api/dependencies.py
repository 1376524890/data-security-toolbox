"""Shared HTTP authentication; this module does not register routes."""

from fastapi import HTTPException

from app.core.security import require_probe_headers


def authenticated_probe(probe_id, request, db):
    probe = require_probe_headers(request, db)
    if not probe or probe.id != probe_id:
        raise HTTPException(403, "probe id mismatch")
    return probe
