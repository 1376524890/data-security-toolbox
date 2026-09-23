"""Translate domain errors at the HTTP boundary, keeping services transport-free."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.services.probe_task_service import ProbeTaskConflict, ProbeTaskNotFound
from app.services.scan_scope import ScanScopeError


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ProbeTaskNotFound)
    async def probe_not_found(request: Request, exc: ProbeTaskNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(ProbeTaskConflict)
    async def probe_conflict(request: Request, exc: ProbeTaskConflict) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ScanScopeError)
    async def scan_scope_rejected(request: Request, exc: ScanScopeError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})
