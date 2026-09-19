import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.requests import Request

from app.api.error_handlers import register_error_handlers
from app.api.v1 import router
from app.api.deployments import router as deployments_router
from app.api.extensions import router as extensions_router
from app.api.libraries import router as libraries_router
from app.api.profiles import router as profiles_router
from app.api.data_catalog import router as data_catalog_router
from app.api.rulesets import router as rulesets_router
from app.core.config import settings
from app.core.database import SessionLocal, engine
from app.core.logging import configure_logging
from app.core.security import ensure_admin, get_session_user
from app.models import Base


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    if settings.database_url.startswith("sqlite"):
        Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        ensure_admin(db)
        try:
            # Publish the built-in rule baseline on first boot so a probe always
            # has something to negotiate against. Failure is reported, not hidden:
            # the rule set endpoints retry and surface the real error.
            from app.services.ruleset_service import ensure_baseline

            ensure_baseline(db)
            db.commit()
        except Exception:
            db.rollback()
            logging.getLogger(__name__).exception("rule set baseline could not be published at startup")
    yield


app = FastAPI(title=settings.app_name, version="2.11.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
register_error_handlers(app)
app.include_router(router)
app.include_router(deployments_router)
app.include_router(extensions_router)
app.include_router(libraries_router)
app.include_router(rulesets_router)
app.include_router(profiles_router)
app.include_router(data_catalog_router)


PUBLIC_PREFIXES = ("/docs", "/openapi.json", "/redoc")


def _is_probe_api(path: str) -> bool:
    return (
        path == "/api/v1/probes/register"
        or (path.startswith("/api/v1/probes/") and any(path.endswith(s) for s in (
            '/heartbeat', '/scan', '/commands', '/inventory', '/data-assets', '/command-status',
            # Rule downloads still require a probe token in the handler; this only
            # exempts them from the admin-session check.
            '/ruleset', '/ruleset/manifest')))
        or path in {"/api/v1/pcaps/upload", "/api/v1/files/upload"}
        or path == "/api/v1/health"
    )


@app.middleware("http")
async def admin_auth_middleware(request: Request, call_next):
    if settings.app_env != "production":
        return await call_next(request)
    path = request.url.path
    if request.method == "OPTIONS" or path.startswith(PUBLIC_PREFIXES) or _is_probe_api(path):
        return await call_next(request)
    if path.startswith("/api/v1/auth/login"):
        return await call_next(request)
    with SessionLocal() as db:
        user = get_session_user(db, request)
    if not user or not user.is_active:
        return JSONResponse({"detail": "admin authentication required"}, status_code=401)
    return await call_next(request)
