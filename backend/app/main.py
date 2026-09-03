from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.requests import Request

from app.api.v1 import router
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
    yield


app = FastAPI(title=settings.app_name, version="v1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(router)


PUBLIC_PREFIXES = ("/docs", "/openapi.json", "/redoc")


def _is_probe_api(path: str) -> bool:
    return (
        path == "/api/v1/probes/register"
        or (path.startswith("/api/v1/probes/") and "/heartbeat" in path)
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
