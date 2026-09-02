from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import router
from app.core.config import settings
from app.core.database import engine
from app.core.logging import configure_logging
from app.models import Base


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    if settings.database_url.startswith("sqlite"):
        Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title=settings.app_name, version="v1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(router)

