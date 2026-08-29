"""SP application factory and ASGI entrypoint.

The process selects which SP it is from ``FABRIC_SP_ID`` (set by the launcher), so the
same code serves both ``sp-a`` and ``sp-b``. Run as ``uvicorn fabric.sp.main:app``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from fabric.common.audit import configure_audit_logging
from fabric.common.config import get_settings
from fabric.common.database import create_all, make_engine, make_sessionmaker
from fabric.sp.api import routes
from fabric.sp.persistence.models import SPBase
from fabric.sp.service.idp_client import IdPClient


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    if settings.sp_id is None:
        raise RuntimeError("FABRIC_SP_ID must be set (e.g. 'sp-a') to run an SP process")
    settings.sp_client(settings.sp_id)  # validate it is a known SP
    configure_audit_logging(settings.sp_id)

    engine = make_engine(settings.sp_db_path(settings.sp_id))
    await create_all(engine, SPBase)
    app.state.engine = engine
    app.state.sessionmaker = make_sessionmaker(engine)
    app.state.idp = IdPClient(settings.idp_issuer)
    try:
        yield
    finally:
        await engine.dispose()


async def _request_id_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
    request.state.request_id = request.headers.get("x-request-id") or uuid4().hex
    response = await call_next(request)
    response.headers["x-request-id"] = request.state.request_id
    return response


def create_app() -> FastAPI:
    settings = get_settings()
    title = "Identity Fabric — SP"
    if settings.sp_id is not None and settings.sp_id in settings.sp_clients():
        title = f"Identity Fabric — {settings.sp_client(settings.sp_id).display_name}"
    app = FastAPI(title=title, lifespan=_lifespan)
    app.add_middleware(BaseHTTPMiddleware, dispatch=_request_id_middleware)
    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    app.include_router(routes.router)
    return app


app = create_app()
