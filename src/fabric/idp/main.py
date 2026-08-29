"""IdP application factories and ASGI entrypoints.

The IdP is split into two ASGI apps on two ports/hosts:

* ``app`` (``uvicorn fabric.idp.main:app``) — the **public**, browser/network-facing
  surface: discovery, JWKS, login UI, ``/authorize``, ``/logout``.
* ``internal_app`` (``uvicorn fabric.idp.main:internal_app``) — the **internal**,
  server-to-server surface: ``/token`` and ``/admin/*``. This is deliberately never
  published on a public port (see ``compose.yaml``'s ``idp-internal`` service, which has
  no ``ports:`` entry) — a leaked SP `private_key_jwt` key or the admin token is only
  useful to whoever can reach this listener.

Both apps talk to the same ``idp.db`` (SQLite tolerates the two local processes this
implies); splitting them is a network-placement control, not a data-separation one — the
IdP's own data has one trust domain regardless of which port served the request.
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
from fabric.idp.api import admin, auth_ui, oidc, token
from fabric.idp.persistence.models import IdPBase


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    engine = make_engine(settings.idp_db_path)
    await create_all(engine, IdPBase)
    app.state.engine = engine
    app.state.sessionmaker = make_sessionmaker(engine)
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
    """The public IdP surface: discovery, JWKS, login UI, authorize, logout."""
    configure_audit_logging("idp")
    app = FastAPI(title="Identity Fabric — IdP", lifespan=_lifespan)
    app.add_middleware(BaseHTTPMiddleware, dispatch=_request_id_middleware)
    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    app.include_router(oidc.router)
    app.include_router(auth_ui.router)
    return app


def create_internal_app() -> FastAPI:
    """The internal IdP surface: the token endpoint and the admin console."""
    configure_audit_logging("idp")
    app = FastAPI(title="Identity Fabric — IdP (internal)", lifespan=_lifespan)
    app.add_middleware(BaseHTTPMiddleware, dispatch=_request_id_middleware)
    app.include_router(token.router)
    app.include_router(admin.router)
    return app


app = create_app()
internal_app = create_internal_app()
