from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .. import app_state
from ..config import Config
from ..crypto import get_vault
from ..scheduler import BackgroundScheduler
from .deps import NeedsSetup, NotAuthenticated, csrf_protect, redirect

log = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"


def create_app(config: Config | None = None, *, start_scheduler: bool | None = None) -> FastAPI:
    config = app_state.init(config)
    run_scheduler = config.scheduler_enabled if start_scheduler is None else start_scheduler

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        scheduler = None
        if run_scheduler:
            scheduler = BackgroundScheduler(config.scheduler_interval_seconds)
            scheduler.start()
            log.info("Scheduler running every %ss", config.scheduler_interval_seconds)
        yield
        if scheduler:
            scheduler.stop()

    app = FastAPI(title="Data Cleaner", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None,
                  dependencies=[Depends(csrf_protect)])
    app.add_middleware(
        SessionMiddleware, secret_key=get_vault().derive("session-cookie").hex(), session_cookie="dc_session",
        max_age=60 * 60 * 24 * 14, same_site="strict", https_only=config.secure_cookies,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'",
        )
        return response

    @app.exception_handler(NotAuthenticated)
    async def _login(request: Request, exc: NotAuthenticated):
        return redirect("/login")

    @app.exception_handler(NeedsSetup)
    async def _setup(request: Request, exc: NeedsSetup):
        return redirect("/setup")

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return PlainTextResponse("ok")

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    from .routes import auth, brokers, dashboard, exposure, profiles, requests, settings, spam

    for module in (auth, dashboard, profiles, brokers, requests, exposure, spam, settings):
        app.include_router(module.router)
    return app
