from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .. import app_state, logredact
from ..config import Config
from ..crypto import get_vault
from ..db import session_scope
from ..scheduler import BackgroundScheduler
from .deps import NeedsSetup, NotAuthenticated, csrf_protect, redirect

log = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; object-src 'none'")


def _allowed_hosts(config: Config) -> set[str] | None:
    if "*" in config.allowed_hosts:
        return None
    hosts = {"localhost", "127.0.0.1", "::1", "[::1]"} | set(config.allowed_hosts)
    if config.base_url:
        hosts.add((urlparse(config.base_url).hostname or "").lower())
    return hosts


def _hostname(host_header: str) -> str:
    host_header = host_header.strip().lower()
    if host_header.startswith("["):  # [::1]:8080
        return host_header.split("]", 1)[0] + "]"
    return host_header.rsplit(":", 1)[0] if host_header.count(":") == 1 else host_header


def _print_setup_banner(config: Config) -> None:
    with session_scope() as s:
        token = app_state.ensure_setup_token(s)
    if not token:
        return
    base = config.base_url or f"http://localhost:{config.port}"
    # Printed (not logged) on purpose: the log filter would redact it.
    print(
        "\n" + "=" * 72 + "\n"
        "  Data Cleaner is ready to set up. Open this link to create your account:\n\n"
        f"    {base}/setup?token={token}\n\n"
        f"  (The token is also in {config.data_dir / 'setup-token'})\n"
        + "=" * 72 + "\n",
        file=sys.stderr, flush=True,
    )


def create_app(config: Config | None = None, *, start_scheduler: bool | None = None) -> FastAPI:
    config = app_state.init(config)
    run_scheduler = config.scheduler_enabled if start_scheduler is None else start_scheduler
    allowed = _allowed_hosts(config)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logredact.install()
        _print_setup_banner(config)
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
    # Lax (not Strict) so the session survives the redirect back from Google/Microsoft.
    # Every state-changing request is a POST with a CSRF token, so Lax loses nothing.
    app.add_middleware(
        SessionMiddleware, secret_key=get_vault().derive("session-cookie").hex(), session_cookie="dc_session",
        max_age=7 * 24 * 3600, same_site="lax", https_only=config.secure_cookies,
    )

    @app.middleware("http")
    async def security(request: Request, call_next):
        if allowed is not None:
            host = _hostname(request.headers.get("host") or "")
            if host not in allowed:
                # Blocks DNS-rebinding attacks from malicious websites against a local install.
                return PlainTextResponse(
                    f"Unknown host {host!r}. If this is your Data Cleaner, set DATACLEANER_BASE_URL "
                    "or add the name to DATACLEANER_ALLOWED_HOSTS.", status_code=400)
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Content-Security-Policy", CSP)
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        if config.secure_cookies:
            h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if not request.url.path.startswith("/static/"):
            # Pages contain personal data: never store them in browser or proxy caches.
            h.setdefault("Cache-Control", "no-store")
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

    from .routes import account, auth, brokers, dashboard, exposure, oauth_routes, profiles, requests, settings, spam

    for module in (auth, oauth_routes, account, dashboard, profiles, brokers, requests, exposure, spam, settings):
        app.include_router(module.router)
    return app
