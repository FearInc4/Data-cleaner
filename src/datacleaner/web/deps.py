"""Shared web helpers: DB session per request, auth, CSRF, flash messages, rendering."""

from __future__ import annotations

import time
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..db import new_session
from ..jurisdictions import COUNTRY_NAMES, US_STATE_NAMES
from ..models import Finding, FindingStatus, Profile, RemovalRequest, RequestStatus, User
from ..security import csrf_matches, new_csrf_token

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _humandate(value: datetime | None) -> str:
    if not value:
        return ""
    return value.strftime("%b %d, %Y")


def _humantime(value: datetime | None) -> str:
    if not value:
        return ""
    return value.strftime("%b %d, %Y %H:%M") + " UTC"


def safe_url(url: str | None) -> str:
    """Only http(s) links reach an href. Data from strangers can't smuggle in javascript: URLs."""
    if not url:
        return "#"
    u = str(url).strip()
    if u.startswith("/") and not u.startswith(("//", "/\\")):
        return u  # link within this app
    return u if urlparse(u).scheme in ("http", "https") else "#"


def _host(url: str | None) -> str:
    if not url:
        return ""
    return (urlparse(url).hostname or url).removeprefix("www.")


templates.env.filters["date"] = _humandate
templates.env.filters["datetime"] = _humantime
templates.env.filters["host"] = _host
templates.env.filters["safe_url"] = safe_url
templates.env.filters["label"] = lambda s: (s or "").replace("_", " ")
templates.env.globals["COUNTRY_NAMES"] = COUNTRY_NAMES
templates.env.globals["US_STATE_NAMES"] = US_STATE_NAMES


class NotAuthenticated(Exception):
    pass


class NeedsSetup(Exception):
    pass


def get_db() -> Iterator[Session]:
    """One session per request, committed when the route returns.

    Always depend on it with ``Depends(get_db, scope="function")``. With FastAPI's default
    "request" scope the commit would run after the response is sent, so a browser could be
    told "saved" before (or even if not) it is.
    """
    session = new_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


SESSION_MAX_AGE = 7 * 24 * 3600  # sign in again after a week, whatever happens
SESSION_IDLE = 24 * 3600  # or after a day without using it


def start_session(request: Request, user: User) -> None:
    """Fresh session on every sign-in (prevents session fixation)."""
    request.session.clear()
    now = int(time.time())
    request.session.update({"uid": user.id, "sv": user.session_version, "iat": now, "seen": now})


def current_user(request: Request, db: Session = Depends(get_db, scope="function")) -> User:
    sess = request.session
    uid = sess.get("uid")
    if uid:
        user = db.get(User, uid)
        now = int(time.time())
        valid = (
            user is not None
            and sess.get("sv") == user.session_version
            and now - int(sess.get("iat", 0)) < SESSION_MAX_AGE
            and now - int(sess.get("seen", 0)) < SESSION_IDLE
        )
        if valid:
            if now - int(sess.get("seen", 0)) > 300:
                sess["seen"] = now
            return user
        sess.clear()
    if db.scalar(select(func.count()).select_from(User)) == 0:
        raise NeedsSetup()
    raise NotAuthenticated()


def csrf_token(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = new_csrf_token()
        request.session["csrf"] = tok
    return tok


async def csrf_protect(request: Request) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    route = request.scope.get("route")
    if route is not None and getattr(route, "path", "").startswith("/api/ext/"):
        return  # the browser extension's API: bearer-token only, never authenticated by cookie
    form = await request.form()
    given = form.get("csrf") or request.headers.get("x-csrf-token")
    if not csrf_matches(request.session.get("csrf"), str(given) if given else None):
        raise HTTPException(status_code=400, detail="Form expired or invalid (CSRF). Go back, reload the page and try again.")


def flash(request: Request, message: str, kind: str = "info") -> None:
    msgs = request.session.get("flash", [])
    msgs.append([kind, message])
    request.session["flash"] = msgs[-5:]


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def nav_counts(db: Session) -> dict[str, int]:
    needs = db.scalar(select(func.count()).select_from(RemovalRequest).where(or_(
        RemovalRequest.status.in_(list(RequestStatus.NEEDS_HUMAN | {RequestStatus.NEEDS_VERIFICATION})),
        RemovalRequest.needs_review.is_(True),
    ))) or 0
    new_findings = db.scalar(select(func.count()).select_from(Finding).where(Finding.status == FindingStatus.NEW)) or 0
    return {"needs": needs, "new_findings": new_findings}


def render(request: Request, db: Session, template: str, **ctx: Any):
    profiles = db.scalars(select(Profile).order_by(Profile.id)).all() if "uid" in request.session else []
    theme = request.cookies.get("dc_theme")
    base = {
        "request": request,
        "theme": theme if theme in ("light", "dark") else "",
        "csrf": csrf_token(request),
        "flashes": request.session.pop("flash", []),
        "nav": nav_counts(db) if "uid" in request.session else {},
        "all_profiles": profiles,
        "path": request.url.path,
    }
    base.update(ctx)
    return templates.TemplateResponse(request, template, base)


def selected_profile(request: Request, db: Session, profile_id: int | None) -> Profile | None:
    if profile_id:
        p = db.get(Profile, profile_id)
        if p:
            request.session["profile_id"] = p.id
            return p
    pid = request.session.get("profile_id")
    if pid:
        p = db.get(Profile, pid)
        if p:
            return p
    return db.scalars(select(Profile).order_by(Profile.id)).first()
