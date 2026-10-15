"""Shared web helpers: DB session per request, auth, CSRF, flash messages, rendering."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
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


def _host(url: str | None) -> str:
    if not url:
        return ""
    return (urlparse(url).hostname or url).removeprefix("www.")


templates.env.filters["date"] = _humandate
templates.env.filters["datetime"] = _humantime
templates.env.filters["host"] = _host
templates.env.filters["label"] = lambda s: (s or "").replace("_", " ")
templates.env.globals["COUNTRY_NAMES"] = COUNTRY_NAMES
templates.env.globals["US_STATE_NAMES"] = US_STATE_NAMES


class NotAuthenticated(Exception):
    pass


class NeedsSetup(Exception):
    pass


def get_db() -> Iterator[Session]:
    session = new_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    uid = request.session.get("uid")
    if uid:
        user = db.get(User, uid)
        if user:
            return user
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
    needs = db.scalar(select(func.count()).select_from(RemovalRequest).where(
        RemovalRequest.status.in_(list(RequestStatus.NEEDS_HUMAN | {RequestStatus.NEEDS_VERIFICATION}))
    )) or 0
    new_findings = db.scalar(select(func.count()).select_from(Finding).where(Finding.status == FindingStatus.NEW)) or 0
    return {"needs": needs, "new_findings": new_findings}


def render(request: Request, db: Session, template: str, **ctx: Any):
    profiles = db.scalars(select(Profile).order_by(Profile.id)).all() if "uid" in request.session else []
    base = {
        "request": request,
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
