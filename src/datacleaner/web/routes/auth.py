from __future__ import annotations

import time
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ... import app_state, oauth
from ...models import User
from ...security import hash_password, verify_password
from ...settings import Settings
from ..deps import flash, get_db, redirect, render, start_session

router = APIRouter()

# Simple brute-force brake: 5 failures per username+IP per 15 minutes.
_failures: dict[tuple[str, str], list[float]] = {}
MAX_FAILURES, WINDOW_SECONDS = 5, 15 * 60
# Verified against when the username doesn't exist, so timing doesn't reveal valid usernames.
_DUMMY_HASH = hash_password("not-a-real-password-just-for-timing")


def _throttled(key: tuple[str, str]) -> bool:
    now = time.monotonic()
    recent = [t for t in _failures.get(key, []) if now - t < WINDOW_SECONDS]
    _failures[key] = recent
    return len(recent) >= MAX_FAILURES


def _client_key(request: Request, name: str) -> tuple[str, str]:
    return (name.strip().lower(), request.client.host if request.client else "")


def _user_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User)) or 0


def oauth_options(db: Session) -> list[oauth.Provider]:
    """Providers this install has OAuth client credentials for."""
    s = Settings(db)
    cfg = app_state.get_config()
    return [p for p in oauth.PROVIDERS.values() if oauth.credentials(p, s, cfg)]


@router.get("/setup")
def setup_page(request: Request, token: str | None = None, db: Session = Depends(get_db, scope="function")):
    if _user_count(db):
        return redirect("/login")
    if token is not None:
        key = _client_key(request, "setup-token")
        if _throttled(key):
            flash(request, "Too many wrong setup tokens. Wait 15 minutes.", "error")
        elif app_state.check_setup_token(db, token):
            request.session["setup_ok"] = True
        else:
            _failures.setdefault(key, []).append(time.monotonic())
            flash(request, "That setup token isn't right. Copy it again from the server log (or the setup-token file in the data directory).", "error")
        return redirect("/setup")  # drop the token from the address bar and history
    app_state.ensure_setup_token(db)
    base_url = _base_url(request)
    return render(request, db, "setup.html", setup_ok=bool(request.session.get("setup_ok")),
                  providers=oauth_options(db), base_url=base_url, redirect_ok=oauth.redirect_allowed(base_url),
                  port=urlparse(base_url).port or app_state.get_config().port)


def _base_url(request: Request) -> str:
    cfg = app_state.get_config()
    return cfg.base_url or str(request.base_url).rstrip("/")


@router.post("/setup")
def setup_submit(request: Request, username: str = Form(...), password: str = Form(...), password2: str = Form(...),
                 db: Session = Depends(get_db, scope="function")):
    if _user_count(db):
        return redirect("/login")
    if not request.session.get("setup_ok"):
        flash(request, "Enter the setup token first.", "error")
        return redirect("/setup")
    if len(password) < 12:
        flash(request, "Use at least 12 characters for the password (a few random words works well).", "error")
        return redirect("/setup")
    if password != password2:
        flash(request, "Passwords don't match.", "error")
        return redirect("/setup")
    user = User(username=username.strip()[:80] or "admin", password_hash=hash_password(password))
    db.add(user)
    db.flush()
    app_state.clear_setup_token()
    start_session(request, user)
    flash(request, "You're in. Let's connect your email and add your details.", "success")
    return redirect("/welcome")


@router.post("/setup/oauth-app")
def setup_oauth_app(request: Request, provider: str = Form(...), client_id: str = Form(...), client_secret: str = Form(...),
                    db: Session = Depends(get_db, scope="function")):
    """Save Google/Microsoft OAuth client credentials before the first account exists."""
    if _user_count(db) or not request.session.get("setup_ok"):
        return redirect("/login")
    if provider not in oauth.PROVIDERS or not client_id.strip() or not client_secret.strip():
        flash(request, "Fill in both the client ID and the secret.", "error")
        return redirect("/setup")
    s = Settings(db)
    s.set(f"{provider}_client_id", client_id.strip())
    s.set(f"{provider}_client_secret", client_secret.strip())
    flash(request, f"Saved. You can now continue with {oauth.PROVIDERS[provider].name}.", "success")
    return redirect("/setup")


@router.get("/login")
def login_page(request: Request, db: Session = Depends(get_db, scope="function")):
    if not _user_count(db):
        return redirect("/setup")
    return render(request, db, "login.html", providers=oauth_options(db),
                  has_password=bool(db.scalars(select(User).where(User.password_hash != "")).first()))


@router.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db, scope="function")):
    key = _client_key(request, username)
    if _throttled(key):
        flash(request, "Too many failed attempts. Wait 15 minutes and try again.", "error")
        return redirect("/login")
    user = db.scalars(select(User).where(User.username == username.strip())).first()
    ok = verify_password(password, user.password_hash if user and user.password_hash else _DUMMY_HASH)
    if not user or not user.password_hash or not ok:
        _failures.setdefault(key, []).append(time.monotonic())
        flash(request, "Wrong username or password.", "error")
        return redirect("/login")
    _failures.pop(key, None)
    start_session(request, user)
    return redirect("/")


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/login")
