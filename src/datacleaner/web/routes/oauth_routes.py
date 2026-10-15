"""Sign in with Google / Microsoft, and connect a mailbox.

Purposes:
- ``setup``   first run: create the owner account, and connect the mailbox in the same consent
- ``login``   sign in with an already-linked account (identity scopes only)
- ``link``    add Google/Microsoft as a sign-in method for the signed-in user
- ``connect`` connect a mailbox for sending and reading (also links it for sign-in)
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ... import app_state, oauth
from ...models import MailAccount, OAuthIdentity, User, utcnow
from ...settings import Settings
from ..deps import NeedsSetup, NotAuthenticated, current_user, flash, get_db, redirect, start_session

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth")

PURPOSES = {"setup", "login", "link", "connect"}


def _base_url(request: Request) -> str:
    cfg = app_state.get_config()
    return cfg.base_url or str(request.base_url).rstrip("/")


def _creds(db: Session, provider: oauth.Provider) -> oauth.ClientCreds | None:
    return oauth.credentials(provider, Settings(db), app_state.get_config())


def _signed_in_user(request: Request, db: Session) -> User | None:
    try:
        return current_user(request, db)
    except (NotAuthenticated, NeedsSetup):
        return None


@router.get("/{provider_key}/start")
def start(provider_key: str, request: Request, purpose: str = "login", db: Session = Depends(get_db, scope="function")):
    try:
        provider = oauth.get_provider(provider_key)
    except oauth.OAuthError:
        return redirect("/login")
    purpose = purpose if purpose in PURPOSES else "login"
    creds = _creds(db, provider)
    if not creds:
        flash(request, f"{provider.name} sign-in isn't set up on this install yet. See Settings → Sign-in apps.", "error")
        return redirect("/settings#sign-in-apps" if request.session.get("uid") else "/setup")
    users = db.scalar(select(func.count()).select_from(User)) or 0
    if purpose == "setup" and (users or not request.session.get("setup_ok")):
        return redirect("/login" if users else "/setup")
    if purpose in ("link", "connect") and not _signed_in_user(request, db):
        return redirect("/login")
    url = oauth.begin(request.session, provider, creds, _base_url(request), purpose=purpose,
                      want_mail=purpose in ("setup", "connect"))
    return redirect(url)


@router.get("/{provider_key}/callback")
def callback(provider_key: str, request: Request, db: Session = Depends(get_db, scope="function")):
    try:
        provider = oauth.get_provider(provider_key)
        creds = _creds(db, provider)
        if not creds:
            raise oauth.OAuthError(f"{provider.name} sign-in isn't set up on this install.")
        result = oauth.complete(request.session, provider, creds, _base_url(request), dict(request.query_params), now=utcnow())
    except oauth.OAuthError as exc:
        flash(request, str(exc), "error")
        return redirect("/settings" if request.session.get("uid") else "/login")

    try:
        return _finish(request, db, result)
    except oauth.OAuthError as exc:
        db.rollback()
        flash(request, str(exc), "error")
        return redirect("/account" if request.session.get("uid") else "/login")


def _finish(request: Request, db: Session, result: oauth.Result):
    provider = result.provider
    if result.purpose == "setup":
        return _finish_setup(request, db, result)
    if result.purpose == "login":
        return _finish_login(request, db, result)
    user = _signed_in_user(request, db)
    if not user:
        return redirect("/login")
    _link_identity(db, user, result)
    if result.purpose == "connect":
        if not _connect_mailbox(request, db, result):
            return redirect("/settings#email")
        flash(request, f"Connected {result.email or 'your mailbox'}. Requests will be sent from it and replies tracked automatically.", "success")
        return redirect(request.session.pop("after_connect", None) or "/settings#email")
    flash(request, f"You can now sign in with {provider.name}.", "success")
    return redirect("/account")


def _identity(db: Session, result: oauth.Result) -> OAuthIdentity | None:
    return db.scalars(select(OAuthIdentity).where(
        OAuthIdentity.provider == result.provider.key, OAuthIdentity.subject == result.subject)).first()


def _link_identity(db: Session, user: User, result: oauth.Result) -> OAuthIdentity:
    ident = _identity(db, result)
    if ident is None:
        ident = OAuthIdentity(user=user, provider=result.provider.key, subject=result.subject, email=result.email)
        db.add(ident)
    elif ident.user_id != user.id:
        # Single-owner install: an identity belongs to exactly one user.
        raise oauth.OAuthError("That account is already linked to a different user.")
    ident.email = result.email or ident.email
    ident.last_login_at = utcnow()
    db.flush()
    return ident


def _connect_mailbox(request: Request, db: Session, result: oauth.Result) -> bool:
    if not result.mail_granted:
        flash(request, f"{result.provider.name} didn't grant permission to send and read mail. Connect again and allow both.", "error")
        return False
    if not result.email:
        flash(request, f"{result.provider.name} didn't share a verified email address for this account.", "error")
        return False
    acc = db.scalars(select(MailAccount).where(
        MailAccount.provider == result.provider.key, MailAccount.subject == result.subject)).first()
    if acc is None:
        acc = MailAccount(provider=result.provider.key, subject=result.subject, email=result.email, cursor={})
        db.add(acc)
    acc.email = result.email
    acc.display_name = result.name
    acc.access_token = result.access_token
    acc.access_expires_at = result.expires_at
    if result.refresh_token:
        acc.refresh_token = result.refresh_token
    acc.scopes = " ".join(sorted(result.scopes))
    acc.status, acc.last_error = ("ok", None) if acc.refresh_token else ("needs_reconnect", "No refresh token was issued.")
    db.flush()
    s = Settings(db)
    s.set("mail_account_id", acc.id)
    if not s.from_name and result.name:
        s.set("from_name", result.name)
    return True


def _finish_setup(request: Request, db: Session, result: oauth.Result):
    if (db.scalar(select(func.count()).select_from(User)) or 0) or not request.session.get("setup_ok"):
        flash(request, "This install has already been set up.", "error")
        return redirect("/login")
    user = User(username=(result.email or f"{result.provider.key}:{result.subject}")[:320], password_hash="")
    db.add(user)
    db.flush()
    _link_identity(db, user, result)
    connected = _connect_mailbox(request, db, result)
    app_state.clear_setup_token()
    start_session(request, user)
    if connected:
        flash(request, f"Welcome! Signed in and connected {result.email}.", "success")
    return redirect("/welcome")


def _finish_login(request: Request, db: Session, result: oauth.Result):
    ident = _identity(db, result)
    if ident is None:
        flash(request, f"That {result.provider.name} account isn't linked to this Data Cleaner. "
                       "Sign in another way, then link it under Account.", "error")
        return redirect("/login")
    ident.last_login_at = utcnow()
    start_session(request, ident.user)
    return redirect("/")
