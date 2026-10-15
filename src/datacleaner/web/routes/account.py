"""Account & security: sign-in methods, password, sessions, connected mailbox, erase everything."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ... import app_state, oauth
from ...app_state import get_config
from ...brokers import sync_catalog
from ...db import Base
from ...models import ExtensionToken, MailAccount, OAuthIdentity, User
from ...security import hash_password, verify_password
from ...settings import Settings
from ..deps import current_user, flash, get_db, redirect, render, start_session
from .auth import oauth_options
from .extension import pair_browser

router = APIRouter(prefix="/account")
EXTENSION_DIR = Path(__file__).resolve().parents[2] / "extension"


def _account(request: Request, db: Session, user: User, **extra):
    accounts = db.scalars(select(MailAccount).order_by(MailAccount.id)).all()
    browsers = db.scalars(select(ExtensionToken).where(ExtensionToken.user_id == user.id, ExtensionToken.session_version == user.session_version)
                          .order_by(ExtensionToken.created_at)).all()
    cfg = get_config()
    base_url = (cfg.base_url or str(request.base_url)).rstrip("/")
    return render(request, db, "account.html", user=user, identities=user.identities, accounts=accounts,
                  providers=oauth_options(db), all_providers=oauth.PROVIDERS, browsers=browsers, base_url=base_url, **extra)


@router.get("")
def account_page(request: Request, db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    return _account(request, db, user)


@router.post("/extension/pair")
def extension_pair(request: Request, name: str = Form(""), db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    token = pair_browser(db, user, name)
    db.flush()
    # Shown once, in this response only: not stored, not put in a redirect or flash message.
    return _account(request, db, user, new_token=token)


@router.post("/extension/{token_id}/revoke")
def extension_revoke(token_id: int, request: Request, db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    row = db.get(ExtensionToken, token_id)
    if row and row.user_id == user.id:
        db.delete(row)
        flash(request, f"Unpaired {row.name}. That browser can't fetch your details any more.", "success")
    return redirect("/account#extension")


@router.get("/extension.zip")
def extension_zip(user: User = Depends(current_user)):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(EXTENSION_DIR.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                zf.write(path, Path("datacleaner-extension") / path.relative_to(EXTENSION_DIR))
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="datacleaner-extension.zip"'})


@router.post("/password")
def set_password(request: Request, current: str = Form(""), new: str = Form(...), new2: str = Form(...),
                 db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    if user.has_password and not verify_password(current, user.password_hash):
        flash(request, "Your current password isn't right.", "error")
        return redirect("/account")
    if len(new) < 12 or new != new2:
        flash(request, "Use at least 12 characters, typed the same twice.", "error")
        return redirect("/account")
    user.password_hash = hash_password(new)
    user.session_version += 1  # sign out other browsers
    db.flush()
    start_session(request, user)
    flash(request, "Password saved. Other browsers have been signed out.", "success")
    return redirect("/account")


@router.post("/unlink/{identity_id}")
def unlink(identity_id: int, request: Request, db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    ident = db.get(OAuthIdentity, identity_id)
    if not ident or ident.user_id != user.id:
        return redirect("/account")
    if len(user.identities) <= 1 and not user.has_password:
        flash(request, "Set a password or link another account first, or you'd be locked out.", "error")
        return redirect("/account")
    db.delete(ident)
    flash(request, "Sign-in method removed.", "success")
    return redirect("/account")


@router.post("/signout-all")
def signout_all(request: Request, db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    user.session_version += 1
    db.flush()
    request.session.clear()
    flash(request, "Signed out everywhere.", "success")
    return redirect("/login")


@router.post("/disconnect/{account_id}")
def disconnect(account_id: int, request: Request, db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    acc = db.get(MailAccount, account_id)
    if not acc:
        return redirect("/settings#email")
    provider = oauth.get_provider(acc.provider)
    revoked = any(oauth.revoke(provider, t) for t in (acc.refresh_token, acc.access_token) if t)
    db.delete(acc)
    s = Settings(db)
    if str(s.get("mail_account_id")) == str(account_id):
        s.set("mail_account_id", "")
    if revoked:
        flash(request, f"Disconnected and revoked Data Cleaner's access to {provider.name}.", "success")
    else:
        flash(request, f"Disconnected. To finish revoking access, remove Data Cleaner at {provider.manage_url}", "warn")
    return redirect("/settings#email")


def erase_everything(db: Session) -> None:
    for acc in db.scalars(select(MailAccount)):
        provider = oauth.get_provider(acc.provider)
        for token in (acc.refresh_token, acc.access_token):
            if token:
                oauth.revoke(provider, token)
    for table in reversed(Base.metadata.sorted_tables):
        db.execute(table.delete())
    db.flush()
    sync_catalog(db)


@router.post("/erase")
def erase(request: Request, confirm: str = Form(""), db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    if confirm.strip() != "ERASE":
        flash(request, 'Type ERASE in capitals to confirm.', "error")
        return redirect("/account#erase")
    erase_everything(db)
    db.commit()
    request.session.clear()
    app_state.ensure_setup_token(db)
    request.session["setup_ok"] = True  # the person who just erased it can set it up again right away
    flash(request, "Everything was erased: people, requests, findings, settings, connected accounts and your login.", "success")
    return redirect("/setup")
