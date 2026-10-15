"""Account & security: sign-in methods, password, sessions, connected mailbox, erase everything."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ... import app_state, oauth
from ...brokers import sync_catalog
from ...db import Base
from ...models import MailAccount, OAuthIdentity, User
from ...security import hash_password, verify_password
from ...settings import Settings
from ..deps import current_user, flash, get_db, redirect, render, start_session
from .auth import oauth_options

router = APIRouter(prefix="/account")


@router.get("")
def account_page(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    accounts = db.scalars(select(MailAccount).order_by(MailAccount.id)).all()
    return render(request, db, "account.html", user=user, identities=user.identities, accounts=accounts,
                  providers=oauth_options(db), all_providers=oauth.PROVIDERS)


@router.post("/password")
def set_password(request: Request, current: str = Form(""), new: str = Form(...), new2: str = Form(...),
                 db: Session = Depends(get_db), user: User = Depends(current_user)):
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
def unlink(identity_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
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
def signout_all(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    user.session_version += 1
    db.flush()
    request.session.clear()
    flash(request, "Signed out everywhere.", "success")
    return redirect("/login")


@router.post("/disconnect/{account_id}")
def disconnect(account_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
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
def erase(request: Request, confirm: str = Form(""), db: Session = Depends(get_db), user: User = Depends(current_user)):
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
