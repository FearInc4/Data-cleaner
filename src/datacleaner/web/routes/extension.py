"""API for the Data Cleaner browser extension, which fills broker opt-out forms.

The extension signs in with a pairing token (``Authorization: Bearer dcx_...``),
never with the session cookie. That's why these endpoints skip the CSRF check:
a web page can't make the browser attach the token, so it can't call them.

It can only see open web-form requests, fetch the details for one form at a
time, and mark a form as submitted.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from urllib.parse import urlparse

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...assist.formfill import FIELD_PATTERNS, values_for
from ...models import Broker, ExtensionToken, RemovalRequest, RequestStatus, User, utcnow
from ...removal import engine
from ..deps import get_db

router = APIRouter(prefix="/api/ext")

TOKEN_PREFIX = "dcx_"
IDLE_EXPIRY = timedelta(days=60)
# Waiting on the person: a form to submit, or (after no reply) to resubmit.
FORM_STATUSES = (RequestStatus.AWAITING_USER, RequestStatus.NEEDS_USER_ACTION)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def pair_browser(db: Session, user: User, name: str) -> str:
    """Create a pairing token. The plain token is returned once and never stored."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    db.add(ExtensionToken(user_id=user.id, name=(name.strip() or "Browser")[:80], token_hash=hash_token(token),
                          session_version=user.session_version))
    return token


def paired_browser(request: Request, db: Session = Depends(get_db)) -> ExtensionToken:
    scheme, _, token = (request.headers.get("authorization") or "").partition(" ")
    if scheme.lower() != "bearer" or not token.startswith(TOKEN_PREFIX):
        raise HTTPException(401, "Not paired", headers={"WWW-Authenticate": "Bearer"})
    row = db.scalars(select(ExtensionToken).where(ExtensionToken.token_hash == hash_token(token.strip()))).first()
    now = utcnow()
    if (row is None or row.user.session_version != row.session_version
            or now - (row.last_used_at or row.created_at) > IDLE_EXPIRY):
        raise HTTPException(401, "This pairing has expired or was removed. Pair the extension again.",
                            headers={"WWW-Authenticate": "Bearer"})
    if row.last_used_at is None or now - row.last_used_at > timedelta(minutes=5):
        row.last_used_at = now
    return row


def fill_domains(broker: Broker) -> list[str]:
    """Where the extension may fill this broker's form: its own domains and the opt-out page's host."""
    out = [d.lower().strip(".") for d in (broker.domains or []) if d]
    host = (urlparse(broker.opt_out_url or "").hostname or "").lower()
    if host and host not in out:
        out.append(host)
    return out


def _open_form_requests(db: Session) -> list[RemovalRequest]:
    return list(db.scalars(
        select(RemovalRequest).join(Broker)
        .where(RemovalRequest.status.in_(FORM_STATUSES), Broker.opt_out_url.is_not(None))
        .order_by(RemovalRequest.created_at)
    ))


def _task(db: Session, request_id: int) -> RemovalRequest:
    req = db.get(RemovalRequest, request_id)
    if req is None or req.status not in FORM_STATUSES or not req.broker.opt_out_url:
        raise HTTPException(404, "That form isn't waiting on you any more.")
    return req


@router.get("/whoami")
def whoami(tok: ExtensionToken = Depends(paired_browser)):
    return {"user": tok.user.username, "browser": tok.name}


@router.get("/tasks")
def tasks(db: Session = Depends(get_db), tok: ExtensionToken = Depends(paired_browser)):
    """Forms waiting to be submitted. No personal details: just which broker, for whom."""
    return {"tasks": [
        {"id": r.id, "broker": r.broker.name, "url": r.broker.opt_out_url, "domains": fill_domains(r.broker),
         "profile": r.profile.label, "status": r.status, "steps": list(r.broker.steps or [])[:8]}
        for r in _open_form_requests(db)
    ]}


@router.get("/tasks/{request_id}/fill")
def fill(request_id: int, db: Session = Depends(get_db), tok: ExtensionToken = Depends(paired_browser)):
    req = _task(db, request_id)
    values = values_for(req.profile, req.listing_url, email=engine.ensure_alias(db, req))
    engine.add_event(db, req, "note", f"Form details sent to the browser extension ({tok.name})", now=utcnow())
    return {"id": req.id, "broker": req.broker.name, "domains": fill_domains(req.broker), "values": values,
            "patterns": [[key, pat.pattern] for key, pat in FIELD_PATTERNS]}


@router.post("/tasks/{request_id}/submitted")
def submitted(request_id: int, note: str = Body("", embed=True, max_length=300), db: Session = Depends(get_db),
              tok: ExtensionToken = Depends(paired_browser)):
    req = _task(db, request_id)
    text = "Submitted with the browser extension" + (f": {note.strip()}" if note.strip() else "")
    engine.mark_submitted(db, req, now=utcnow(), note=text)
    return {"id": req.id, "status": req.status,
            "next_action_at": req.next_action_at.isoformat() if req.next_action_at else None}
