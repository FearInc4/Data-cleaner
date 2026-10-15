from __future__ import annotations

import os
import threading

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...brokers import render_search_url, search_values_for
from ...db import session_scope
from ...jurisdictions import broker_serves, resolve_law
from ...models import Broker, Profile, Relation, RemovalRequest, RequestStatus, User, utcnow
from ...removal import engine
from ...settings import Settings
from ..deps import current_user, flash, get_db, redirect, render, selected_profile

router = APIRouter(prefix="/requests")


def _assist_available() -> bool:
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    # A visible browser needs a display; Docker/headless servers don't have one.
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY") or os.name == "nt" or os.uname().sysname == "Darwin")


@router.get("")
def list_requests(request: Request, status: str = "", profile_id: int | None = None, db: Session = Depends(get_db),
                  user: User = Depends(current_user)):
    profile = selected_profile(request, db, profile_id)
    stmt = select(RemovalRequest).join(Broker)
    if profile:
        stmt = stmt.where(RemovalRequest.profile_id == profile.id)
    if status == "needs_you":
        stmt = stmt.where(RemovalRequest.status.in_(list(RequestStatus.NEEDS_HUMAN | {RequestStatus.NEEDS_VERIFICATION})))
    elif status == "open":
        stmt = stmt.where(RemovalRequest.status.in_(list(RequestStatus.OPEN)))
    elif status:
        stmt = stmt.where(RemovalRequest.status == status)
    reqs = db.scalars(stmt.order_by(Broker.priority, Broker.name)).all()
    drafts = sum(1 for r in reqs if r.status == RequestStatus.DRAFT)
    return render(request, db, "requests.html", reqs=reqs, status=status, profile=profile, drafts=drafts,
                  statuses=RequestStatus.ALL)


@router.get("/new")
def new_requests(request: Request, profile_id: int | None = None, db: Session = Depends(get_db),
                 user: User = Depends(current_user)):
    profile = selected_profile(request, db, profile_id)
    if not profile:
        flash(request, "Add a profile first.", "warn")
        return redirect("/profiles/new")
    existing = {r.broker_id: r for r in db.scalars(select(RemovalRequest).where(RemovalRequest.profile_id == profile.id))
                if r.status not in RequestStatus.TERMINAL}
    brokers = [b for b in db.scalars(select(Broker).where(Broker.active.is_(True)).order_by(Broker.priority, Broker.name))
               if broker_serves(b.regions, profile.country)]
    law = resolve_law(profile.country, profile.region)
    return render(request, db, "requests_new.html", profile=profile, brokers=brokers, existing=existing, law=law)


@router.post("/create")
async def create_requests(request: Request, profile_id: int = Form(...), db: Session = Depends(get_db),
                          user: User = Depends(current_user)):
    form = await request.form()
    broker_ids = [int(v) for v in form.getlist("broker_id") if str(v).isdigit()]
    profile = db.get(Profile, profile_id)
    if not profile:
        raise HTTPException(404)
    if profile.relation == Relation.AGENT and not profile.agent_authorization_on_file:
        flash(request, "This profile is for someone else. Get their signed authorization first (download it from the profile page), then tick the box.", "error")
        return redirect(f"/profiles/{profile.id}")
    now = utcnow()
    created = 0
    for bid in broker_ids:
        broker = db.get(Broker, bid)
        if broker:
            _, was_new = engine.create_request(db, profile, broker, now=now)
            created += int(was_new)
    flash(request, f"Created {created} request(s). Email drafts are below. Review one, then send them all.", "success")
    return redirect(f"/requests?profile_id={profile.id}")


@router.post("/approve-all")
def approve_all(request: Request, profile_id: int = Form(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    settings = Settings(db)
    if not (settings.smtp_host and settings.from_address):
        flash(request, "Set up outgoing email on the Settings page first.", "error")
        return redirect("/settings")
    now = utcnow()
    n = 0
    for req in db.scalars(select(RemovalRequest).where(RemovalRequest.profile_id == profile_id,
                                                       RemovalRequest.status == RequestStatus.DRAFT)):
        if req.method == "email" and req.to_address:
            engine.approve(db, req, now=now)
            n += 1
    flash(request, f"Queued {n} email(s). They go out within a few minutes, at most {settings.rate_limit_per_hour} per hour.", "success")
    return redirect(f"/requests?profile_id={profile_id}")


def _get(db: Session, request_id: int) -> RemovalRequest:
    req = db.get(RemovalRequest, request_id)
    if not req:
        raise HTTPException(404)
    return req


@router.get("/{request_id}")
def request_detail(request_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    req = _get(db, request_id)
    settings = Settings(db)
    preview = None
    if req.status == RequestStatus.DRAFT and req.method == "email":
        preview = engine.preview_initial(req, settings, today=utcnow())
    law = resolve_law(req.profile.country, req.profile.region)
    search_link = render_search_url(req.broker.search_url, search_values_for(req.profile)) if req.broker.search_url else None
    escalation = next((e for e in reversed(req.events) if e.type == "escalation_ready"), None)
    return render(request, db, "request_detail.html", req=req, preview=preview, law=law, search_link=search_link,
                  escalation=escalation, assist=_assist_available(), statuses=RequestStatus.ALL)


@router.post("/{request_id}/action")
def request_action(request_id: int, request: Request, action: str = Form(...), note: str = Form(""),
                   listing_url: str = Form(""), status: str = Form(""), db: Session = Depends(get_db),
                   user: User = Depends(current_user)):
    req = _get(db, request_id)
    now = utcnow()
    try:
        if action == "approve":
            engine.approve(db, req, now=now)
            flash(request, "Queued. It goes out on the next scheduler run.", "success")
        elif action == "submitted":
            engine.mark_submitted(db, req, now=now, note=note or None)
            flash(request, "Recorded. Follow-ups are scheduled.", "success")
        elif action == "completed":
            engine.mark_completed(db, req, now=now, summary=note or "Marked complete by you")
            flash(request, "Marked complete. Data Cleaner will re-check later in case the data comes back.", "success")
        elif action == "resume":
            engine.resume(db, req, now=now)
            flash(request, "Follow-ups resumed.", "success")
        elif action == "pause":
            req.paused = True
            req.next_action_at = None
            engine.add_event(db, req, "paused", "Follow-ups paused", now=now)
        elif action == "cancel":
            engine.set_status(db, req, RequestStatus.CANCELLED, now=now, summary=note or "Cancelled")
        elif action == "escalate":
            engine.escalate(db, req, now=now)
            flash(request, "Complaint draft generated below.", "success")
        elif action == "note" and note.strip():
            engine.add_event(db, req, "note", note.strip()[:500], now=now)
        elif action == "listing" and listing_url.strip():
            req.listing_url = listing_url.strip()
            engine.add_event(db, req, "note", "Listing URL updated", now=now)
        elif action == "status" and status in RequestStatus.ALL:
            engine.set_status(db, req, status, now=now, summary=note or f"Status set to {status.replace('_', ' ')}")
        elif action == "retry":
            req.status = RequestStatus.DRAFT if req.method == "email" else RequestStatus.AWAITING_USER
            engine.add_event(db, req, "status", "Reset to retry", now=now)
        else:
            flash(request, "Nothing to do.", "warn")
    except ValueError as exc:
        flash(request, str(exc), "error")
    return redirect(f"/requests/{request_id}")


@router.post("/{request_id}/assist")
def request_assist(request_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    req = _get(db, request_id)
    if not _assist_available():
        flash(request, "Assisted fill needs Playwright and a desktop session (it opens a visible browser).", "error")
        return redirect(f"/requests/{request_id}")
    if not req.broker.opt_out_url:
        flash(request, "This broker has no opt-out form URL.", "error")
        return redirect(f"/requests/{request_id}")
    from ...assist.formfill import run_assisted, values_for

    url = req.broker.opt_out_url
    values = values_for(req.profile, req.listing_url)

    def worker():
        try:
            result = run_assisted(url, values)
            with session_scope() as s:
                r = s.get(RemovalRequest, request_id)
                if r:
                    engine.add_event(s, r, "note", f"Assisted fill: {result['filled']} field(s) filled. Mark as submitted once you've sent it.", now=utcnow())
        except Exception as exc:  # pragma: no cover - interactive
            with session_scope() as s:
                r = s.get(RemovalRequest, request_id)
                if r:
                    engine.add_event(s, r, "note", f"Assisted fill failed: {exc}", now=utcnow())

    threading.Thread(target=worker, daemon=True).start()
    flash(request, "A browser window is opening with the form pre-filled. Check it, solve any CAPTCHA, submit, then come back and click 'I submitted it'.", "info")
    return redirect(f"/requests/{request_id}")
