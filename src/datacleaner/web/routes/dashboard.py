from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ...jurisdictions import DROP_URL, supports_drop
from ...models import (
    Finding,
    FindingKind,
    FindingStatus,
    RemovalRequest,
    RequestEvent,
    RequestStatus,
    User,
    utcnow,
)
from ...settings import Settings
from ..deps import current_user, get_db, redirect, render, selected_profile

router = APIRouter()


@router.get("/")
def dashboard(request: Request, profile_id: int | None = None, db: Session = Depends(get_db),
              user: User = Depends(current_user)):
    profile = selected_profile(request, db, profile_id)
    settings = Settings(db)
    counts: dict[str, int] = {}
    needs: list[RemovalRequest] = []
    upcoming: list[RemovalRequest] = []
    findings_by_kind: dict[str, int] = {}
    if profile:
        for status, n in db.execute(
            select(RemovalRequest.status, func.count()).where(RemovalRequest.profile_id == profile.id).group_by(RemovalRequest.status)
        ):
            counts[status] = n
        needs = list(db.scalars(select(RemovalRequest).where(
            RemovalRequest.profile_id == profile.id,
            or_(RemovalRequest.status.in_([RequestStatus.DRAFT, RequestStatus.AWAITING_USER, RequestStatus.NEEDS_USER_ACTION,
                                           RequestStatus.NEEDS_VERIFICATION, RequestStatus.REJECTED]),
                RemovalRequest.needs_review.is_(True)),
        ).order_by(RemovalRequest.created_at).limit(12)))
        upcoming = list(db.scalars(select(RemovalRequest).where(
            RemovalRequest.profile_id == profile.id, RemovalRequest.next_action_at.is_not(None),
        ).order_by(RemovalRequest.next_action_at).limit(8)))
        for kind, n in db.execute(
            select(Finding.kind, func.count()).where(Finding.profile_id == profile.id, Finding.status == FindingStatus.NEW)
            .group_by(Finding.kind)
        ):
            findings_by_kind[kind] = n
    recent = list(db.scalars(select(RequestEvent).order_by(RequestEvent.at.desc()).limit(10)))
    total = sum(counts.values())
    done = counts.get(RequestStatus.COMPLETED, 0)
    from ...mail.transport import describe

    mail = describe(db)
    setup = {
        "email": mail["can_send"],
        "imap": mail["can_read"],
        "search": bool(settings.searxng_url or settings.brave_api_key),
        "profile": profile is not None,
        "requests": total > 0,
    }
    return render(
        request, db, "dashboard.html", profile=profile, counts=counts, total=total, done=done, needs=needs,
        upcoming=upcoming, recent=recent, findings_by_kind=findings_by_kind, setup=setup, FindingKind=FindingKind,
        show_drop=profile is not None and supports_drop(profile.country, profile.region), drop_url=DROP_URL,
        now=utcnow(), last_tick=settings.get("last_tick_at"), mail=mail,
    )


@router.get("/switch")
def switch_profile(request: Request, profile_id: int, next: str = "/", db: Session = Depends(get_db),
                   user: User = Depends(current_user)):
    selected_profile(request, db, profile_id)
    # Only ever redirect within this app.
    return redirect(next if next.startswith("/") and not next.startswith(("//", "/\\")) else "/")


@router.get("/welcome")
def welcome(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Guided setup: connect email, add yourself, pick brokers, send."""
    from ...mail.transport import describe
    from ...models import Profile
    from .auth import oauth_options

    mail = describe(db)
    profile = selected_profile(request, db, None)
    n_requests = db.scalar(select(func.count()).select_from(RemovalRequest)) or 0
    drafts = db.scalar(select(func.count()).select_from(RemovalRequest).where(RemovalRequest.status == RequestStatus.DRAFT)) or 0
    sent = db.scalar(select(func.count()).select_from(RemovalRequest).where(RemovalRequest.first_sent_at.is_not(None))) or 0
    steps = [
        {"n": 1, "title": "Connect your email", "done": mail["can_send"],
         "why": "Requests are sent from your own address, and Data Cleaner reads the replies so it knows when to stop pestering."},
        {"n": 2, "title": "Tell us who you are", "done": profile is not None,
         "why": "Your name, emails, phones and addresses: what brokers list, and what we ask them to delete."},
        {"n": 3, "title": "Pick the brokers", "done": n_requests > 0,
         "why": "The worst offenders are pre-selected. You can add more any time."},
        {"n": 4, "title": "Review and send", "done": sent > 0 and drafts == 0,
         "why": "Check one email, then send them all. Follow-ups happen on their own."},
    ]
    current = next((s for s in steps if not s["done"]), None)
    return render(request, db, "welcome.html", steps=steps, current=current, mail=mail, profile=profile,
                  providers=oauth_options(db), drafts=drafts, show_drop=profile is not None and supports_drop(profile.country, profile.region),
                  drop_url=DROP_URL, has_profiles=db.scalar(select(func.count()).select_from(Profile)) or 0)
