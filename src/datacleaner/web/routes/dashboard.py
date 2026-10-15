from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
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
            RemovalRequest.status.in_([RequestStatus.DRAFT, RequestStatus.AWAITING_USER, RequestStatus.NEEDS_USER_ACTION,
                                       RequestStatus.NEEDS_VERIFICATION, RequestStatus.REJECTED]),
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
    setup = {
        "email": bool(settings.smtp_host and settings.from_address),
        "imap": bool(settings.imap_host),
        "search": bool(settings.searxng_url or settings.brave_api_key),
        "profile": profile is not None,
        "requests": total > 0,
    }
    return render(
        request, db, "dashboard.html", profile=profile, counts=counts, total=total, done=done, needs=needs,
        upcoming=upcoming, recent=recent, findings_by_kind=findings_by_kind, setup=setup, FindingKind=FindingKind,
        show_drop=profile is not None and supports_drop(profile.country, profile.region), drop_url=DROP_URL,
        now=utcnow(), last_tick=settings.get("last_tick_at"),
    )


@router.get("/switch")
def switch_profile(request: Request, profile_id: int, next: str = "/", db: Session = Depends(get_db),
                   user: User = Depends(current_user)):
    selected_profile(request, db, profile_id)
    # Only ever redirect within this app.
    return redirect(next if next.startswith("/") and not next.startswith(("//", "/\\")) else "/")
