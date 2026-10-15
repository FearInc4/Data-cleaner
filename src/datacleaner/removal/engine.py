"""Removal request lifecycle: create, approve, send, follow up, escalate, complete.

Every function takes ``now`` so the whole engine can be driven by a fake clock
in tests, and the scheduler is a pure function of database state.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..jurisdictions import resolve_law
from ..models import (
    Broker,
    OutboxMessage,
    Profile,
    RemovalRequest,
    RequestEvent,
    RequestStatus,
)
from ..settings import Settings
from . import letters

log = logging.getLogger(__name__)


# --- cadence ---------------------------------------------------------------

@dataclass(frozen=True)
class Step:
    offset_days: int
    action: str  # followup, final_notice, escalate


def cadence(deadline_days: int, followup_days: list[int], repeat_days: int, max_followups: int) -> list[Step]:
    """The full schedule of actions after the first send, in order.

    ``max_followups`` caps the number of emails (follow-ups + final notice); the
    escalation step is not an email and doesn't count against it.
    """
    steps = [Step(d, "followup") for d in followup_days if d < deadline_days]
    steps.append(Step(deadline_days, "final_notice"))
    steps.append(Step(deadline_days + 7, "escalate"))
    emails = sum(1 for s in steps if s.action != "escalate")
    if emails > max_followups:
        # Keep the final notice; drop the earliest plain reminders.
        drop = emails - max_followups
        kept = []
        for s in steps:
            if s.action == "followup" and drop > 0:
                drop -= 1
                continue
            kept.append(s)
        return kept
    k = 1
    while emails < max_followups:
        steps.append(Step(deadline_days + 7 + repeat_days * k, "followup"))
        emails += 1
        k += 1
    return steps


def _cadence_for(req: RemovalRequest, settings: Settings) -> list[Step]:
    law = resolve_law(req.profile.country, req.profile.region)
    return cadence(law.deadline_days, settings.followup_days(), int(settings.repeat_days), int(settings.max_followups))


def _next_step_index(req: RemovalRequest, steps: list[Step]) -> int:
    idx = req.cadence_step
    if req.status == RequestStatus.ACKNOWLEDGED:
        # They answered; skip reminders scheduled before the statutory deadline.
        law = resolve_law(req.profile.country, req.profile.region)
        while idx < len(steps) and steps[idx].action == "followup" and steps[idx].offset_days < law.deadline_days:
            idx += 1
    return idx


# Minimum spacing between cadence actions, so a broker never gets a burst of emails
# (e.g. after downtime or a long pause). The final notice promises 7 days before escalating.
MIN_EMAIL_GAP = timedelta(days=3)
ESCALATE_GAP = timedelta(days=7)


def schedule_next(req: RemovalRequest, settings: Settings) -> None:
    # due_at is None while the current attempt hasn't gone out yet (see approve()).
    if req.first_sent_at is None or req.due_at is None or req.status in RequestStatus.TERMINAL or req.paused:
        req.next_action_at = None
        return
    if req.status in (RequestStatus.NEEDS_VERIFICATION, RequestStatus.NEEDS_USER_ACTION, RequestStatus.REJECTED):
        # The ball is in our court; don't nag the broker.
        req.next_action_at = None
        return
    steps = _cadence_for(req, settings)
    idx = _next_step_index(req, steps)
    if idx >= len(steps):
        req.next_action_at = None
        return
    at = req.first_sent_at + timedelta(days=steps[idx].offset_days)
    if req.last_action_at:
        at = max(at, req.last_action_at + (ESCALATE_GAP if steps[idx].action == "escalate" else MIN_EMAIL_GAP))
    req.next_action_at = at


def _reset_cadence(req: RemovalRequest) -> None:
    """A fresh attempt (re-sent letter, re-submitted form) gets the full follow-up schedule."""
    req.cadence_step = 0
    req.followup_count = 0
    req.escalated_at = None
    req.last_action_at = None
    req.next_action_at = None
    req.due_at = None


def cancel_queued(session: Session, req: RemovalRequest) -> int:
    """Withdraw mail for this request that hasn't gone out yet."""
    n = 0
    for msg in session.scalars(select(OutboxMessage).where(OutboxMessage.request_id == req.id,
                                                           OutboxMessage.status == "queued")):
        msg.status = "cancelled"
        n += 1
    return n


# --- helpers ----------------------------------------------------------------

KIND_LABELS = {"initial": "request", "followup": "follow-up", "final_notice": "final notice"}


def add_event(session: Session, req: RemovalRequest, type_: str, summary: str, *, now: datetime,
              direction: str = "system", body: str | None = None, message_id: str | None = None) -> RequestEvent:
    ev = RequestEvent(request=req, at=now, type=type_, summary=summary[:500], direction=direction,
                      body=body, message_id=message_id)
    session.add(ev)
    return ev


def _message_id(reference: str, session: Session) -> str:
    from ..mail.transport import sender_address

    domain = (sender_address(session) or "datacleaner.local").split("@")[-1] or "datacleaner.local"
    return f"<{reference.lower()}.{secrets.token_hex(6)}@{domain}>"


def ensure_alias(session: Session, req: RemovalRequest) -> str | None:
    """The per-broker address for this request ("" = person turned aliases off for it)."""
    from ..mail.transport import alias_for

    if req.reply_alias is None:
        alias = alias_for(session, req.broker.slug, req.profile)
        if alias:
            req.reply_alias = alias
    return req.reply_alias or None


def _thread_ids(req: RemovalRequest) -> list[str]:
    return [e.message_id for e in req.events if e.direction == "out" and e.message_id]


def _original(req: RemovalRequest) -> RequestEvent | None:
    for e in req.events:
        if e.type in ("sent", "submitted") and e.direction in ("out", "system"):
            return e
    return None


def open_request_for(session: Session, profile_id: int, broker_id: int) -> RemovalRequest | None:
    return session.scalars(
        select(RemovalRequest).where(
            RemovalRequest.profile_id == profile_id,
            RemovalRequest.broker_id == broker_id,
            RemovalRequest.status.not_in(list(RequestStatus.TERMINAL)),
        )
    ).first()


# --- lifecycle ---------------------------------------------------------------

def create_request(session: Session, profile: Profile, broker: Broker, *, now: datetime,
                   listing_url: str | None = None, method: str | None = None) -> tuple[RemovalRequest, bool]:
    """Create a request (or return the existing open one). Returns (request, created)."""
    existing = open_request_for(session, profile.id, broker.id)
    if existing:
        if listing_url and not existing.listing_url:
            existing.listing_url = listing_url
        return existing, False
    law = resolve_law(profile.country, profile.region)
    method = method or broker.preferred_method
    req = RemovalRequest(
        profile=profile, broker=broker, method=method, law_key=law.key, created_at=now,
        to_address=broker.privacy_email if method == "email" else None,
        listing_url=listing_url,
        status=RequestStatus.DRAFT if method == "email" else RequestStatus.AWAITING_USER,
    )
    session.add(req)
    session.flush()
    add_event(session, req, "created", f"Request created ({method}, {law.short})", now=now)
    settings = Settings(session)
    if method == "email" and settings.auto_approve:
        approve(session, req, now=now)
    return req, True


def preview_initial(req: RemovalRequest, settings: Settings, *, today: datetime) -> letters.Letter:
    return letters.render_initial(
        req.profile, req.broker, req.reference, sent_on=today.date(), listing_url=req.listing_url,
        agent_name=settings.from_name or None,
    )


def approve(session: Session, req: RemovalRequest, *, now: datetime) -> OutboxMessage:
    if req.method != "email" or not req.to_address:
        raise ValueError("Only email requests with a recipient can be queued")
    if req.status not in (RequestStatus.DRAFT, RequestStatus.NEEDS_USER_ACTION, RequestStatus.REJECTED):
        raise ValueError(f"Request is {req.status}; nothing to approve")
    settings = Settings(session)
    letter = preview_initial(req, settings, today=now)
    msg = OutboxMessage(
        request_id=req.id, kind="initial", to_address=req.to_address, subject=letter.subject,
        body=letter.body, message_id=_message_id(req.reference, session), reply_to=ensure_alias(session, req), created_at=now,
    )
    cancel_queued(session, req)  # never two copies of the letter in flight
    session.add(msg)
    _reset_cadence(req)
    req.status = RequestStatus.QUEUED
    add_event(session, req, "queued", f"Queued email to {req.to_address}", now=now)
    return msg


def on_message_sent(session: Session, msg: OutboxMessage, *, now: datetime) -> None:
    if msg.request_id is None:
        return
    req = session.get(RemovalRequest, msg.request_id)
    if req is None:
        return
    settings = Settings(session)
    law = resolve_law(req.profile.country, req.profile.region)
    type_ = {"initial": "sent"}.get(msg.kind, msg.kind)
    add_event(session, req, type_, f"Sent {KIND_LABELS.get(msg.kind, msg.kind)} to {msg.to_address}", now=now,
              direction="out", body=msg.body, message_id=msg.message_id)
    req.last_sent_at = now
    if req.status in RequestStatus.TERMINAL:
        return  # completed/cancelled while this was in flight; don't bring it back to life
    if msg.kind == "initial":
        req.first_sent_at = now
        req.due_at = now + timedelta(days=law.deadline_days)
        req.status = RequestStatus.SENT
    elif msg.kind == "final_notice":
        req.status = RequestStatus.OVERDUE
    elif req.status == RequestStatus.QUEUED:
        req.status = RequestStatus.SENT
    session.flush()
    schedule_next(req, settings)


def on_message_failed(session: Session, msg: OutboxMessage, error: str, *, now: datetime) -> None:
    if msg.request_id is None:
        return
    req = session.get(RemovalRequest, msg.request_id)
    if req is None:
        return
    add_event(session, req, "send_failed", f"Could not send: {error[:300]}", now=now)
    req.status = RequestStatus.NEEDS_USER_ACTION
    req.next_action_at = None


def mark_submitted(session: Session, req: RemovalRequest, *, now: datetime, note: str | None = None) -> None:
    """Human says they submitted the web form / made the call / mailed the letter."""
    law = resolve_law(req.profile.country, req.profile.region)
    add_event(session, req, "submitted", note or f"Submitted via {req.method}", now=now)
    _reset_cadence(req)
    req.first_sent_at = now
    req.last_sent_at = now
    req.due_at = req.first_sent_at + timedelta(days=law.deadline_days)
    req.status = RequestStatus.SENT
    # Follow-ups can still go by email if the broker publishes a privacy address.
    if not req.to_address and req.broker.privacy_email:
        req.to_address = req.broker.privacy_email
    session.flush()
    schedule_next(req, Settings(session))


def mark_completed(session: Session, req: RemovalRequest, *, now: datetime, summary: str = "Marked complete") -> None:
    settings = Settings(session)
    req.status = RequestStatus.COMPLETED
    req.completed_at = now
    req.next_action_at = None
    req.recheck_at = now + timedelta(days=int(settings.recheck_days))
    cancel_queued(session, req)
    add_event(session, req, "completed", summary, now=now)


def set_status(session: Session, req: RemovalRequest, status: str, *, now: datetime, summary: str) -> None:
    if status not in RequestStatus.ALL:
        raise ValueError(status)
    if status == RequestStatus.COMPLETED:
        mark_completed(session, req, now=now, summary=summary)
        return
    req.status = status
    if status in RequestStatus.TERMINAL:
        cancel_queued(session, req)
    add_event(session, req, "status", summary, now=now)
    session.flush()
    schedule_next(req, Settings(session))


def resume(session: Session, req: RemovalRequest, *, now: datetime) -> None:
    """After the human dealt with a verification/info request, carry on the cadence."""
    req.paused = False
    if req.status in (RequestStatus.NEEDS_VERIFICATION, RequestStatus.NEEDS_USER_ACTION):
        # approve() clears due_at; sending or submitting sets it again.
        if req.first_sent_at is None or req.due_at is None:
            # This attempt never went out (e.g. the email failed): back to the start.
            req.status = RequestStatus.DRAFT if req.method == "email" else RequestStatus.AWAITING_USER
        else:
            req.status = RequestStatus.ACKNOWLEDGED if req.last_reply_at else RequestStatus.SENT
    add_event(session, req, "resumed", "Follow-ups resumed", now=now)
    session.flush()
    schedule_next(req, Settings(session))


def _enqueue_followup(session: Session, req: RemovalRequest, kind: str, *, now: datetime, settings: Settings) -> OutboxMessage | None:
    original = _original(req)
    if not req.to_address:
        return None
    original_body = (original.body if original and original.body else "(submitted via web form)")
    original_date = (req.first_sent_at or now).date()
    if kind == "final_notice":
        letter = letters.render_final_notice(req.profile, req.broker, req.reference, original_date=original_date,
                                             original_body=original_body, agent_name=settings.from_name or None)
    else:
        letter = letters.render_followup(req.profile, req.broker, req.reference, original_date=original_date,
                                         original_body=original_body, followup_number=req.followup_count + 1,
                                         today=now.date(), agent_name=settings.from_name or None)
    thread = _thread_ids(req)
    msg = OutboxMessage(
        request_id=req.id, kind=kind, to_address=req.to_address, subject=letter.subject, body=letter.body,
        message_id=_message_id(req.reference, session), reply_to=ensure_alias(session, req),
        in_reply_to=thread[0] if thread else None, references=" ".join(thread) or None, created_at=now,
    )
    session.add(msg)
    return msg


def escalate(session: Session, req: RemovalRequest, *, now: datetime) -> str:
    timeline = [{"at": e.at.strftime("%Y-%m-%d"), "summary": e.summary} for e in req.events]
    replies = sum(1 for e in req.events if e.direction == "in")
    regulator, draft = letters.render_escalation(
        req.profile, req.broker, req.reference, to_address=req.to_address,
        original_date=(req.first_sent_at or now).date(), timeline=timeline,
        followups=req.followup_count, replies=replies,
    )
    req.escalated_at = now
    req.status = RequestStatus.OVERDUE
    add_event(session, req, "escalation_ready",
              f"Complaint draft ready for {regulator.name}: file it at {regulator.url}", now=now, body=draft)
    return draft


def process_due(session: Session, *, now: datetime) -> dict[str, int]:
    """Run every due follow-up / final notice / escalation. Idempotent per tick."""
    settings = Settings(session)
    stats = {"followup": 0, "final_notice": 0, "escalate": 0, "user_action": 0}
    due = session.scalars(
        select(RemovalRequest).where(
            RemovalRequest.next_action_at.is_not(None),
            RemovalRequest.next_action_at <= now,
            RemovalRequest.paused.is_(False),
            RemovalRequest.status.in_([RequestStatus.SENT, RequestStatus.ACKNOWLEDGED, RequestStatus.OVERDUE]),
        )
    ).all()
    for req in due:
        steps = _cadence_for(req, settings)
        idx = _next_step_index(req, steps)
        if idx >= len(steps):
            req.cadence_step = idx
            req.next_action_at = None
            continue
        # After downtime or a pause several reminders can be overdue at once: send only the
        # latest one. The final notice and the escalation are never skipped.
        while (idx + 1 < len(steps) and steps[idx].action == "followup" and req.first_sent_at
               and req.first_sent_at + timedelta(days=steps[idx + 1].offset_days) <= now):
            idx += 1
        step = steps[idx]
        req.cadence_step = idx + 1
        req.last_action_at = now
        if step.action == "escalate":
            escalate(session, req, now=now)
            stats["escalate"] += 1
        elif not req.to_address:
            # Form-only broker: we can't email them, so hand it to the human.
            req.followup_count += 1
            req.status = RequestStatus.NEEDS_USER_ACTION
            add_event(session, req, "check_needed",
                      "No confirmation yet. Check whether your listing is gone; resubmit the form if not.", now=now)
            stats["user_action"] += 1
        else:
            _enqueue_followup(session, req, step.action, now=now, settings=settings)
            req.followup_count += 1
            add_event(session, req, "queued", f"Queued {KIND_LABELS[step.action]} #{req.followup_count}", now=now)
            stats[step.action] += 1
        session.flush()
        schedule_next(req, settings)
    return stats


def due_rechecks(session: Session, *, now: datetime) -> list[RemovalRequest]:
    return list(session.scalars(
        select(RemovalRequest).where(
            RemovalRequest.status == RequestStatus.COMPLETED,
            RemovalRequest.recheck_at.is_not(None),
            RemovalRequest.recheck_at <= now,
        )
    ))
