"""Tell the person when something needs them: new exposures, broker replies needing action."""

from __future__ import annotations

import logging
import secrets
from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Finding, FindingStatus, OutboxMessage, RemovalRequest, RequestStatus
from .settings import Settings

log = logging.getLogger(__name__)


def build_digest(session: Session, since: datetime | None) -> str | None:
    q = select(Finding).where(Finding.status == FindingStatus.NEW)
    if since:
        q = q.where(Finding.first_seen >= since)
    findings = session.scalars(q).all()
    needs = session.scalars(select(RemovalRequest).where(
        RemovalRequest.status.in_([RequestStatus.NEEDS_USER_ACTION, RequestStatus.NEEDS_VERIFICATION, RequestStatus.REJECTED]),
    )).all()
    escalations = session.scalars(select(RemovalRequest).where(
        RemovalRequest.escalated_at.is_not(None), RemovalRequest.status == RequestStatus.OVERDUE,
        *( [RemovalRequest.escalated_at >= since] if since else [] ),
    )).all()
    if not findings and not needs and not escalations:
        return None
    lines = ["Data Cleaner update", ""]
    if findings:
        lines.append(f"New exposures found: {len(findings)}")
        by_kind: dict[str, int] = {}
        for f in findings:
            by_kind[f.kind] = by_kind.get(f.kind, 0) + 1
        lines += [f"  - {k}: {n}" for k, n in sorted(by_kind.items())]
        lines.append("")
    if needs:
        lines.append(f"Requests waiting on you: {len(needs)}")
        lines += [f"  - {r.broker.name}: {r.status.replace('_', ' ')}" for r in needs[:20]]
        lines.append("")
    if escalations:
        lines.append(f"Brokers that missed their legal deadline (complaint drafts ready): {len(escalations)}")
        lines += [f"  - {r.broker.name}" for r in escalations[:20]]
        lines.append("")
    lines.append("Open Data Cleaner to review. (Details are kept out of this email on purpose.)")
    return "\n".join(lines)


def send_digest(session: Session, *, now: datetime, since: datetime | None) -> bool:
    settings = Settings(session)
    text = build_digest(session, since)
    if not text:
        return False
    sent = False
    from .mail.transport import sender_address

    sender = sender_address(session)
    if settings.notify_email and sender:
        domain = sender.split("@")[-1]
        session.add(OutboxMessage(kind="digest", to_address=settings.notify_email, subject="Data Cleaner: things need your attention",
                                  body=text, message_id=f"<digest.{secrets.token_hex(8)}@{domain}>", created_at=now))
        sent = True
    if settings.ntfy_url:
        try:
            # Counts only. Never push personal details through a third-party push service.
            first_line = text.splitlines()[2] if len(text.splitlines()) > 2 else "Data Cleaner update"
            httpx.post(settings.ntfy_url, content=first_line.encode(), headers={"Title": "Data Cleaner"}, timeout=10)
            sent = True
        except httpx.HTTPError as exc:
            log.info("ntfy push failed: %s", exc)
    return sent
