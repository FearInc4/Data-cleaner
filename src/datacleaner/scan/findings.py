from __future__ import annotations

import hashlib
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Broker, Finding, FindingStatus, Profile


def fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(p.lower() for p in parts).encode()).hexdigest()


def upsert_finding(
    session: Session, profile: Profile, *, kind: str, source: str, key: str, now: datetime,
    url: str | None = None, title: str | None = None, snippet: str | None = None,
    data_classes: list[str] | None = None, matched: list[str] | None = None, score: float = 0.0,
    occurred_on: str | None = None, broker: Broker | None = None, check_state: str | None = None,
) -> tuple[Finding, bool]:
    fp = fingerprint(kind, source, key)
    row = session.scalars(select(Finding).where(Finding.profile_id == profile.id, Finding.fingerprint == fp)).first()
    created = row is None
    if row is None:
        row = Finding(profile=profile, kind=kind, source=source, fingerprint=fp, first_seen=now)
        session.add(row)
    elif row.status == FindingStatus.REMOVED and check_state == "found":
        # A listing we saw taken down is back. (A breach marked resolved stays resolved:
        # providers report the same breach on every check.)
        row.status = FindingStatus.NEW
        created = True
    row.last_seen = now
    row.url = url or row.url
    row.title = title or row.title
    row.snippet = snippet or row.snippet
    if data_classes is not None:
        row.data_classes = data_classes
    if matched is not None:
        row.matched_fields = matched
    row.score = max(score, row.score or 0.0) if not created else score
    row.occurred_on = occurred_on or row.occurred_on
    row.broker = broker or row.broker
    if check_state:
        row.check_state = check_state
    return row, created
