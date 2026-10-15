"""The heartbeat. ``tick()`` is idempotent: run it every few minutes, from the web
process (default) or from cron/systemd with ``datacleaner tick``.

Order of work per tick:
1. Send queued mail (rate limited).
2. Read new mail and act on broker replies.
3. Queue due follow-ups, final notices, escalations.
4. Re-check brokers whose removal was confirmed a while ago.
5. Run due exposure scans and breach checks.
6. Send a digest if anything needs the person.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import or_, select

from .breach.providers import providers_from_settings, run_breach_check
from .db import session_scope
from .mail.inbox import Clicker, MailSource, process_inbox
from .mail.smtp import Mailer, drain_outbox
from .models import Profile, utcnow
from .notify import send_digest
from .removal import engine
from .scan.brokers import check_brokers
from .scan.search import provider_from_settings, run_search_scan
from .settings import Settings

log = logging.getLogger(__name__)
_lock = threading.Lock()


@dataclass
class TickDeps:
    """Injectable side-effects, so tests can run a tick without a network."""
    mailer: Mailer | None = None
    mail_source: MailSource | None = None
    clicker: Clicker | None = None
    run_scans: bool = True


@dataclass
class TickReport:
    started: datetime
    steps: dict[str, object] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def _step(report: TickReport, name: str, fn):
    try:
        with session_scope() as session:
            report.steps[name] = fn(session)
    except Exception as exc:
        log.exception("Scheduler step %s failed", name)
        report.errors.append(f"{name}: {exc}")


def tick(now: datetime | None = None, deps: TickDeps | None = None) -> TickReport:
    now = now or utcnow()
    deps = deps or TickDeps()
    report = TickReport(started=now)
    if not _lock.acquire(blocking=False):
        report.errors.append("tick already running")
        return report
    try:
        _step(report, "outbox", lambda s: drain_outbox(s, deps.mailer, now=now))
        _step(report, "inbox", lambda s: process_inbox(s, deps.mail_source, now=now, clicker=deps.clicker))
        _step(report, "followups", lambda s: engine.process_due(s, now=now))
        # Follow-ups queued above go out in this same tick.
        _step(report, "outbox_followups", lambda s: drain_outbox(s, deps.mailer, now=now))
        _step(report, "rechecks", lambda s: _rechecks(s, now))
        if deps.run_scans:
            _step(report, "scans", lambda s: _due_scans(s, now))
        _step(report, "digest", lambda s: _digest(s, now))
    finally:
        _lock.release()
    return report


def _rechecks(session, now: datetime) -> int:
    n = 0
    by_profile: dict[int, list[int]] = {}
    for req in engine.due_rechecks(session, now=now):
        req.recheck_at = None
        if req.broker.search_url:
            by_profile.setdefault(req.profile_id, []).append(req.broker_id)
        engine.add_event(session, req, "recheck", "Re-checking whether the listing came back", now=now)
        n += 1
    for profile_id, broker_ids in by_profile.items():
        profile = session.get(Profile, profile_id)
        if profile:
            check_brokers(session, profile, broker_ids=broker_ids, now=now)
    return n


def _due_scans(session, now: datetime) -> dict[str, int]:
    settings = Settings(session)
    stats = {"search": 0, "brokers": 0, "breach": 0}
    profiles = session.scalars(select(Profile).where(
        Profile.monitoring_enabled.is_(True), Profile.attested_at.is_not(None),
        or_(Profile.next_scan_at.is_(None), Profile.next_scan_at <= now,
            Profile.next_breach_check_at.is_(None), Profile.next_breach_check_at <= now),
    )).all()
    for p in profiles:
        if p.next_scan_at is None or p.next_scan_at <= now:
            provider = provider_from_settings(settings)
            if provider:
                run_search_scan(session, p, provider, now=now)
                stats["search"] += 1
            check_brokers(session, p, now=now)
            stats["brokers"] += 1
            p.next_scan_at = now + timedelta(days=int(settings.scan_interval_days))
        if p.next_breach_check_at is None or p.next_breach_check_at <= now:
            providers = providers_from_settings(settings)
            if providers:
                run_breach_check(session, p, providers, now=now)
                stats["breach"] += 1
            p.next_breach_check_at = now + timedelta(days=int(settings.breach_interval_days))
        session.flush()
    return stats


def _digest(session, now: datetime) -> bool:
    settings = Settings(session)
    last = settings.get("last_digest_at")
    last_dt = datetime.fromisoformat(last) if last else None
    if last_dt and now - last_dt < timedelta(hours=20):
        return False
    sent = send_digest(session, now=now, since=last_dt)
    if sent or last_dt is None:
        settings.set("last_digest_at", now.isoformat())
    return sent


class BackgroundScheduler:
    def __init__(self, interval_seconds: int):
        self.interval = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="datacleaner-scheduler", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        # Small delay so the web server is up before the first (possibly slow) tick.
        if self._stop.wait(10):
            return
        while not self._stop.is_set():
            report = tick()
            with session_scope() as s:
                Settings(s).set("last_tick_at", report.started.isoformat())
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
