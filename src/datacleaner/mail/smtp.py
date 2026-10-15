"""Outgoing mail: build messages from the outbox and send them under a rate limit."""

from __future__ import annotations

import logging
import smtplib
import ssl
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.utils import format_datetime, formataddr
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import OutboxMessage
from ..removal import engine
from ..settings import Settings

log = logging.getLogger(__name__)

MAX_ATTEMPTS = 5


class MailNotConfigured(RuntimeError):
    pass


class Mailer(Protocol):
    def send(self, message: EmailMessage) -> None: ...


class SmtpMailer:
    def __init__(self, host: str, port: int, security: str, username: str, password: str, timeout: int = 30):
        self.host, self.port, self.security = host, port, security
        self.username, self.password, self.timeout = username, password, timeout

    @classmethod
    def from_settings(cls, settings: Settings) -> "SmtpMailer":
        if not settings.smtp_host or not settings.from_address:
            raise MailNotConfigured("Set SMTP host and From address on the Settings page")
        return cls(settings.smtp_host, int(settings.smtp_port), settings.smtp_security,
                   settings.smtp_username or "", settings.smtp_password or "")

    def _connect(self) -> smtplib.SMTP:
        ctx = ssl.create_default_context()
        if self.security == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=ctx)
        else:
            server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            server.ehlo()
            if self.security == "starttls":
                server.starttls(context=ctx)
                server.ehlo()
        if self.username:
            server.login(self.username, self.password)
        return server

    def send(self, message: EmailMessage) -> None:
        with self._connect() as server:
            server.send_message(message)

    def check(self) -> None:
        with self._connect():
            pass


def build_message(msg: OutboxMessage, settings: Settings, *, now: datetime) -> EmailMessage:
    em = EmailMessage()
    em["From"] = formataddr((settings.from_name or "", settings.from_address))
    em["To"] = msg.to_address
    em["Subject"] = msg.subject
    em["Message-ID"] = msg.message_id
    em["Date"] = format_datetime(now if now.tzinfo else now.replace(tzinfo=UTC))
    if msg.in_reply_to:
        em["In-Reply-To"] = msg.in_reply_to
    if msg.references:
        em["References"] = msg.references
    em["Reply-To"] = settings.from_address
    em.set_content(msg.body)
    return em


def sent_in_last_hour(session: Session, now: datetime) -> int:
    return session.scalar(
        select(func.count()).select_from(OutboxMessage).where(
            OutboxMessage.status == "sent", OutboxMessage.sent_at >= now - timedelta(hours=1)
        )
    ) or 0


def drain_outbox(session: Session, mailer: Mailer | None, *, now: datetime) -> dict[str, int]:
    settings = Settings(session)
    stats = {"sent": 0, "failed": 0, "deferred": 0}
    queued = session.scalars(
        select(OutboxMessage).where(OutboxMessage.status == "queued").order_by(OutboxMessage.created_at)
    ).all()
    if not queued:
        return stats
    if mailer is None:
        try:
            mailer = SmtpMailer.from_settings(settings)
        except MailNotConfigured:
            stats["deferred"] = len(queued)
            return stats
    budget = max(0, int(settings.rate_limit_per_hour) - sent_in_last_hour(session, now))
    for msg in queued:
        if budget <= 0:
            stats["deferred"] += 1
            continue
        try:
            mailer.send(build_message(msg, settings, now=now))
        except Exception as exc:  # network errors, auth errors, refused recipients
            msg.attempts += 1
            msg.error = str(exc)[:1000]
            log.warning("Send failed for outbox %s (attempt %s): %s", msg.id, msg.attempts, exc)
            if msg.attempts >= MAX_ATTEMPTS or isinstance(exc, smtplib.SMTPRecipientsRefused):
                msg.status = "failed"
                engine.on_message_failed(session, msg, str(exc), now=now)
                stats["failed"] += 1
            continue
        msg.status = "sent"
        msg.sent_at = now
        msg.attempts += 1
        budget -= 1
        stats["sent"] += 1
        engine.on_message_sent(session, msg, now=now)
        session.flush()
    return stats
