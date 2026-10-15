"""Incoming mail: poll IMAP, match replies to requests, act on them."""

from __future__ import annotations

import imaplib
import logging
import ssl
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import net
from ..brokers import host_matches
from ..models import Broker, OutboxMessage, Profile, RemovalRequest, RequestEvent, RequestStatus
from ..removal import engine
from ..settings import Settings
from .aliases import parse_alias
from .parse import (
    MSGID_RE,
    Classification,
    IncomingMessage,
    ReplyKind,
    classify,
    find_reference,
    parse_message,
    verification_links,
)
from .trust import STRONG, imap_authserv, recipients, sender_trust

log = logging.getLogger(__name__)
MAX_MESSAGE_BYTES = 10 * 1024 * 1024


class MailSource(Protocol):
    def fetch_new(self, session: Session) -> Iterable[IncomingMessage]: ...


class ImapSource:
    """Fetch messages newer than the last UID we processed (tracked per UIDVALIDITY)."""

    def __init__(self, host: str, port: int, username: str, password: str, folder: str = "INBOX", timeout: int = 30,
                 authserv: str | None = None):
        self.host, self.port, self.username, self.password, self.folder = host, port, username, password, folder
        self.timeout = timeout
        self.authserv = authserv if authserv is not None else imap_authserv(host)

    @classmethod
    def from_settings(cls, settings: Settings) -> "ImapSource | None":
        if not settings.imap_host or not settings.imap_username:
            return None
        return cls(settings.imap_host, int(settings.imap_port), settings.imap_username,
                   settings.imap_password or "", settings.imap_folder or "INBOX",
                   authserv=imap_authserv(settings.imap_host, settings.imap_authserv_id))

    def connect(self) -> imaplib.IMAP4_SSL:
        conn = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=ssl.create_default_context(), timeout=self.timeout)
        conn.login(self.username, self.password)
        return conn

    def check(self) -> None:
        conn = self.connect()
        try:
            conn.select(self.folder, readonly=True)
        finally:
            conn.logout()

    def fetch_new(self, session: Session, limit: int = 200) -> list[IncomingMessage]:
        settings = Settings(session)
        conn = self.connect()
        try:
            typ, data = conn.select(self.folder, readonly=True)
            if typ != "OK":
                raise RuntimeError(f"Cannot open folder {self.folder}")
            uidvalidity = _untagged(conn, "UIDVALIDITY")
            last_uid = int(settings.get("imap_last_uid") or 0)
            if uidvalidity and uidvalidity != settings.get("imap_uidvalidity"):
                # New mailbox (or server reset): start from recent mail, not the whole history.
                settings.set("imap_uidvalidity", uidvalidity)
                last_uid = 0
                typ, data = conn.uid("search", None, "SINCE", _imap_date_days_ago(30))
            else:
                typ, data = conn.uid("search", None, f"UID {last_uid + 1}:*")
            uids = [int(u) for u in (data[0] or b"").split() if int(u) > last_uid][:limit]
            out: list[IncomingMessage] = []
            for uid in uids:
                typ, msg_data = conn.uid("fetch", str(uid), f"(BODY.PEEK[]<0.{MAX_MESSAGE_BYTES}>)")
                if typ != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                    continue
                try:
                    msg = parse_message(msg_data[0][1], uid=str(uid))
                except Exception:  # one malformed message shouldn't stall the inbox
                    log.exception("Could not parse message UID %s", uid)
                    continue
                msg.authserv = self.authserv
                out.append(msg)
            if uids:
                settings.set("imap_last_uid", max(uids))
            return out
        finally:
            try:
                conn.logout()
            except Exception:
                pass


def _untagged(conn: imaplib.IMAP4, key: str) -> str | None:
    typ, data = conn.response(key)
    if data and data[0]:
        return data[0].decode() if isinstance(data[0], bytes) else str(data[0])
    return None


def _imap_date_days_ago(days: int) -> str:
    from datetime import UTC, timedelta

    return (datetime.now(UTC) - timedelta(days=days)).strftime("%d-%b-%Y")


# --- matching ------------------------------------------------------------------

def _request_for_alias(session: Session, msg: IncomingMessage) -> RemovalRequest | None:
    catchall = Settings(session).alias_domain or None
    for addr in recipients(msg):
        parsed = parse_alias(addr, catchall_domain=catchall)
        if not parsed:
            continue
        slug, profile_id = parsed
        if not session.get(Profile, profile_id):
            continue
        reqs = session.scalars(
            select(RemovalRequest).join(Broker).where(RemovalRequest.profile_id == profile_id)
            .order_by(RemovalRequest.created_at.desc())
        ).all()
        # Exact slug first; a long slug may have been shortened to fit the address.
        for match in (lambda b: b.slug == slug, lambda b: b.slug.startswith(slug)):
            candidates = [r for r in reqs if match(r.broker)]
            open_ = [r for r in candidates if r.status not in RequestStatus.TERMINAL]
            if open_ or candidates:
                return (open_ or candidates)[0]
    return None


def match_request(session: Session, msg: IncomingMessage, bounce: bool = False) -> tuple[RemovalRequest | None, str]:
    """Find the request an email belongs to. Returns (request, how it was matched)."""
    # 1. Threading headers (and, for bounces, Message-IDs quoted in the DSN body).
    ids = list(msg.thread_ids)
    if bounce or not ids:
        ids += MSGID_RE.findall(msg.text)
    if ids:
        ev = session.scalars(select(RequestEvent).where(RequestEvent.message_id.in_(ids),
                                                        RequestEvent.direction == "out")).first()
        if ev:
            return ev.request, "thread"
        out = session.scalars(select(OutboxMessage).where(OutboxMessage.message_id.in_(ids))).first()
        if out and out.request_id:
            return session.get(RemovalRequest, out.request_id), "thread"
        # A reply to a message we *received*: same conversation, but anyone could have
        # sent that message, so this proves nothing about the sender.
        ev = session.scalars(select(RequestEvent).where(RequestEvent.message_id.in_(ids))).first()
        if ev:
            return ev.request, "chain"
    # 2. Our private reference token in subject/body.
    ref = find_reference(msg)
    if ref:
        req = session.scalars(select(RemovalRequest).where(RemovalRequest.reference == ref)).first()
        if req:
            return req, "reference"
    # 3. Sent to a per-broker alias.
    if not bounce:
        req = _request_for_alias(session, msg)
        if req:
            return req, "alias"
    # 4. Sender's domain belongs to a broker with exactly one open request.
    if msg.from_domain and not bounce:
        candidates = []
        open_reqs = session.scalars(
            select(RemovalRequest).join(Broker).where(RemovalRequest.status.not_in(list(RequestStatus.TERMINAL)))
        ).all()
        for req in open_reqs:
            domains = list(req.broker.domains or [])
            if req.broker.privacy_email:
                domains.append(req.broker.privacy_email.rsplit("@", 1)[-1])
            if host_matches(msg.from_domain, domains):
                candidates.append(req)
        if len(candidates) == 1:
            return candidates[0], "domain"
    return None, ""


# --- acting on replies -------------------------------------------------------------

Clicker = Callable[[str], int]


def default_clicker(url: str) -> int:
    # Verification links come from email: refuse anything that isn't a public https host, at every redirect.
    with net.public_client(timeout=20) as client:
        return client.get(url).status_code


def _our_message_ids(req: RemovalRequest) -> set[str]:
    return {e.message_id for e in req.events if e.direction == "out" and e.message_id}


def _our_bodies(req: RemovalRequest) -> list[str]:
    return [e.body for e in req.events if e.direction == "out" and e.body]


def _flag_for_review(session: Session, req: RemovalRequest, summary: str, *, now: datetime) -> None:
    req.needs_review = True
    engine.add_event(session, req, "review", summary, now=now)


def apply_reply(session: Session, req: RemovalRequest, msg: IncomingMessage, cls: Classification, *,
                now: datetime, clicker: Clicker | None = None, trust: str = "thread", matched_by: str = "thread") -> str:
    """Record the reply on the request and move it along. Returns a short description of what happened.

    Only replies we can tie to the broker (``trust`` in STRONG) change the request's state.
    Anything else is kept for the person to judge, and the follow-up clock keeps running.
    """
    settings = Settings(session)
    strong = trust in STRONG
    if cls.kind != ReplyKind.BOUNCE and strong:
        req.last_reply_at = now
    summary = f"Reply from {msg.from_addr}: {msg.subject[:120]}"
    if not strong:
        summary += " (sender not verified)"
    engine.add_event(session, req, "reply", summary, now=now, direction="in", body=msg.text[:20000],
                     message_id=msg.message_id)
    detail = f" ({cls.evidence})" if cls.evidence else ""

    if cls.kind == ReplyKind.BOUNCE:
        if matched_by != "thread":
            _flag_for_review(session, req, "A bounce notice arrived but doesn't quote our message. Check it.", now=now)
            return "unverified"
        engine.set_status(session, req, RequestStatus.NEEDS_USER_ACTION, now=now,
                          summary="Email bounced; the broker's address may have changed. Check the broker page or use their web form.")
        return "bounce"

    if cls.kind == ReplyKind.AUTO_REPLY:
        return "auto_reply"

    if not strong:
        if matched_by == "alias" and trust == "none":
            hint = (f"Mail from {msg.from_domain or 'an unknown sender'} arrived at the address you gave {req.broker.name}. "
                    f"If it isn't from {req.broker.name}, they may have shared or leaked your address.")
        else:
            label = {ReplyKind.COMPLETED: "says the request is complete", ReplyKind.NOT_FOUND: "says they hold no data",
                     ReplyKind.NEEDS_VERIFICATION: "asks you to confirm", ReplyKind.NEEDS_INFO: "asks for more information",
                     ReplyKind.REJECTED: "declines the request", ReplyKind.ACKNOWLEDGED: "acknowledges the request"}.get(cls.kind, "arrived")
            hint = (f"A reply {label}, but we can't prove it came from {req.broker.name}. "
                    "Read it, and update the request yourself if it's genuine. Follow-ups continue meanwhile.")
        _flag_for_review(session, req, hint, now=now)
        return "unverified"

    if cls.kind in (ReplyKind.COMPLETED, ReplyKind.NOT_FOUND):
        label = "Broker confirmed deletion" if cls.kind == ReplyKind.COMPLETED else "Broker says it holds no data about you"
        engine.mark_completed(session, req, now=now, summary=label + detail)
        return cls.kind

    if cls.kind == ReplyKind.NEEDS_VERIFICATION:
        links = verification_links(msg, list(req.broker.domains or []))
        if links and settings.auto_click_verification:
            clicker = clicker or default_clicker
            try:
                status = clicker(links[0])
            except Exception as exc:
                status = 0
                log.info("Verification link failed: %s", exc)
            if 200 <= status < 400:
                engine.add_event(session, req, "verified",
                                 f"Opened verification link (HTTP {status}). If the page needed a button press, open it yourself: {links[0]}",
                                 now=now)
                engine.set_status(session, req, RequestStatus.ACKNOWLEDGED, now=now, summary="Verification link opened")
                return "verified"
        engine.set_status(session, req, RequestStatus.NEEDS_VERIFICATION, now=now,
                          summary="Broker wants you to confirm the request" + (f": {links[0]}" if links else "; open the email and click the link") + detail)
        return "needs_verification"

    if cls.kind == ReplyKind.NEEDS_INFO:
        engine.set_status(session, req, RequestStatus.NEEDS_USER_ACTION, now=now,
                          summary="Broker asked for more information" + detail)
        return "needs_info"

    if cls.kind == ReplyKind.REJECTED:
        engine.set_status(session, req, RequestStatus.REJECTED, now=now, summary="Broker declined the request" + detail)
        return "rejected"

    if cls.kind == ReplyKind.ACKNOWLEDGED:
        if req.status in (RequestStatus.SENT, RequestStatus.QUEUED):
            engine.set_status(session, req, RequestStatus.ACKNOWLEDGED, now=now, summary="Broker acknowledged" + detail)
        return "acknowledged"

    # Unknown: a human should read it, but don't stop the clock on the broker.
    _flag_for_review(session, req, "New reply needs your review", now=now)
    if req.status in (RequestStatus.SENT, RequestStatus.QUEUED):
        req.status = RequestStatus.ACKNOWLEDGED
        session.flush()
        engine.schedule_next(req, settings)
    return "unknown"


def process_inbox(session: Session, source: MailSource | None, *, now: datetime,
                  clicker: Clicker | None = None) -> dict[str, int]:
    from .transport import get_source, sender_address

    stats: dict[str, int] = {"fetched": 0, "matched": 0}
    if source is None:
        source = get_source(session)
        if source is None:
            return stats
    from .oauth_mail import MailAuthError

    own = (sender_address(session) or "").lower()
    try:
        messages = list(source.fetch_new(session))
    except MailAuthError as exc:
        # The account was flagged "needs reconnect"; return normally so that sticks
        # (raising would roll it back, and replies would silently stop being read).
        log.warning("Mailbox needs reconnecting: %s", exc)
        stats["needs_reconnect"] = 1
        return stats
    for msg in messages:
        stats["fetched"] += 1
        if msg.message_id and session.scalars(
            select(RequestEvent).where(RequestEvent.message_id == msg.message_id, RequestEvent.direction == "in")
        ).first():
            continue  # already processed
        cls = classify(msg)
        req, how = match_request(session, msg, bounce=cls.kind == ReplyKind.BOUNCE)
        if req is None:
            continue
        # Ignore copies of our own outgoing messages (e.g. Gmail shows sent mail in All Mail).
        if own and msg.from_addr == own and cls.kind != ReplyKind.BOUNCE:
            continue
        if cls.kind != ReplyKind.BOUNCE:
            cls = classify(msg, ours=_our_bodies(req))
        trust = "thread" if how == "thread" else sender_trust(msg, req, our_message_ids=_our_message_ids(req))
        stats["matched"] += 1
        outcome = apply_reply(session, req, msg, cls, now=now, clicker=clicker, trust=trust, matched_by=how)
        stats[outcome] = stats.get(outcome, 0) + 1
        session.flush()
    return stats
