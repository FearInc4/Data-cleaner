"""Inbox unsubscribe helper.

Finds senders that include a List-Unsubscribe header and unsubscribes on request:

- RFC 8058 one-click: POST ``List-Unsubscribe=One-Click`` to the https URL. Safe to automate.
- mailto: send an "unsubscribe" email from your address.
- Plain web links are shown but never fetched automatically: opening them can
  confirm to a spammer that your address is live.
"""

from __future__ import annotations

import email
import email.policy
import imaplib
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import getaddresses, parsedate_to_datetime
from urllib.parse import parse_qs, unquote, urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import net
from ..mail.inbox import ImapSource
from ..models import MailingSender, OutboxMessage

HEADER_FIELDS = "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE LIST-UNSUBSCRIBE LIST-UNSUBSCRIBE-POST)])"


@dataclass
class UnsubInfo:
    sender: str
    display_name: str
    subject: str
    date: datetime | None
    one_click_url: str | None
    mailto: str | None
    web_url: str | None


def parse_list_unsubscribe(header: str, post_header: str | None) -> tuple[str | None, str | None, str | None]:
    """Return (one_click_url, mailto, web_url)."""
    entries = re.findall(r"<([^>]+)>", header or "")
    https = [e.strip() for e in entries if e.strip().lower().startswith("https://")]
    http = [e.strip() for e in entries if e.strip().lower().startswith("http://")]
    mailtos = [e.strip() for e in entries if e.strip().lower().startswith("mailto:")]
    one_click = None
    if https and post_header and "list-unsubscribe=one-click" in post_header.lower().replace(" ", ""):
        one_click = https[0]
    web = None if one_click else (https[0] if https else (http[0] if http else None))
    return one_click, (mailtos[0] if mailtos else None), web


def parse_headers(raw: bytes) -> UnsubInfo | None:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    lu = str(msg.get("List-Unsubscribe", "") or "")
    if not lu:
        return None
    one_click, mailto, web = parse_list_unsubscribe(lu, str(msg.get("List-Unsubscribe-Post", "") or ""))
    pairs = getaddresses([str(msg.get("From", ""))])
    name, addr = pairs[0] if pairs else ("", "")
    if not addr:
        return None
    try:
        dt = parsedate_to_datetime(str(msg["Date"])) if msg.get("Date") else None
    except (TypeError, ValueError):
        dt = None
    return UnsubInfo(addr.lower(), name, str(msg.get("Subject", "")), dt, one_click, mailto, web)


def scan_inbox(session: Session, *, days: int = 60, limit: int = 2000, source: ImapSource | None = None) -> int:
    from ..mail.transport import get_source

    if source is None:
        active = get_source(session)
        if active is not None and hasattr(active, "fetch_headers"):
            # Connected Gmail / Microsoft account.
            infos = [i for i in (parse_headers(raw) for raw in active.fetch_headers(days, limit)) if i]
            return record(session, infos)
        source = active
    if source is None:
        raise RuntimeError("Connect your mailbox on the Settings page first")
    conn = source.connect()
    infos: list[UnsubInfo] = []
    try:
        conn.select(source.folder, readonly=True)
        since = (datetime.now(UTC) - timedelta(days=days)).strftime("%d-%b-%Y")
        typ, data = conn.uid("search", None, "SINCE", since)
        uids = (data[0] or b"").split()[-limit:]
        for i in range(0, len(uids), 100):
            batch = b",".join(uids[i:i + 100]).decode()
            typ, resp = conn.uid("fetch", batch, HEADER_FIELDS)
            for part in resp or []:
                if isinstance(part, tuple):
                    info = parse_headers(part[1])
                    if info:
                        infos.append(info)
    finally:
        try:
            conn.logout()
        except (imaplib.IMAP4.error, OSError):
            pass
    return record(session, infos)


def record(session: Session, infos: list[UnsubInfo]) -> int:
    by_sender: dict[str, MailingSender] = {}
    for info in infos:
        row = by_sender.get(info.sender) or session.scalars(
            select(MailingSender).where(MailingSender.sender == info.sender)
        ).first()
        if row is None:
            row = MailingSender(sender=info.sender, messages=0)
            session.add(row)
        by_sender[info.sender] = row
        row.messages = (row.messages or 0) + 1
        row.display_name = info.display_name or row.display_name
        when = info.date.astimezone(UTC).replace(tzinfo=None) if info.date and info.date.tzinfo else info.date
        if when and (row.last_seen is None or when >= row.last_seen):
            row.last_seen = when
            row.sample_subject = info.subject[:300]
            row.one_click_url = info.one_click_url or row.one_click_url
            row.mailto = info.mailto or row.mailto
            row.web_url = info.web_url or row.web_url
        elif not (row.one_click_url or row.mailto):
            row.one_click_url = info.one_click_url
            row.mailto = info.mailto
            row.web_url = row.web_url or info.web_url
    session.flush()
    return len(by_sender)


_SAFE_SUBJECT = re.compile(r"[^\w\s.:#@+=-]")


def _parse_mailto(mailto: str) -> tuple[str, str, str]:
    """Recipient and a sanitised subject. The body is always ours.

    The sender of a spam email controls this header. Letting it choose the
    body would let a stranger send arbitrary text from your account, so only a
    short single-line subject is kept (some list servers need a token there).
    """
    parsed = urlparse(mailto)
    addr = unquote(parsed.path).strip()
    if "," in addr or any(c in addr for c in "\r\n<>"):
        addr = ""  # one recipient only
    qs = parse_qs(parsed.query)
    subject = " ".join((qs.get("subject", ["unsubscribe"])[0] or "unsubscribe").split())
    subject = _SAFE_SUBJECT.sub("", subject)[:100] or "unsubscribe"
    return addr, subject, "unsubscribe"


def is_public_https(url: str) -> bool:
    """Header URLs come from strangers; never let one point us at the local network."""
    return net.is_public_url(url)


def unsubscribe(session: Session, sender: MailingSender, *, now: datetime, client: httpx.Client | None = None) -> str:
    if sender.one_click_url and not is_public_https(sender.one_click_url):
        sender.status, sender.detail = "failed", "Refused: unsubscribe URL does not point at a public https host"
        return "failed"
    if sender.one_click_url:
        own = client is None
        client = client or net.public_client(timeout=20, follow_redirects=False)
        try:
            resp = client.post(sender.one_click_url, data={"List-Unsubscribe": "One-Click"})
        except httpx.HTTPError as exc:
            sender.status, sender.detail = "failed", str(exc)[:300]
            return "failed"
        finally:
            if own:
                client.close()
        if resp.status_code < 400:
            sender.status, sender.detail = "unsubscribed", f"One-click POST (HTTP {resp.status_code})"
            return "unsubscribed"
        sender.status, sender.detail = "failed", f"One-click POST returned HTTP {resp.status_code}"
        if not sender.mailto:
            return "failed"
    if sender.mailto:
        addr, subject, body = _parse_mailto(sender.mailto)
        if "@" not in addr:
            sender.status, sender.detail = "failed", "Invalid mailto address"
            return "failed"
        from ..mail.transport import sender_address

        domain = (sender_address(session) or "datacleaner.local").split("@")[-1]
        session.add(OutboxMessage(kind="unsubscribe", to_address=addr, subject=subject[:200], body=body[:1000],
                                  message_id=f"<unsub.{secrets.token_hex(8)}@{domain}>", created_at=now))
        sender.status, sender.detail = "unsubscribed", f"Unsubscribe email queued to {addr}"
        return "queued"
    sender.status, sender.detail = "kept", "Only a web link is available; open it yourself if you trust the sender."
    return "manual"
