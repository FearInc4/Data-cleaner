"""How sure are we that a reply really came from the broker?

Anyone can send an email that *looks* like "Your data has been deleted". If we
believed it, a broker (or anyone) could make us stop following up just by
spoofing a confirmation. So replies are graded:

- ``thread``: the email quotes one of our unguessable Message-IDs or our
  private request reference. Strong.
- ``authenticated``: the receiving mail server says DMARC (or aligned DKIM)
  passed for a domain that belongs to this broker. Strong.
- ``domain``: the From address is on the broker's domain, but nothing proves it.
  Weak (trivially spoofed).
- ``none``: none of the above.

Only strong replies can close a request or have their verification links opened
automatically. Weak ones are recorded and shown to the person to confirm.
"""

from __future__ import annotations

import re
from email.utils import getaddresses

from ..brokers import host_matches
from ..models import RemovalRequest
from .parse import IncomingMessage, find_reference

STRONG = {"thread", "authenticated"}

_DKIM_DOMAIN = re.compile(r"\bdkim\s*=\s*pass\b[^;]*?\bheader\.(?:d|i)\s*=\s*@?([A-Za-z0-9.-]+)", re.I)
_DMARC_FROM = re.compile(r"\bdmarc\s*=\s*pass\b[^;]*?\bheader\.from\s*=\s*([A-Za-z0-9.-]+)", re.I)


def _broker_domains(req: RemovalRequest) -> list[str]:
    domains = list(req.broker.domains or [])
    if req.broker.privacy_email and "@" in req.broker.privacy_email:
        domains.append(req.broker.privacy_email.rsplit("@", 1)[1].lower())
    return domains


def top_authentication_results(msg: IncomingMessage) -> str:
    """The topmost Authentication-Results header: the one our own mail provider added.

    Headers lower down may have been forged by the sender, so only the first counts.
    """
    raw = msg.raw_headers.get("authentication-results") or []
    return raw[0] if raw else ""


def authenticated_domain(msg: IncomingMessage) -> str | None:
    """The domain our provider vouches for, if DMARC passed or DKIM passed aligned with From."""
    ar = top_authentication_results(msg)
    if not ar:
        return None
    from_domain = msg.from_domain
    m = _DMARC_FROM.search(ar)
    if m:
        d = m.group(1).lower()
        return d if (not from_domain or from_domain == d or from_domain.endswith("." + d) or d.endswith("." + from_domain)) else None
    for d in _DKIM_DOMAIN.findall(ar):
        d = d.lower()
        if from_domain and (from_domain == d or from_domain.endswith("." + d)):
            return d
    return None


def sender_trust(msg: IncomingMessage, req: RemovalRequest, *, our_message_ids: set[str]) -> str:
    if set(msg.thread_ids) & our_message_ids:
        return "thread"
    if find_reference(msg) == req.reference:
        return "thread"
    domains = _broker_domains(req)
    auth = authenticated_domain(msg)
    if auth and (host_matches(auth, domains) or any(host_matches(d, [auth]) for d in domains)):
        return "authenticated"
    if msg.from_domain and host_matches(msg.from_domain, domains):
        return "domain"
    return "none"


def recipients(msg: IncomingMessage) -> list[str]:
    """Every address the message was delivered to (for alias matching)."""
    out: list[str] = []
    for name in ("to", "cc", "delivered-to", "x-original-to", "envelope-to", "x-forwarded-to"):
        for value in msg.raw_headers.get(name, []):
            out += [a.lower() for _, a in getaddresses([value]) if a]
    return out
