"""Parse incoming mail and classify broker replies.

Classification is deliberately rule-based and transparent: every decision can
be traced to a phrase in the email. Wrong guesses only ever move a request to a
state where a human looks at it; nothing is auto-closed on a weak signal.
"""

from __future__ import annotations

import email
import email.policy
import html
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime
from datetime import datetime
from urllib.parse import urlparse

REF_RE = re.compile(r"\bDC-[A-HJ-NP-Z2-9]{8}\b")
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.I)
MSGID_RE = re.compile(r"<[^<>@\s]+@[^<>\s]+>")


@dataclass
class IncomingMessage:
    uid: str
    message_id: str | None
    in_reply_to: str | None
    references: list[str]
    from_addr: str
    from_name: str
    to_addrs: list[str]
    subject: str
    date: datetime | None
    text: str
    links: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    # Every header value in original order, keyed by lower-case name.
    raw_headers: dict[str, list[str]] = field(default_factory=dict)
    # Who should have stamped the topmost Authentication-Results header (our mail
    # provider's authserv-id). None: unknown, so that header proves nothing.
    authserv: str | None = None

    @property
    def from_domain(self) -> str:
        return self.from_addr.rsplit("@", 1)[-1].lower() if "@" in self.from_addr else ""

    @property
    def thread_ids(self) -> list[str]:
        ids = list(self.references)
        if self.in_reply_to:
            ids.append(self.in_reply_to)
        return ids


def html_to_text(markup: str) -> str:
    markup = re.sub(r"(?is)<(script|style).*?</\1>", " ", markup)
    markup = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</li>", "\n", markup)
    markup = re.sub(r"<[^>]+>", " ", markup)
    text = html.unescape(markup)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()


def _clean_url(u: str) -> str:
    return html.unescape(u).rstrip(".,;:!?")


def parse_message(raw: bytes, uid: str = "") -> IncomingMessage:
    msg: EmailMessage = email.message_from_bytes(raw, policy=email.policy.default)  # type: ignore[assignment]
    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        if part.get_content_disposition() == "attachment":
            continue
        try:
            content = part.get_content()
        except (LookupError, ValueError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if not isinstance(content, str):
            # message/rfc822 (bounce attachments) and other non-text parts
            if ctype in ("message/rfc822", "message/delivery-status", "text/rfc822-headers"):
                content = str(content)
            else:
                continue
        if ctype == "text/html":
            html_parts.append(content)
        elif ctype.startswith("text/") or ctype.startswith("message/"):
            text_parts.append(content)
    text = "\n\n".join(text_parts).strip()
    if not text and html_parts:
        text = html_to_text("\n".join(html_parts))

    links: list[str] = []
    for h in html_parts:
        links.extend(_clean_url(u) for u in HREF_RE.findall(h) if u.lower().startswith(("http://", "https://")))
    links.extend(_clean_url(u) for u in URL_RE.findall(text))
    seen: set[str] = set()
    uniq = [u for u in links if not (u in seen or seen.add(u))]

    from_pairs = getaddresses([str(msg.get("From", ""))])
    from_name, from_addr = from_pairs[0] if from_pairs else ("", "")
    date = None
    if msg.get("Date"):
        try:
            date = parsedate_to_datetime(str(msg["Date"]))
        except (TypeError, ValueError):
            date = None
    refs = MSGID_RE.findall(str(msg.get("References", "")))
    irt = MSGID_RE.findall(str(msg.get("In-Reply-To", "")))
    return IncomingMessage(
        uid=uid,
        message_id=(MSGID_RE.findall(str(msg.get("Message-ID", ""))) or [None])[0],
        in_reply_to=irt[0] if irt else None,
        references=refs,
        from_addr=from_addr.lower(),
        from_name=from_name,
        to_addrs=[a.lower() for _, a in getaddresses([str(msg.get("To", ""))]) if a],
        subject=str(msg.get("Subject", "")),
        date=date,
        text=text,
        links=uniq,
        headers={k: str(v) for k, v in msg.items()},
        raw_headers=_ordered_headers(msg),
    )


def _ordered_headers(msg) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for k, v in msg.items():
        out.setdefault(k.lower(), []).append(str(v))
    return out


# --- classification ----------------------------------------------------------

class ReplyKind:
    COMPLETED = "completed"
    NEEDS_VERIFICATION = "needs_verification"
    NEEDS_INFO = "needs_info"
    REJECTED = "rejected"
    NOT_FOUND = "not_found"  # "we have no records" (often counts as done)
    ACKNOWLEDGED = "acknowledged"
    BOUNCE = "bounce"
    AUTO_REPLY = "auto_reply"
    UNKNOWN = "unknown"


_RULES: list[tuple[str, list[str]]] = [
    (ReplyKind.NEEDS_VERIFICATION, [
        r"click (the|this|on the)? ?(link|button) (below )?to (verify|confirm|complete|validate)",
        r"(verify|confirm) your (email|request|opt[- ]?out|identity by clicking)",
        r"please confirm (your|this) (request|opt[- ]?out|removal)",
        r"verification (link|code)",
        r"confirm (that )?you (made|submitted) this request",
    ]),
    (ReplyKind.COMPLETED, [
        r"(has|have) been (successfully )?(deleted|removed|suppressed|opted out|processed|honou?red|completed)",
        r"(we|we've|we have) (deleted|removed|suppressed|opted you out|processed your (deletion|opt[- ]?out))",
        r"your (deletion|removal|opt[- ]?out|suppression) (request )?(is|was) (now )?(complete|completed|processed|successful)",
        r"(request|opt[- ]?out) (has been|was) (completed|fulfilled|processed)",
        r"will no longer (appear|be displayed|be shown|be sold)",
    ]),
    (ReplyKind.NOT_FOUND, [
        r"(unable|could not|couldn't|were not able) to (locate|find|identify) (any )?(records?|information|data|personal)",
        r"(no|do not have any) (records?|personal (information|data)) (matching|associated|about|on file|for you)",
        r"we do not (hold|have|maintain|process) (any )?(personal )?(data|information) (about|for|relating to) you",
    ]),
    (ReplyKind.NEEDS_INFO, [
        r"(need|require) (additional|more|further) information",
        r"(please )?(provide|send|attach|upload) (a copy of )?(your|a) (government|photo|driver'?s|state)? ?(id|identification|license|proof)",
        r"(unable|cannot|can't) (to )?verify your identity",
        r"(please )?(provide|send) (us )?the (url|link) (of|to) (your|the) (profile|listing|record)",
        r"(fill out|complete|submit) (the|our) (web )?form",
        r"(please )?(visit|use|go to) (our )?(online )?(privacy|opt[- ]?out|request) (portal|page|form|center)",
    ]),
    (ReplyKind.REJECTED, [
        r"(we are|we're) (unable|not able) to (honou?r|process|comply with) (your|this) request",
        r"(do not|does not|don't) (qualify|apply)",
        r"exempt from",
        r"(request|it) (is|has been) (denied|declined|rejected)",
        r"only (available|applies) to (residents|consumers) of",
    ]),
    (ReplyKind.ACKNOWLEDGED, [
        r"(we have|we've) received your (request|email|message)",
        r"(thank you for|thanks for) (contacting|your (request|email|message))",
        r"(we will|we'll) (process|respond|get back|review)",
        r"within \d+ (business )?days",
        r"ticket (number|#|id)",
    ]),
]
_COMPILED = [(kind, [re.compile(p, re.I) for p in pats]) for kind, pats in _RULES]

_BOUNCE_SENDERS = ("mailer-daemon@", "postmaster@", "mail-daemon@")
_BOUNCE_SUBJECTS = re.compile(
    r"(undeliver|delivery status notification|delivery (has )?failed|returned mail|failure notice|mail delivery (failed|system))", re.I
)
_AUTO_REPLY_SUBJECT = re.compile(r"^(auto(matic)? ?(reply|response)|out of (the )?office)", re.I)


@dataclass
class Classification:
    kind: str
    evidence: str = ""


def classify(msg: IncomingMessage, ours: Iterable[str] = ()) -> Classification:
    """Classify a reply. ``ours`` are the letters we sent on this request: wording quoted
    from them ("...confirming that the request has been completed") is never evidence."""
    if msg.from_addr.startswith(_BOUNCE_SENDERS) or _BOUNCE_SUBJECTS.search(msg.subject) or "multipart/report" in msg.headers.get("Content-Type", ""):
        return Classification(ReplyKind.BOUNCE, msg.subject[:120])
    ours_norm = _norm("\n".join(o for o in ours if o))
    body = f"{msg.subject}\n{_strip_quoted(msg.text, ours_norm)}"
    for kind, patterns in _COMPILED:
        for pat in patterns:
            for m in pat.finditer(body):
                if ours_norm and _line_at(body, m) in ours_norm:
                    continue  # our own words, re-wrapped or pasted without quote marks
                return Classification(kind, _context(body, m))
    auto = msg.headers.get("Auto-Submitted", "").lower()
    if (auto and auto != "no") or _AUTO_REPLY_SUBJECT.search(msg.subject):
        return Classification(ReplyKind.AUTO_REPLY, msg.subject[:120])
    return Classification(ReplyKind.UNKNOWN)


_QUOTE_START = re.compile(
    r"\s*(-{3,}\s*(Original (request|message)|Forwarded message)|_{10,}\s*$|On .{5,200} wrote:|Begin forwarded message:)", re.I)
_ON_WROTE_START = re.compile(r"\s*On .{5,200}$", re.I)
_HEADER_FROM = re.compile(r"\s*\*?(From|De|Von):\*?\s+\S", re.I)
_HEADER_NEXT = re.compile(r"\s*\*?(Sent|Date|To|Subject|Cc|Envoy[ée]|Gesendet|Enviado):\*?(\s|$)", re.I)


def _norm(text: str) -> str:
    return " ".join(text.lower().split())


def _line_at(text: str, m: re.Match[str]) -> str:
    start = text.rfind("\n", 0, m.start()) + 1
    end = text.find("\n", m.end())
    return _norm(text[start:end if end >= 0 else len(text)])


def _strip_quoted(text: str, ours_norm: str = "") -> str:
    """Drop quoted mail (ours, mostly) so its wording ('delete', 'has been completed') doesn't trigger rules.

    Handles '>' quoting, Gmail's "On ... wrote:", Outlook's From:/Sent: header block and
    separator lines, and, given ``ours_norm``, lines copied verbatim from our letters.
    """
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        if line.lstrip().startswith(">"):
            continue
        if _QUOTE_START.match(line):
            break
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if _ON_WROTE_START.match(line) and nxt.lower().endswith("wrote:"):
            break  # "On <date>, <name> <\naddress> wrote:" wrapped over two lines
        if _HEADER_FROM.match(line) and any(_HEADER_NEXT.match(n) for n in lines[i + 1:i + 5]):
            break
        if ours_norm:
            n = _norm(line)
            if len(n) >= 20 and n in ours_norm:
                continue
        out.append(line)
    return "\n".join(out)


def _context(text: str, m: re.Match[str]) -> str:
    start = max(0, m.start() - 60)
    end = min(len(text), m.end() + 60)
    return " ".join(text[start:end].split())


# --- verification links --------------------------------------------------------

_VERIFY_HINTS = ("verify", "verif", "confirm", "optout", "opt-out", "opt_out", "suppress", "validate", "removal", "remove", "token", "activate")
_NEVER_FOLLOW = ("unsubscribe", "privacy-policy", "terms", "login", "signin", "sign-in", "account/delete", "upgrade", "checkout", "pay")


def verification_links(msg: IncomingMessage, allowed_domains: list[str]) -> list[str]:
    """Links in the email that look like confirmation links on the broker's own domain.

    Links anywhere else (click trackers, other companies) are never auto-opened.
    """
    from ..brokers import host_matches

    out = []
    for link in msg.links:
        parsed = urlparse(link)
        if parsed.scheme != "https":
            continue
        if not host_matches(parsed.hostname or "", allowed_domains):
            continue
        low = link.lower()
        if any(bad in low for bad in _NEVER_FOLLOW):
            continue
        if any(h in low for h in _VERIFY_HINTS):
            out.append(link)
    return out


def find_reference(msg: IncomingMessage) -> str | None:
    for source in (msg.subject, msg.text):
        m = REF_RE.search(source or "")
        if m:
            return m.group(0)
    return None


def referenced_message_ids(msg: IncomingMessage) -> list[str]:
    """Message-IDs this email points at: threading headers, plus any quoted in a bounce body."""
    ids = msg.thread_ids
    if not ids:
        ids = MSGID_RE.findall(msg.text)
    return ids
