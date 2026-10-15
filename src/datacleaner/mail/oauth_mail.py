"""Send and read mail through a connected Gmail or Microsoft account.

Gmail: Gmail API (`gmail.send` + `gmail.readonly`).
Outlook / Hotmail / Microsoft 365: Microsoft Graph (`Mail.Send` + `Mail.Read`).

Messages are sent as raw MIME so our Message-ID / In-Reply-To / Reply-To
headers survive, which keeps threading and per-broker aliases working.
"""

from __future__ import annotations

import base64
import logging
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from .. import oauth
from ..models import MailAccount, utcnow
from .parse import IncomingMessage, parse_message
from .trust import MICROSOFT

log = logging.getLogger(__name__)

GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me"
GRAPH = "https://graph.microsoft.com/v1.0/me"
MAX_MESSAGE_BYTES = 10 * 1024 * 1024
FIRST_SYNC_DAYS = 30
SEEN_KEEP = 500


class MailAuthError(RuntimeError):
    """The mailbox needs to be reconnected; shown to the person as-is."""


class TokenSource:
    """Hands out a valid access token, refreshing (and persisting) it as needed."""

    def __init__(self, session: Session, account: MailAccount, creds: oauth.ClientCreds | None):
        self.session, self.account, self.creds = session, account, creds
        self.provider = oauth.get_provider(account.provider)

    def token(self, *, force: bool = False) -> str:
        acc = self.account
        now = utcnow()
        if not force and acc.access_token and acc.access_expires_at and acc.access_expires_at > now + timedelta(seconds=60):
            return acc.access_token
        if not acc.refresh_token or not self.creds:
            self._needs_reconnect("No refresh token. Reconnect the mailbox.")
        try:
            access, new_refresh, expires = oauth.refresh(self.provider, self.creds, acc.refresh_token, now=now)
        except oauth.ReauthRequired as exc:
            self._needs_reconnect(str(exc))
        acc.access_token, acc.access_expires_at = access, expires
        if new_refresh:  # Microsoft rotates refresh tokens
            acc.refresh_token = new_refresh
        acc.status, acc.last_error = "ok", None
        self.session.flush()
        return access

    def _needs_reconnect(self, why: str):
        self.account.status = "needs_reconnect"
        self.account.last_error = why[:500]
        self.session.flush()
        raise MailAuthError(why)


def _request(client: httpx.Client, tokens: TokenSource, method: str, url: str, *, headers: dict | None = None,
             **kw) -> httpx.Response:
    base = dict(headers or {})
    for attempt in (0, 1):
        auth = {"Authorization": f"Bearer {tokens.token(force=attempt == 1)}"}
        resp = client.request(method, url, headers={**base, **auth}, **kw)
        if resp.status_code != 401:
            break
    if resp.status_code == 401:
        tokens._needs_reconnect(f"{tokens.provider.name} rejected the access token.")
    if resp.status_code == 403:
        raise MailAuthError(f"{tokens.provider.name} denied access. Reconnect and allow sending and reading mail.")
    resp.raise_for_status()
    return resp


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _remember(account: MailAccount, ids: list[str], newest: datetime | None) -> None:
    cur = dict(account.cursor or {})
    seen = list(cur.get("seen", []))
    seen = (seen + ids)[-SEEN_KEEP:]
    cur["seen"] = seen
    if newest:
        cur["since"] = max(cur.get("since", ""), newest.isoformat())
    account.cursor = cur


# --- Gmail ---------------------------------------------------------------------------------

class GmailMailer:
    def __init__(self, tokens: TokenSource, client: httpx.Client | None = None):
        self.tokens, self.client = tokens, client or oauth.http()

    def send(self, message: EmailMessage) -> None:
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
        _request(self.client, self.tokens, "POST", f"{GMAIL}/messages/send", json={"raw": raw})


class GmailSource:
    def __init__(self, tokens: TokenSource, client: httpx.Client | None = None):
        self.tokens, self.client = tokens, client or oauth.http()

    def _since(self) -> datetime:
        since = (self.tokens.account.cursor or {}).get("since")
        if since:
            return datetime.fromisoformat(since) - timedelta(minutes=10)  # overlap; dedupe by id
        return utcnow() - timedelta(days=FIRST_SYNC_DAYS)

    def _list(self, query: str, limit: int) -> list[str]:
        ids: list[str] = []
        page = None
        while len(ids) < limit:
            params = {"q": query, "maxResults": min(100, limit - len(ids)), "includeSpamTrash": "true"}
            if page:
                params["pageToken"] = page
            data = _request(self.client, self.tokens, "GET", f"{GMAIL}/messages", params=params).json()
            ids += [m["id"] for m in data.get("messages", [])]
            page = data.get("nextPageToken")
            if not page:
                break
        return ids

    def fetch_new(self, session: Session, limit: int = 200) -> list[IncomingMessage]:
        acc = self.tokens.account
        since = self._since()
        seen = set((acc.cursor or {}).get("seen", []))
        # Includes Spam: broker replies often land there.
        ids = [i for i in self._list(f"after:{int(since.replace(tzinfo=UTC).timestamp())} -from:me -in:sent", limit) if i not in seen]
        out: list[IncomingMessage] = []
        newest = None
        for mid in ids:
            data = _request(self.client, self.tokens, "GET", f"{GMAIL}/messages/{mid}", params={"format": "raw"}).json()
            if int(data.get("sizeEstimate", 0)) > MAX_MESSAGE_BYTES:
                continue
            try:
                msg = parse_message(_b64url_decode(data.get("raw", "")), uid=mid)
            except Exception:
                log.exception("Could not parse Gmail message")
            else:
                msg.authserv = "mx.google.com"
                out.append(msg)
            ts = int(data.get("internalDate", 0)) / 1000
            if ts:
                when = datetime.fromtimestamp(ts, UTC).replace(tzinfo=None)
                newest = max(newest, when) if newest else when
        _remember(acc, ids, newest)
        return out

    def fetch_headers(self, days: int, limit: int = 2000) -> list[bytes]:
        since = int((datetime.now(UTC) - timedelta(days=days)).timestamp())
        out = []
        for mid in self._list(f"after:{since} -from:me", limit):
            data = _request(self.client, self.tokens, "GET", f"{GMAIL}/messages/{mid}", params=[
                ("format", "metadata"), ("metadataHeaders", "From"), ("metadataHeaders", "Subject"),
                ("metadataHeaders", "Date"), ("metadataHeaders", "List-Unsubscribe"), ("metadataHeaders", "List-Unsubscribe-Post"),
            ]).json()
            headers = (data.get("payload") or {}).get("headers", [])
            out.append(_headers_to_bytes(headers))
        return out


# --- Microsoft Graph -----------------------------------------------------------------------

class GraphMailer:
    def __init__(self, tokens: TokenSource, client: httpx.Client | None = None):
        self.tokens, self.client = tokens, client or oauth.http()

    def send(self, message: EmailMessage) -> None:
        mime = base64.b64encode(message.as_bytes())
        _request(self.client, self.tokens, "POST", f"{GRAPH}/sendMail", content=mime, headers={"Content-Type": "text/plain"})


class GraphSource:
    def __init__(self, tokens: TokenSource, client: httpx.Client | None = None):
        self.tokens, self.client = tokens, client or oauth.http()

    def _since(self) -> datetime:
        since = (self.tokens.account.cursor or {}).get("since")
        if since:
            return datetime.fromisoformat(since) - timedelta(minutes=10)
        return utcnow() - timedelta(days=FIRST_SYNC_DAYS)

    def _list(self, since: datetime, select: str, limit: int) -> list[dict]:
        url = f"{GRAPH}/messages"
        params: dict | None = {
            "$filter": f"receivedDateTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
            "$orderby": "receivedDateTime asc", "$select": select, "$top": 50,
        }
        items: list[dict] = []
        while url and len(items) < limit:
            data = _request(self.client, self.tokens, "GET", url, params=params).json()
            items += data.get("value", [])
            url, params = data.get("@odata.nextLink"), None
        return items[:limit]

    def fetch_new(self, session: Session, limit: int = 200) -> list[IncomingMessage]:
        acc = self.tokens.account
        own = (acc.email or "").lower()
        seen = set((acc.cursor or {}).get("seen", []))
        items = [m for m in self._list(self._since(), "id,receivedDateTime,from", limit) if m.get("id") not in seen]
        out: list[IncomingMessage] = []
        newest = None
        for m in items:
            sender = (((m.get("from") or {}).get("emailAddress") or {}).get("address") or "").lower()
            received = m.get("receivedDateTime")
            if received:
                when = datetime.fromisoformat(received.replace("Z", "+00:00")).astimezone(UTC).replace(tzinfo=None)
                newest = max(newest, when) if newest else when
            if sender == own:
                continue
            resp = _request(self.client, self.tokens, "GET", f"{GRAPH}/messages/{quote(m['id'], safe='')}/$value")
            if len(resp.content) > MAX_MESSAGE_BYTES:
                continue
            try:
                msg = parse_message(resp.content, uid=m["id"])
            except Exception:
                log.exception("Could not parse Graph message")
            else:
                msg.authserv = MICROSOFT
                out.append(msg)
        _remember(acc, [m["id"] for m in items if m.get("id")], newest)
        return out

    def fetch_headers(self, days: int, limit: int = 2000) -> list[bytes]:
        since = utcnow() - timedelta(days=days)
        out = []
        for m in self._list(since, "id,internetMessageHeaders", limit):
            out.append(_headers_to_bytes(m.get("internetMessageHeaders") or []))
        return out


def _headers_to_bytes(headers: list[dict]) -> bytes:
    lines = []
    for h in headers:
        name, value = str(h.get("name", "")), str(h.get("value", ""))
        if name and "\n" not in name and "\r" not in name:
            lines.append(f"{name}: {value.replace(chr(13), ' ').replace(chr(10), ' ')}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", errors="replace")
