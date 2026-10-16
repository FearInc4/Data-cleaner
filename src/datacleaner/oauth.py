"""Sign in with Google / Microsoft, and connect their mailboxes.

OpenID Connect authorization-code flow with every protection the providers support:

- ``state`` bound to the browser session (stops login CSRF / code injection)
- PKCE S256 (stops intercepted codes being redeemed)
- ``nonce`` checked inside the ID token (stops token replay)
- ID token signature verified against the provider's published keys, plus
  ``iss``, ``aud``, ``exp`` and ``iat``
- People are identified by the provider's stable subject id, never by email.

Each install uses its own OAuth client (see README → "Sign in with Google /
Microsoft"), so no third party ever sits between the person and their mailbox.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
import jwt

log = logging.getLogger(__name__)

STATE_TTL_SECONDS = 600
MS_PERSONAL_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad"


class OAuthError(Exception):
    """Something went wrong in the flow; the message is safe to show to the person."""


class ReauthRequired(OAuthError):
    """The refresh token stopped working (revoked, expired, password changed)."""


@dataclass(frozen=True)
class Provider:
    key: str
    name: str
    authorize_url: str
    token_url: str
    jwks_url: str
    login_scopes: tuple[str, ...]
    mail_scopes: tuple[str, ...]
    revoke_url: str | None = None
    extra_auth_params: dict[str, str] = field(default_factory=dict)
    manage_url: str = ""

    def check_issuer(self, claims: dict[str, Any]) -> None:
        iss = claims.get("iss")
        if self.key == "google":
            ok = iss in ("https://accounts.google.com", "accounts.google.com")
        else:
            tid = claims.get("tid")
            ok = bool(tid) and iss == f"https://login.microsoftonline.com/{tid}/v2.0"
        if not ok:
            raise OAuthError("The sign-in response came from an unexpected issuer.")

    def subject(self, claims: dict[str, Any]) -> str:
        if self.key == "microsoft" and claims.get("oid") and claims.get("tid"):
            return f"{claims['tid']}:{claims['oid']}"
        sub = claims.get("sub")
        if not sub:
            raise OAuthError("The sign-in response had no account id.")
        return str(sub)

    def email(self, claims: dict[str, Any]) -> str | None:
        if self.key == "google":
            # Only trust Google's email if Google says it's verified.
            return claims.get("email") if claims.get("email_verified") else None
        return claims.get("email") or claims.get("preferred_username")


GOOGLE = Provider(
    key="google",
    name="Google",
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    token_url="https://oauth2.googleapis.com/token",
    jwks_url="https://www.googleapis.com/oauth2/v3/certs",
    login_scopes=("openid", "email", "profile"),
    mail_scopes=("https://www.googleapis.com/auth/gmail.send", "https://www.googleapis.com/auth/gmail.readonly"),
    revoke_url="https://oauth2.googleapis.com/revoke",
    manage_url="https://myaccount.google.com/connections",
)

MICROSOFT = Provider(
    key="microsoft",
    name="Microsoft",
    authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
    jwks_url="https://login.microsoftonline.com/common/discovery/v2.0/keys",
    login_scopes=("openid", "email", "profile", "offline_access", "User.Read"),
    mail_scopes=("Mail.Send", "Mail.Read"),
    manage_url="https://account.live.com/consent/Manage",
)

PROVIDERS = {p.key: p for p in (GOOGLE, MICROSOFT)}


def get_provider(key: str) -> Provider:
    try:
        return PROVIDERS[key]
    except KeyError:
        raise OAuthError("Unknown sign-in provider.") from None


# --- HTTP client (swappable for tests) -----------------------------------------

_http: httpx.Client | None = None


def http() -> httpx.Client:
    global _http
    if _http is None:
        _http = httpx.Client(timeout=20, headers={"User-Agent": "DataCleaner"})
    return _http


def set_http(client: httpx.Client | None) -> None:
    global _http, _jwks_cache
    _http = client
    _jwks_cache = {}


# --- client credentials -------------------------------------------------------------

@dataclass(frozen=True)
class ClientCreds:
    client_id: str
    client_secret: str


def credentials(provider: Provider, settings, config) -> ClientCreds | None:
    """Environment variables win over values saved on the Settings page."""
    cid = getattr(config, f"{provider.key}_client_id", None) or settings.get(f"{provider.key}_client_id")
    secret = getattr(config, f"{provider.key}_client_secret", None) or settings.get(f"{provider.key}_client_secret")
    if cid and secret:
        return ClientCreds(cid.strip(), secret.strip())
    return None


def redirect_allowed(base_url: str) -> bool:
    """Google and Microsoft accept redirect URIs on https://, or plain http:// only for localhost."""
    url = urlparse(base_url)
    return url.scheme == "https" or (url.scheme == "http" and url.hostname in ("localhost", "127.0.0.1", "::1"))


def redirect_uri(base_url: str, provider: Provider) -> str:
    return f"{base_url.rstrip('/')}/auth/{provider.key}/callback"


# --- the flow ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def begin(store: dict, provider: Provider, creds: ClientCreds, base_url: str, *, purpose: str,
          want_mail: bool, login_hint: str | None = None) -> str:
    """Build the provider URL and remember the per-attempt secrets in the (signed) session."""
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    scopes = list(provider.login_scopes) + (list(provider.mail_scopes) if want_mail else [])
    params = {
        "client_id": creds.client_id,
        "redirect_uri": redirect_uri(base_url, provider),
        "response_type": "code",
        "scope": " ".join(scopes),
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if provider.key == "google":
        params["include_granted_scopes"] = "true"
        if want_mail:
            # Ask for a refresh token, and re-show consent so one is always returned.
            params.update(access_type="offline", prompt="consent")
        else:
            params["prompt"] = "select_account"
    else:
        params.update(response_mode="query", prompt="select_account")
    if login_hint:
        params["login_hint"] = login_hint
    store["oauth"] = {
        "state": state, "nonce": nonce, "verifier": verifier, "provider": provider.key,
        "purpose": purpose, "want_mail": want_mail, "ts": int(time.time()),
    }
    return f"{provider.authorize_url}?{urlencode(params)}"


@dataclass
class Result:
    provider: Provider
    purpose: str
    subject: str
    email: str | None
    name: str | None
    access_token: str
    refresh_token: str | None
    expires_at: datetime
    scopes: set[str]
    want_mail: bool

    @property
    def mail_granted(self) -> bool:
        granted = {s.lower() for s in self.scopes}
        return all(s.lower() in granted for s in self.provider.mail_scopes)


def complete(store: dict, provider: Provider, creds: ClientCreds, base_url: str, params: dict[str, str],
             *, now: datetime) -> Result:
    pending = store.pop("oauth", None)
    if not pending or pending.get("provider") != provider.key:
        raise OAuthError("This sign-in link has expired. Please start again.")
    if not secrets.compare_digest(str(params.get("state", "")), str(pending["state"])):
        raise OAuthError("The sign-in response didn't match this browser. Please start again.")
    if time.time() - pending["ts"] > STATE_TTL_SECONDS:
        raise OAuthError("The sign-in took too long. Please start again.")
    if params.get("error"):
        if params["error"] in ("access_denied", "consent_required"):
            raise OAuthError("Permission wasn't granted, so nothing was connected.")
        raise OAuthError(f"{provider.name} returned an error: {params.get('error_description') or params['error']}"[:300])
    code = params.get("code")
    if not code:
        raise OAuthError("The sign-in response was missing its code.")

    resp = http().post(provider.token_url, data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(base_url, provider),
        "client_id": creds.client_id, "client_secret": creds.client_secret, "code_verifier": pending["verifier"],
    }, headers={"Accept": "application/json"})
    data = _json(resp)
    if resp.status_code != 200 or "access_token" not in data:
        raise OAuthError(f"{provider.name} refused the sign-in: {data.get('error_description') or data.get('error') or resp.status_code}"[:300])
    if "id_token" not in data:
        raise OAuthError(f"{provider.name} didn't return an ID token.")
    claims = verify_id_token(provider, creds, data["id_token"], nonce=pending["nonce"])
    scope_str = data.get("scope") or ""
    return Result(
        provider=provider, purpose=pending["purpose"], subject=provider.subject(claims), email=provider.email(claims),
        name=claims.get("name"), access_token=data["access_token"], refresh_token=data.get("refresh_token"),
        expires_at=now + timedelta(seconds=int(data.get("expires_in", 3600))),
        scopes=set(scope_str.split()), want_mail=bool(pending.get("want_mail")),
    )


def _json(resp: httpx.Response) -> dict[str, Any]:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


_jwks_cache: dict[str, tuple[float, dict]] = {}


def _jwks(provider: Provider, force: bool = False) -> dict:
    cached = _jwks_cache.get(provider.key)
    if cached and not force and time.time() - cached[0] < 3600:
        return cached[1]
    resp = http().get(provider.jwks_url)
    resp.raise_for_status()
    data = resp.json()
    _jwks_cache[provider.key] = (time.time(), data)
    return data


def _signing_key(provider: Provider, token: str):
    kid = jwt.get_unverified_header(token).get("kid")
    for force in (False, True):  # refresh once if keys rotated
        for jwk in _jwks(provider, force=force).get("keys", []):
            if jwk.get("kid") == kid:
                return jwt.PyJWK(jwk).key
    raise OAuthError("Couldn't verify the sign-in token (unknown signing key).")


def verify_id_token(provider: Provider, creds: ClientCreds, token: str, *, nonce: str) -> dict[str, Any]:
    try:
        key = _signing_key(provider, token)
        claims = jwt.decode(
            token, key=key, algorithms=["RS256"], audience=creds.client_id,
            options={"require": ["exp", "iat", "aud", "iss", "sub"]}, leeway=60,
        )
    except jwt.PyJWTError as exc:
        raise OAuthError(f"Couldn't verify the sign-in token: {exc}") from exc
    provider.check_issuer(claims)
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise OAuthError("The sign-in token was replayed or tampered with.")
    return claims


# --- tokens for connected mailboxes -------------------------------------------------------

def refresh(provider: Provider, creds: ClientCreds, refresh_token: str, *, now: datetime) -> tuple[str, str | None, datetime]:
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token,
            "client_id": creds.client_id, "client_secret": creds.client_secret}
    if provider.key == "microsoft":
        data["scope"] = " ".join(("offline_access",) + provider.mail_scopes)
    resp = http().post(provider.token_url, data=data, headers={"Accept": "application/json"})
    body = _json(resp)
    if resp.status_code in (400, 401) and body.get("error") in ("invalid_grant", "unauthorized_client", "invalid_client", "interaction_required"):
        raise ReauthRequired(f"{provider.name} needs you to reconnect ({body.get('error')}).")
    if resp.status_code != 200 or "access_token" not in body:
        raise OAuthError(f"Token refresh failed: {body.get('error') or resp.status_code}")
    return body["access_token"], body.get("refresh_token"), now + timedelta(seconds=int(body.get("expires_in", 3600)))


def revoke(provider: Provider, token: str) -> bool:
    """Best effort. Microsoft has no revocation endpoint for personal accounts; we point people to their account page."""
    if not provider.revoke_url:
        return False
    try:
        return http().post(provider.revoke_url, data={"token": token}).status_code == 200
    except httpx.HTTPError:
        return False
