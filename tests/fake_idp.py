"""A fake Google / Microsoft identity provider + Gmail / Graph API for tests.

Signs real RS256 ID tokens with a throwaway key and serves the matching JWKS,
so the code under test does full signature, issuer, audience and nonce checks.
"""

from __future__ import annotations

import base64
import json
import time
from email import message_from_bytes
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from datacleaner import oauth

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KID = "test-key-1"


def jwks() -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
    jwk.update(kid=KID, alg="RS256", use="sig")
    return {"keys": [jwk]}


class FakeIdP:
    def __init__(self, client_id="client-123"):
        self.client_id = client_id
        self.users = {
            "google": {"sub": "g-111", "email": "jane.doe@gmail.com", "email_verified": True, "name": "Jane Doe"},
            "microsoft": {"oid": "o-222", "tid": "9188040d-6c67-4c5b-b112-36a304b66dad", "sub": "pairwise",
                          "preferred_username": "jane@outlook.com", "name": "Jane Doe"},
        }
        self.codes: dict[str, dict] = {}
        self.grant_mail = True
        self.refresh_ok = True
        self.revoked: list[str] = []
        self.sent: list[bytes] = []
        self.inbox: list[bytes] = []
        self.token_overrides: dict = {}
        self.access_tokens = {"good"}
        self.calls: list[str] = []

    # -- helpers for tests --
    def authorize(self, url: str) -> tuple[str, str]:
        """Simulate the person approving consent: returns (callback path+query, provider)."""
        q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        provider = "google" if "google" in url else "microsoft"
        code = f"code-{len(self.codes)}"
        self.codes[code] = {"nonce": q["nonce"], "provider": provider, "verifier": q.get("code_challenge"),
                            "scope": q["scope"], "redirect_uri": q["redirect_uri"]}
        cb = urlparse(q["redirect_uri"]).path
        return f"{cb}?code={code}&state={q['state']}", provider

    def id_token(self, provider: str, nonce: str, override: dict | None = None) -> str:
        now = int(time.time())
        claims = dict(self.users[provider])
        claims.update(aud=self.client_id, iat=now, exp=now + 3600, nonce=nonce)
        if provider == "google":
            claims["iss"] = "https://accounts.google.com"
        else:
            claims["iss"] = f"https://login.microsoftonline.com/{claims['tid']}/v2.0"
        claims.update(override or {})
        return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": KID})

    # -- HTTP --
    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.calls.append(f"{request.method} {request.url.path}")
        if url.endswith("/oauth2/v3/certs") or url.endswith("/discovery/v2.0/keys"):
            return httpx.Response(200, json=jwks())
        if request.url.path.endswith("/token"):
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            if form["grant_type"] == "refresh_token":
                if not self.refresh_ok:
                    return httpx.Response(400, json={"error": "invalid_grant"})
                self.access_tokens.add("refreshed")
                return httpx.Response(200, json={"access_token": "refreshed", "expires_in": 3600})
            info = self.codes.pop(form["code"], None)
            if not info:
                return httpx.Response(400, json={"error": "invalid_grant"})
            scope = info["scope"]
            if not self.grant_mail:
                scope = " ".join(s for s in scope.split() if "mail" not in s.lower())
            body = {"access_token": "good", "expires_in": 3600, "refresh_token": "refresh-1", "scope": scope,
                    "id_token": self.id_token(info["provider"], info["nonce"], self.token_overrides)}
            return httpx.Response(200, json=body)
        if request.url.path.endswith("/revoke"):
            self.revoked.append(parse_qs(request.content.decode())["token"][0])
            return httpx.Response(200)
        auth = request.headers.get("Authorization", "")
        if request.url.host in ("gmail.googleapis.com", "graph.microsoft.com") and auth.removeprefix("Bearer ") not in self.access_tokens:
            return httpx.Response(401)
        if request.url.host == "gmail.googleapis.com":
            return self._gmail(request)
        if request.url.host == "graph.microsoft.com":
            return self._graph(request)
        return httpx.Response(404)

    def _gmail(self, request):
        path = request.url.path
        if path.endswith("/messages/send"):
            raw = json.loads(request.content)["raw"]
            self.sent.append(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
            return httpx.Response(200, json={"id": "s1", "threadId": "t1"})
        if path.endswith("/messages"):
            return httpx.Response(200, json={"messages": [{"id": f"m{i}"} for i in range(len(self.inbox))]})
        mid = path.rsplit("/", 1)[-1]
        raw = self.inbox[int(mid[1:])]
        if request.url.params.get("format") == "metadata":
            msg = message_from_bytes(raw)
            return httpx.Response(200, json={"payload": {"headers": [{"name": k, "value": v} for k, v in msg.items()]}})
        return httpx.Response(200, json={"raw": base64.urlsafe_b64encode(raw).decode(), "sizeEstimate": len(raw),
                                         "internalDate": str(int(time.time() * 1000))})

    def _graph(self, request):
        path = request.url.path
        if path.endswith("/sendMail"):
            self.sent.append(base64.b64decode(request.content))
            return httpx.Response(202)
        if path.endswith("/$value"):
            mid = path.split("/messages/")[1].split("/")[0]
            return httpx.Response(200, content=self.inbox[int(mid[1:])])
        if path.endswith("/messages"):
            items = []
            for i, raw in enumerate(self.inbox):
                msg = message_from_bytes(raw)
                items.append({"id": f"m{i}", "receivedDateTime": "2026-03-05T10:00:00Z",
                              "from": {"emailAddress": {"address": msg["From"].split("<")[-1].rstrip(">")}},
                              "internetMessageHeaders": [{"name": k, "value": v} for k, v in msg.items()]})
            return httpx.Response(200, json={"value": items})
        return httpx.Response(404)

    def install(self) -> httpx.Client:
        client = httpx.Client(transport=httpx.MockTransport(self.handler))
        oauth.set_http(client)
        return client
