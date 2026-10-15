import time
from datetime import datetime, timedelta

import pytest

from datacleaner import oauth

from .fake_idp import FakeIdP

NOW = datetime(2026, 3, 2, 12, 0)
CREDS = oauth.ClientCreds("client-123", "secret")
BASE = "http://localhost:8080"


@pytest.fixture()
def idp():
    fake = FakeIdP()
    fake.install()
    yield fake
    oauth.set_http(None)


def _roundtrip(idp, provider, *, purpose="login", want_mail=False, tamper=None):
    store = {}
    url = oauth.begin(store, provider, CREDS, BASE, purpose=purpose, want_mail=want_mail)
    cb, _ = idp.authorize(url)
    params = dict(p.split("=", 1) for p in cb.split("?", 1)[1].split("&"))
    if tamper:
        tamper(store, params)
    return oauth.complete(store, provider, CREDS, BASE, params, now=NOW), url, store


def test_authorize_url_has_pkce_state_nonce(idp):
    store = {}
    url = oauth.begin(store, oauth.GOOGLE, CREDS, BASE, purpose="connect", want_mail=True)
    assert "code_challenge_method=S256" in url and "access_type=offline" in url and "prompt=consent" in url
    assert "gmail.send" in url and "gmail.readonly" in url
    assert store["oauth"]["state"] in url and store["oauth"]["verifier"] not in url
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauth%2Fgoogle%2Fcallback" in url


@pytest.mark.parametrize("provider,subject,email", [
    (oauth.GOOGLE, "g-111", "jane.doe@gmail.com"),
    (oauth.MICROSOFT, "9188040d-6c67-4c5b-b112-36a304b66dad:o-222", "jane@outlook.com"),
])
def test_full_flow(idp, provider, subject, email):
    result, _, store = _roundtrip(idp, provider, purpose="connect", want_mail=True)
    assert result.subject == subject and result.email == email and result.refresh_token == "refresh-1"
    assert result.mail_granted and result.purpose == "connect"
    assert "oauth" not in store  # one-shot


def test_state_mismatch_rejected(idp):
    with pytest.raises(oauth.OAuthError, match="didn't match"):
        _roundtrip(idp, oauth.GOOGLE, tamper=lambda store, p: p.update(state="attacker"))


def test_replayed_callback_rejected(idp):
    result, url, store = _roundtrip(idp, oauth.GOOGLE)
    with pytest.raises(oauth.OAuthError, match="expired"):
        oauth.complete(store, oauth.GOOGLE, CREDS, BASE, {"state": "x", "code": "y"}, now=NOW)


def test_stale_state_rejected(idp):
    def age(store, params):
        store["oauth"]["ts"] = int(time.time()) - 3600
    with pytest.raises(oauth.OAuthError, match="too long"):
        _roundtrip(idp, oauth.GOOGLE, tamper=age)


def test_provider_error_and_denied(idp):
    store = {}
    oauth.begin(store, oauth.GOOGLE, CREDS, BASE, purpose="login", want_mail=False)
    state = store["oauth"]["state"]
    with pytest.raises(oauth.OAuthError, match="Permission wasn't granted"):
        oauth.complete(store, oauth.GOOGLE, CREDS, BASE, {"state": state, "error": "access_denied"}, now=NOW)


@pytest.mark.parametrize("override,match", [
    ({"nonce": "wrong"}, "replayed"),
    ({"aud": "someone-else"}, "verify"),
    ({"iss": "https://evil.example"}, "issuer"),
    ({"exp": int(time.time()) - 3600}, "verify"),
])
def test_id_token_validation(idp, override, match):
    idp.token_overrides = override
    with pytest.raises(oauth.OAuthError, match=match):
        _roundtrip(idp, oauth.GOOGLE)


def test_microsoft_issuer_must_match_tenant(idp):
    idp.token_overrides = {"iss": "https://login.microsoftonline.com/other-tenant/v2.0"}
    with pytest.raises(oauth.OAuthError, match="issuer"):
        _roundtrip(idp, oauth.MICROSOFT)


def test_forged_signature_rejected(idp):
    from cryptography.hazmat.primitives.asymmetric import rsa
    import jwt as pyjwt

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    real = idp.id_token

    def forged(provider, nonce, override=None):
        claims = pyjwt.decode(real(provider, nonce, override), options={"verify_signature": False})
        return pyjwt.encode(claims, other, algorithm="RS256", headers={"kid": "test-key-1"})

    idp.id_token = forged
    with pytest.raises(oauth.OAuthError, match="verify"):
        _roundtrip(idp, oauth.GOOGLE)


def test_unverified_google_email_not_trusted(idp):
    idp.users["google"]["email_verified"] = False
    result, _, _ = _roundtrip(idp, oauth.GOOGLE)
    assert result.email is None and result.subject == "g-111"


def test_scopes_not_granted(idp):
    idp.grant_mail = False
    result, _, _ = _roundtrip(idp, oauth.GOOGLE, purpose="connect", want_mail=True)
    assert not result.mail_granted


def test_refresh_and_reauth(idp):
    access, _, exp = oauth.refresh(oauth.GOOGLE, CREDS, "refresh-1", now=NOW)
    assert access == "refreshed" and exp == NOW + timedelta(hours=1)
    idp.refresh_ok = False
    with pytest.raises(oauth.ReauthRequired):
        oauth.refresh(oauth.GOOGLE, CREDS, "refresh-1", now=NOW)


def test_revoke(idp):
    assert oauth.revoke(oauth.GOOGLE, "refresh-1") and idp.revoked == ["refresh-1"]
    assert oauth.revoke(oauth.MICROSOFT, "x") is False  # no endpoint; UI points to account page
