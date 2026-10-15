"""End-to-end: sign in with Google/Microsoft, send via Gmail/Graph, read replies, aliases."""

from email.message import EmailMessage

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from datacleaner import oauth
from datacleaner.config import Config
from datacleaner.db import session_scope
from datacleaner.models import Broker, MailAccount, OAuthIdentity, OutboxMessage, RemovalRequest, RequestStatus, User, utcnow
from datacleaner.removal import engine
from datacleaner.scheduler import TickDeps, tick
from datacleaner.web.app import create_app

from .conftest import make_profile
from .fake_idp import FakeIdP
from .test_web import csrf, setup_token


@pytest.fixture()
def idp():
    fake = FakeIdP()
    fake.install()
    yield fake
    oauth.set_http(None)


@pytest.fixture()
def client(tmp_path, idp):
    from datacleaner.web.routes import auth

    auth._failures.clear()
    cfg = Config(data_dir=tmp_path, scheduler_enabled=False, allowed_hosts=["testserver"],
                 google_client_id="client-123", google_client_secret="s",
                 microsoft_client_id="client-123", microsoft_client_secret="s")
    with TestClient(create_app(cfg)) as c:
        yield c


def oauth_dance(c, idp, provider, purpose):
    r = c.get(f"/auth/{provider}/start?purpose={purpose}", follow_redirects=False)
    assert r.status_code == 303, r.text
    callback, _ = idp.authorize(r.headers["location"])
    return c.get(callback, follow_redirects=False)


def setup_with(c, idp, provider="google"):
    c.get(f"/setup?token={setup_token(c)}")
    return oauth_dance(c, idp, provider, "setup")


def test_setup_with_google_connects_mailbox(client, idp):
    page = client.get(f"/setup?token={setup_token(client)}", follow_redirects=True)
    assert "Continue with Google" in page.text and "Continue with Microsoft" in page.text
    r = oauth_dance(client, idp, "google", "setup")
    assert r.headers["location"] == "/welcome"
    with session_scope() as s:
        user = s.scalars(select(User)).one()
        assert user.username == "jane.doe@gmail.com" and not user.has_password
        ident = s.scalars(select(OAuthIdentity)).one()
        assert (ident.provider, ident.subject) == ("google", "g-111")
        acc = s.scalars(select(MailAccount)).one()
        assert acc.email == "jane.doe@gmail.com" and acc.refresh_token == "refresh-1" and acc.status == "ok"
    welcome = client.get("/welcome")
    assert "Tell us who you are" in welcome.text and "Signed in and connected jane.doe@gmail.com" in welcome.text
    # Setup can't be repeated.
    assert client.get("/auth/google/start?purpose=setup", follow_redirects=False).headers["location"] == "/login"


def test_setup_requires_token(client, idp):
    r = client.get("/auth/google/start?purpose=setup", follow_redirects=False)
    assert r.headers["location"] == "/setup"
    page = client.get("/setup?token=wrong", follow_redirects=True)
    assert "That setup token isn" in page.text
    assert 'name="csrf"' not in page.text  # only the token form is offered
    r = client.post("/setup", data={"username": "x", "password": "p" * 14, "password2": "p" * 14}, follow_redirects=False)
    assert r.status_code in (303, 400)
    with session_scope() as s:
        assert s.scalars(select(User)).all() == []


def test_login_with_linked_account_only(client, idp):
    setup_with(client, idp)
    client.post("/logout", data={"csrf": csrf(client, "/")})
    assert "Sign in with Google" in client.get("/login").text
    r = oauth_dance(client, idp, "google", "login")
    assert r.headers["location"] == "/"
    assert client.get("/", follow_redirects=False).status_code == 200
    # A different Google account (same email!) can't sign in: identity is the subject, not the email.
    client.post("/logout", data={"csrf": csrf(client, "/")})
    idp.users["google"]["sub"] = "g-attacker"
    r = oauth_dance(client, idp, "google", "login")
    assert r.headers["location"] == "/login"
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"


def test_microsoft_setup_and_graph_mail(client, idp, now=None):
    setup_with(client, idp, "microsoft")
    with session_scope() as s:
        acc = s.scalars(select(MailAccount)).one()
        assert acc.provider == "microsoft" and acc.email == "jane@outlook.com"
        p = make_profile(s, emails=["jane@outlook.com"])
        broker = s.scalars(select(Broker).where(Broker.slug == "mylife")).one()
        req, _ = engine.create_request(s, p, broker, now=utcnow())
        engine.approve(s, req, now=utcnow())
        rid = req.id
    report = tick(deps=TickDeps(run_scans=False))
    assert not report.errors, report.errors
    assert len(idp.sent) == 1
    sent = idp.sent[0].decode()
    assert "From: " in sent and "jane@outlook.com" in sent
    assert "Reply-To: jane+dc-mylife-1@outlook.com" in sent
    with session_scope() as s:
        assert s.get(RemovalRequest, rid).status == RequestStatus.SENT


def _reply(to, subject, body, sender="privacy@mylife.com", auth=None, extra_headers=None):
    m = EmailMessage()
    m["From"] = sender
    m["To"] = to
    m["Subject"] = subject
    m["Message-ID"] = f"<r{abs(hash((to, subject, body))) % 10**9}@mylife.com>"
    if auth:
        m["Authentication-Results"] = auth
    for k, v in (extra_headers or {}).items():
        m[k] = v
    m.set_content(body)
    return m.as_bytes()


def _gmail_request(client, idp, slug="mylife"):
    setup_with(client, idp, "google")
    with session_scope() as s:
        p = make_profile(s, emails=["jane.doe@gmail.com"])
        broker = s.scalars(select(Broker).where(Broker.slug == slug)).one()
        req, _ = engine.create_request(s, p, broker, now=utcnow())
        engine.approve(s, req, now=utcnow())
        rid, pid = req.id, p.id
    tick(deps=TickDeps(run_scans=False))
    return rid, pid


def test_gmail_send_has_alias_and_threading(client, idp):
    rid, pid = _gmail_request(client, idp)
    raw = idp.sent[0].decode()
    assert f"Reply-To: jane.doe+dc-mylife-{pid}@gmail.com" in raw
    assert "Message-ID: <dc-" in raw
    page = client.get(f"/requests/{rid}")
    assert f"jane.doe+dc-mylife-{pid}@gmail.com" in page.text


def test_authenticated_alias_reply_completes(client, idp):
    rid, pid = _gmail_request(client, idp)
    alias = f"jane.doe+dc-mylife-{pid}@gmail.com"
    idp.inbox.append(_reply(alias, "Your privacy request", "Your information has been removed from our site.",
                            auth="mx.google.com; dkim=pass header.i=@mylife.com; spf=pass smtp.mailfrom=mylife.com; dmarc=pass (p=REJECT) header.from=mylife.com"))
    report = tick(deps=TickDeps(run_scans=False))
    assert report.steps["inbox"]["completed"] == 1, report.steps
    with session_scope() as s:
        assert s.get(RemovalRequest, rid).status == RequestStatus.COMPLETED


def test_spoofed_completion_is_not_trusted(client, idp):
    rid, pid = _gmail_request(client, idp)
    alias = f"jane.doe+dc-mylife-{pid}@gmail.com"
    # Spoofed From with a forged Authentication-Results *below* the real one added by Gmail.
    raw = _reply(alias, "Done", "Your information has been removed from our site.",
                 auth="mx.google.com; spf=fail smtp.mailfrom=evil.example; dmarc=fail header.from=mylife.com",
                 extra_headers={"X-Forged": "1"})
    raw = raw.replace(b"X-Forged: 1", b"Authentication-Results: mx.google.com; dkim=pass header.d=mylife.com; dmarc=pass header.from=mylife.com")
    idp.inbox.append(raw)
    report = tick(deps=TickDeps(run_scans=False))
    assert report.steps["inbox"]["unverified"] == 1, report.steps
    with session_scope() as s:
        req = s.get(RemovalRequest, rid)
        assert req.status == RequestStatus.SENT and req.needs_review and req.next_action_at is not None
    assert "needs your review" in client.get(f"/requests/{rid}").text


def test_alias_leak_hint(client, idp):
    rid, pid = _gmail_request(client, idp)
    idp.inbox.append(_reply(f"jane.doe+dc-mylife-{pid}@gmail.com", "Hot deals!!", "Buy now", sender="promo@spammer.example"))
    tick(deps=TickDeps(run_scans=False))
    with session_scope() as s:
        req = s.get(RemovalRequest, rid)
        assert any("may have shared or leaked your address" in e.summary for e in req.events)


def test_expired_token_refreshes_and_revoked_token_pauses(client, idp):
    rid, pid = _gmail_request(client, idp)
    with session_scope() as s:
        acc = s.scalars(select(MailAccount)).one()
        acc.access_expires_at = utcnow()  # force a refresh
        req = s.get(RemovalRequest, rid)
        req.status = RequestStatus.DRAFT
        engine.approve(s, req, now=utcnow())
    tick(deps=TickDeps(run_scans=False))
    assert len(idp.sent) == 2 and "POST /token" in idp.calls
    with session_scope() as s:
        acc = s.scalars(select(MailAccount)).one()
        assert acc.access_token == "refreshed"
        acc.access_expires_at = utcnow()
        req = s.get(RemovalRequest, rid)
        req.status = RequestStatus.DRAFT
        engine.approve(s, req, now=utcnow())
    idp.refresh_ok = False
    tick(deps=TickDeps(run_scans=False))
    with session_scope() as s:
        acc = s.scalars(select(MailAccount)).one()
        assert acc.status == "needs_reconnect"
        assert s.scalars(select(OutboxMessage).where(OutboxMessage.status == "queued")).first() is not None
    assert "needs reconnecting" in client.get("/settings").text


def test_revoked_token_seen_while_reading_mail_is_shown(client, idp):
    _gmail_request(client, idp)  # nothing left in the outbox: the inbox read is the first to notice
    with session_scope() as s:
        s.scalars(select(MailAccount)).one().access_expires_at = utcnow()
    idp.refresh_ok = False
    tick(deps=TickDeps(run_scans=False))
    with session_scope() as s:
        assert s.scalars(select(MailAccount)).one().status == "needs_reconnect"
    assert "needs reconnecting" in client.get("/settings").text


def test_send_all_and_inbox_scan_work_with_a_connected_mailbox(client, idp):
    setup_with(client, idp, "google")
    with session_scope() as s:
        p = make_profile(s, emails=["jane.doe@gmail.com"])
        broker = s.scalars(select(Broker).where(Broker.slug == "mylife")).one()
        req, _ = engine.create_request(s, p, broker, now=utcnow())
        rid, pid = req.id, p.id
    r = client.post("/requests/approve-all", data={"csrf": csrf(client, "/requests"), "profile_id": pid},
                    follow_redirects=False)
    assert r.headers["location"] == f"/requests?profile_id={pid}"
    with session_scope() as s:
        assert s.get(RemovalRequest, rid).status == RequestStatus.QUEUED
    assert "disabled>Scan inbox" not in client.get("/spam").text


def test_disconnect_revokes(client, idp):
    setup_with(client, idp)
    with session_scope() as s:
        aid = s.scalars(select(MailAccount)).one().id
    client.post(f"/account/disconnect/{aid}", data={"csrf": csrf(client, "/settings")})
    assert "refresh-1" in idp.revoked
    with session_scope() as s:
        assert s.scalars(select(MailAccount)).all() == []


def test_cannot_remove_last_sign_in_method(client, idp):
    setup_with(client, idp)
    with session_scope() as s:
        iid = s.scalars(select(OAuthIdentity)).one().id
    r = client.post(f"/account/unlink/{iid}", data={"csrf": csrf(client, "/account")}, follow_redirects=True)
    assert "locked out" in r.text


def test_unsubscribe_scan_via_gmail(client, idp):
    setup_with(client, idp)
    m = EmailMessage()
    m["From"] = "Shop <deals@shop.example>"
    m["Subject"] = "Sale"
    m["List-Unsubscribe"] = "<https://shop.example/u/1>"
    m["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
    m.set_content("x")
    idp.inbox.append(m.as_bytes())
    r = client.post("/spam/unsubscribe/scan", data={"csrf": csrf(client, "/spam"), "days": "30"}, follow_redirects=True)
    assert "Found 1 senders" in r.text and "deals@shop.example" in r.text
