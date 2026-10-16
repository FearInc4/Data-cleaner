import re
import sqlite3

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from datacleaner.db import session_scope
from datacleaner.models import OutboxMessage, Profile, RemovalRequest, RequestStatus
from datacleaner.scheduler import TickDeps, tick
from datacleaner.web.app import create_app

from .test_engine import FakeMailer


@pytest.fixture()
def client(tmp_path):
    from datacleaner.config import Config

    from datacleaner.web.routes import auth

    auth._failures.clear()
    app = create_app(Config(data_dir=tmp_path, scheduler_enabled=False, allowed_hosts=["testserver"]))
    with TestClient(app) as c:
        yield c


def csrf(c, url):
    html = c.get(url).text
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    assert m, f"no csrf token on {url}"
    return m.group(1)


def setup_token(c):
    from datacleaner.app_state import get_config

    return (get_config().data_dir / "setup-token").read_text().strip()


def login(c):
    c.get(f"/setup?token={setup_token(c)}")
    tok = csrf(c, "/setup")
    r = c.post("/setup", data={"csrf": tok, "username": "admin", "password": "correct horse battery", "password2": "correct horse battery"},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/welcome"


def add_profile(c, **extra):
    tok = csrf(c, "/profiles/new")
    data = {"csrf": tok, "label": "Me", "relation": "self", "country": "US", "region_US": "CA", "first_name": "Jane",
            "last_name": "Doe", "emails": "jane.doe@example.com", "phones": "415-555-0134", "street": "1 Market St",
            "city": "San Francisco", "postal_code": "94105", "previous_addresses": "9 Old Rd, Oakland, CA, 94601",
            "attest": "on", "monitoring_enabled": "on"}
    data.update(extra)
    return c.post("/profiles/save", data=data, follow_redirects=False)


def test_requires_setup_then_login(client):
    assert client.get("/", follow_redirects=False).headers["location"] == "/setup"
    login(client)
    assert client.get("/").status_code == 200
    tok = csrf(client, "/")
    client.post("/logout", data={"csrf": tok})
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
    tok = csrf(client, "/login")
    bad = client.post("/login", data={"csrf": tok, "username": "admin", "password": "nope"}, follow_redirects=True)
    assert "Wrong username or password" in bad.text
    tok = csrf(client, "/login")
    ok = client.post("/login", data={"csrf": tok, "username": "admin", "password": "correct horse battery"}, follow_redirects=False)
    assert ok.headers["location"] == "/"


def test_csrf_required(client):
    login(client)
    r = client.post("/profiles/save", data={"label": "x", "first_name": "a", "last_name": "b", "attest": "on"})
    assert r.status_code == 400


def test_security_headers(client):
    r = client.get("/setup")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


def test_profile_requires_attestation(client):
    login(client)
    r = add_profile(client, attest="")
    assert r.headers["location"] == "/profiles/new"
    with session_scope() as s:
        assert s.scalars(select(Profile)).all() == []


def test_full_flow(client, tmp_path):
    login(client)
    r = add_profile(client)
    assert r.status_code == 303 and r.headers["location"].startswith("/requests/new")
    with session_scope() as s:
        p = s.scalars(select(Profile)).one()
        assert p.region == "CA" and p.addresses[1]["city"] == "Oakland"
        pid = p.id

    page = client.get(f"/requests/new?profile_id={pid}")
    assert "California Consumer Privacy Act" in page.text
    broker_ids = re.findall(r'name="broker_id" value="(\d+)" class="p1 p12 emailable"', page.text)
    assert broker_ids, "expected crucial brokers with email"
    tok = csrf(client, f"/requests/new?profile_id={pid}")
    r = client.post("/requests/create", data={"csrf": tok, "profile_id": pid, "broker_id": broker_ids}, follow_redirects=True)
    assert "Created" in r.text and "draft" in r.text

    with session_scope() as s:
        req = s.scalars(select(RemovalRequest).where(RemovalRequest.method == "email")).first()
        rid = req.id
    detail = client.get(f"/requests/{rid}")
    assert "Review the email" in detail.text and "§ 1798.105" in detail.text

    # Sending needs mail settings.
    tok = csrf(client, "/requests")
    r = client.post("/requests/approve-all", data={"csrf": tok, "profile_id": pid}, follow_redirects=False)
    assert r.headers["location"] == "/settings#email"
    tok = csrf(client, "/settings")
    client.post("/settings", data={"csrf": tok, "smtp_host": "smtp.example.com", "smtp_port": "587", "smtp_security": "starttls",
                                   "smtp_username": "me", "smtp_password": "app-pass-123", "from_address": "privacy@me.example",
                                   "from_name": "Jane Doe", "rate_limit_per_hour": "50", "auto_click_verification": "on"})
    settings_page = client.get("/settings").text
    assert "app-pass-123" not in settings_page and "••••••••" in settings_page
    tok = csrf(client, "/requests")
    client.post("/requests/approve-all", data={"csrf": tok, "profile_id": pid})
    with session_scope() as s:
        queued = s.scalars(select(OutboxMessage)).all()
        assert len(queued) == len(broker_ids)

    mailer = FakeMailer()
    report = tick(deps=TickDeps(mailer=mailer, run_scans=False))
    assert not report.errors, report.errors
    assert len(mailer.sent) == len(broker_ids)
    with session_scope() as s:
        assert all(r.status == RequestStatus.SENT for r in s.scalars(select(RemovalRequest).where(RemovalRequest.method == "email")))

    # Every page renders.
    for url in ["/", "/requests", "/requests?status=needs_you", f"/requests/{rid}", "/scan", "/breaches", "/spam", "/brokers",
                "/brokers?category=people_search&method=email", "/brokers/spokeo", "/brokers/import", "/brokers/new",
                "/profiles", f"/profiles/{pid}", "/settings"]:
        assert client.get(url).status_code == 200, url

    vcf = client.get("/spam/blocklist.vcf")
    assert vcf.status_code == 200 and vcf.headers["content-type"].startswith("text/vcard")

    # Mark a form request submitted.
    with session_scope() as s:
        form_req = s.scalars(select(RemovalRequest).where(RemovalRequest.method == "form")).first()
        fid = form_req.id if form_req else None
    if fid:
        tok = csrf(client, f"/requests/{fid}")
        client.post(f"/requests/{fid}/action", data={"csrf": tok, "action": "submitted", "note": "conf #123"})
        with session_scope() as s:
            assert s.get(RemovalRequest, fid).status == RequestStatus.SENT

    # PII and secrets are encrypted at rest.
    con = sqlite3.connect(tmp_path / "datacleaner.db")
    dump = "\n".join(con.iterdump())
    con.close()
    for secret in ("jane.doe@example.com", "Market St", "app-pass-123", "Oakland"):
        assert secret not in dump, secret


def test_agent_profile_needs_authorization(client):
    login(client)
    add_profile(client, relation="agent", label="Mom")
    with session_scope() as s:
        pid = s.scalars(select(Profile)).one().id
    letter = client.get(f"/profiles/{pid}/authorization.txt")
    assert "authorize admin" in letter.text
    page = client.get(f"/requests/new?profile_id={pid}")
    ids = re.findall(r'name="broker_id" value="(\d+)"', page.text)[:2]
    tok = csrf(client, f"/requests/new?profile_id={pid}")
    r = client.post("/requests/create", data={"csrf": tok, "profile_id": pid, "broker_id": ids}, follow_redirects=False)
    assert r.headers["location"] == f"/profiles/{pid}"
    with session_scope() as s:
        assert s.scalars(select(RemovalRequest)).all() == []


def test_switch_rejects_offsite_redirect(client):
    login(client)
    add_profile(client)
    with session_scope() as s:
        pid = s.scalars(select(Profile)).one().id
    assert client.get(f"/switch?profile_id={pid}&next=//evil.example", follow_redirects=False).headers["location"] == "/"
    assert client.get(f"/switch?profile_id={pid}&next=/scan", follow_redirects=False).headers["location"] == "/scan"


def test_login_lockout(client):
    login(client)
    tok = csrf(client, "/")
    client.post("/logout", data={"csrf": tok})
    for _ in range(5):
        tok = csrf(client, "/login")
        client.post("/login", data={"csrf": tok, "username": "admin", "password": "wrong"})
    tok = csrf(client, "/login")
    r = client.post("/login", data={"csrf": tok, "username": "admin", "password": "correct horse battery"}, follow_redirects=True)
    assert "Too many failed attempts" in r.text


def test_a_failed_save_is_never_reported_as_success(tmp_path, monkeypatch):
    # The database commit must happen before the response goes out. Otherwise the
    # browser is told "saved" (and the extension "recorded") first, and a failed
    # commit is silently lost.
    from sqlalchemy.orm import Session

    from datacleaner.config import Config
    from datacleaner.web.routes import auth

    auth._failures.clear()
    app = create_app(Config(data_dir=tmp_path, scheduler_enabled=False, allowed_hosts=["testserver"]))
    with TestClient(app, raise_server_exceptions=False) as c:
        login(c)
        tok = csrf(c, "/settings")

        def disk_full(self):
            raise sqlite3.OperationalError("database or disk is full")

        monkeypatch.setattr(Session, "commit", disk_full)
        r = c.post("/settings", data={"csrf": tok, "from_name": "Jane"}, follow_redirects=False)
        assert r.status_code == 500


def test_redirect_uris_google_and_microsoft_accept():
    from datacleaner import oauth

    assert oauth.redirect_allowed("https://privacy.example.com")
    assert oauth.redirect_allowed("http://localhost:25326")
    assert oauth.redirect_allowed("http://127.0.0.1:25326")
    assert not oauth.redirect_allowed("http://10.0.1.4:25326")
    assert not oauth.redirect_allowed("http://plex-server.local:25326")


def test_sign_in_app_steps_link_every_google_page(client):
    login(client)
    page = client.get("/settings").text
    for url in ("console.cloud.google.com/projectcreate", "apis/library/gmail.googleapis.com", "/auth/overview",
                "/auth/audience", "/auth/scopes", "/auth/clients/create"):
        assert url in page
    assert "Publish app" in page and "Access blocked" in page
    assert 'data-copy="http://testserver/auth/google/callback"' in page
    # http://testserver isn't https or localhost, so Google would refuse its redirect URI: say so, and how to get round it.
    assert "only accept sign-in addresses" in page and "ssh -L 25326:localhost:25326" in page

    local = client.get("/settings", headers={"host": "localhost:25326"}).text
    assert "only accept sign-in addresses" not in local
    assert 'data-copy="http://localhost:25326/auth/google/callback"' in local


def test_setup_page_shows_the_sign_in_app_steps(client):
    client.get(f"/setup?token={setup_token(client)}")
    page = client.get("/setup", headers={"host": "localhost:25326"}).text
    assert "/auth/audience" in page and "Steps for Microsoft" in page
    assert 'data-copy="http://localhost:25326/auth/google/callback"' in page
    assert 'data-copy="http://localhost:25326/auth/microsoft/callback"' in page
