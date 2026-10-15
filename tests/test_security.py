"""Regression tests for the security audit fixes."""

import logging
import time

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from datacleaner import logredact, net
from datacleaner.config import Config
from datacleaner.db import session_scope
from datacleaner.mail.aliases import make_alias, parse_alias
from datacleaner.models import Broker, MailingSender, OutboxMessage, Profile, User
from datacleaner.spam.unsubscribe import _parse_mailto
from datacleaner.web.app import create_app
from datacleaner.web.deps import safe_url

from .test_web import add_profile, csrf, login


@pytest.fixture()
def client(tmp_path):
    from datacleaner.web.routes import auth

    auth._failures.clear()
    with TestClient(create_app(Config(data_dir=tmp_path, scheduler_enabled=False, allowed_hosts=["testserver"]))) as c:
        yield c


# --- SSRF -----------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://127.0.0.1/x", "https://10.1.2.3/", "https://192.168.1.1/admin", "https://169.254.169.254/latest/meta-data/",
    "https://[::1]/", "https://[::ffff:127.0.0.1]/", "https://localhost/", "https://printer.local/", "https://router.lan/",
    "https://intranet/", "http://shop.example/", "https://user:pw@shop.example/", "https://rebind.example/",
    "https://metadata.example/", "file:///etc/passwd", "javascript:alert(1)", "https://0.0.0.0/",
])
def test_unsafe_urls_refused(url):
    assert not net.is_public_url(url)


def test_public_url_allowed():
    assert net.is_public_url("https://www.mylife.com/verify?t=1")


def test_public_client_blocks_redirect_to_private_network():
    def handler(request):
        if request.url.host == "shop.example":
            return httpx.Response(302, headers={"Location": "https://192.168.0.1/admin"})
        return httpx.Response(200)

    with net.public_client(transport=httpx.MockTransport(handler)) as c:
        with pytest.raises(net.UnsafeURL):
            c.get("https://shop.example/unsub")


# --- untrusted content -------------------------------------------------------------

def test_safe_url_filter():
    assert safe_url("javascript:alert(1)") == "#"
    assert safe_url("  JaVaScRiPt:alert(1)") == "#"
    assert safe_url("data:text/html,<script>") == "#"
    assert safe_url("//evil.example") == "#"
    assert safe_url("https://ok.example/x") == "https://ok.example/x"
    assert safe_url("/spam#unsubscribe") == "/spam#unsubscribe"


def test_mailto_cannot_inject_body_or_extra_recipients():
    addr, subject, body = _parse_mailto("mailto:list@news.example?subject=unsubscribe%20123&body=Wire%20money%20to%20...")
    assert (addr, subject, body) == ("list@news.example", "unsubscribe 123", "unsubscribe")
    addr, subject, _ = _parse_mailto("mailto:a@x.example,b@y.example?subject=hi%0d%0aBcc:%20c@z.example")
    assert addr == "" and "\n" not in subject and "\r" not in subject


def test_log_redaction():
    out = logredact.redact("GET /auth/google/callback?state=abc&code=4/0AY HTTP/1.1 jane.doe%40example.com (415) 555-0134 Bearer ya29.x")
    assert "abc" not in out and "4/0AY" not in out and "jane.doe" not in out and "555-0134" not in out and "ya29" not in out
    assert logredact.redact("2026-03-02 12:00:00 id 12345") == "2026-03-02 12:00:00 id 12345"


def test_log_filter_scrubs_exceptions(caplog):
    logger = logging.getLogger("dc-test")
    handler = logging.Handler()
    records = []
    handler.emit = records.append
    handler.addFilter(logredact.RedactingFilter())
    logger.addHandler(handler)
    try:
        raise ValueError("lookup failed for jane.doe@example.com")
    except ValueError:
        logger.exception("provider error for %s", "jane.doe@example.com")
    logger.removeHandler(handler)
    assert "jane.doe" not in records[0].getMessage()


def test_access_log_lines_still_format():
    from uvicorn.logging import AccessFormatter

    record = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
                               ("172.18.0.1:5000", "GET", "/auth/google/callback?code=4/0AY&state=abc", "1.1", 303), None)
    assert logredact.RedactingFilter().filter(record)
    line = AccessFormatter('%(client_addr)s - "%(request_line)s" %(status_code)s', use_colors=False).format(record)
    assert "/auth/google/callback?code=[redacted]&state=[redacted]" in line and "4/0AY" not in line and "303" in line


def test_aliases_round_trip_and_limits():
    a = make_alias("jane.doe@gmail.com", "spokeo", 3)
    assert a == "jane.doe+dc-spokeo-3@gmail.com" and parse_alias(a) == ("spokeo", 3)
    assert make_alias("jane+old@gmail.com", "x", 1) == "jane+dc-x-1@gmail.com"
    assert make_alias("me@yahoo.com", "spokeo", 1) is None  # Yahoo doesn't do plus-addressing
    long = make_alias("a" * 40 + "@gmail.com", "truepeoplesearch-net-very-long-slug", 12)
    assert len(long.split("@")[0]) <= 64 and parse_alias(long)[1] == 12
    c = make_alias(None, "spokeo", 2, mode="catchall", catchall_domain="mine.example")
    assert c == "dc-spokeo-2@mine.example" and parse_alias(c, catchall_domain="mine.example") == ("spokeo", 2)
    assert parse_alias("dc-spokeo-2@someone-else.example") is None
    assert make_alias("jane@gmail.com", "spokeo", 1, mode="off") is None


# --- web hardening -----------------------------------------------------------------

def test_unknown_host_rejected(client):
    r = client.get("/setup", headers={"Host": "attacker.example"})
    assert r.status_code == 400 and "Unknown host" in r.text
    assert client.get("/healthz", headers={"Host": "localhost:8080"}).status_code == 200


def test_security_headers_and_no_store(client):
    r = client.get("/setup")
    h = r.headers
    assert "base-uri 'none'" in h["content-security-policy"] and "object-src 'none'" in h["content-security-policy"]
    assert h["cache-control"] == "no-store" and h["cross-origin-opener-policy"] == "same-origin"
    assert "camera=()" in h["permissions-policy"]
    assert "no-store" not in client.get("/static/style.css").headers.get("cache-control", "")


def test_setup_token_is_one_time(client, tmp_path):
    login(client)
    assert not (tmp_path / "setup-token").exists()
    assert client.get("/setup", follow_redirects=False).headers["location"] == "/login"


def test_sign_out_everywhere_kills_other_sessions(client, tmp_path):
    login(client)
    other = TestClient(client.app)
    other.cookies.update(client.cookies)  # a second browser with the same session cookie
    assert other.get("/", follow_redirects=False).status_code == 200
    client.post("/account/signout-all", data={"csrf": csrf(client, "/account")})
    assert other.get("/", follow_redirects=False).headers["location"] == "/login"


def test_session_expiry(client, monkeypatch):
    login(client)
    assert client.get("/", follow_redirects=False).status_code == 200
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 25 * 3600)  # idle for a day+
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"


def test_password_change_signs_out_others(client):
    login(client)
    other = TestClient(client.app)
    other.cookies.update(client.cookies)
    r = client.post("/account/password", data={"csrf": csrf(client, "/account"), "current": "correct horse battery",
                                               "new": "a brand new passphrase", "new2": "a brand new passphrase"})
    assert r.status_code == 200 and client.get("/", follow_redirects=False).status_code == 200
    assert other.get("/", follow_redirects=False).headers["location"] == "/login"


def test_theme_cookie_rendered_server_side(client):
    client.cookies.set("dc_theme", "dark")
    assert '<html lang="en" data-theme="dark">' in client.get("/setup").text
    client.cookies.set("dc_theme", '"><script>alert(1)</script>')
    assert "<script>alert" not in client.get("/setup").text


def test_erase_everything(client, tmp_path):
    login(client)
    add_profile(client)
    r = client.post("/account/erase", data={"csrf": csrf(client, "/account"), "confirm": "nope"}, follow_redirects=True)
    assert "Type ERASE" in r.text
    r = client.post("/account/erase", data={"csrf": csrf(client, "/account"), "confirm": "ERASE"}, follow_redirects=False)
    assert r.headers["location"] == "/setup"
    with session_scope() as s:
        assert s.scalars(select(User)).all() == [] and s.scalars(select(Profile)).all() == []
        assert s.scalars(select(Broker)).first() is not None  # public catalog is restored
    assert (tmp_path / "setup-token").exists()
    # The person who erased can set up again straight away.
    assert 'name="password2"' in client.get("/setup").text


def test_private_settings_encrypted_at_rest(client, tmp_path):
    import sqlite3

    login(client)
    client.post("/settings", data={"csrf": csrf(client, "/settings"), "from_address": "secret.person@example.com",
                                   "smtp_username": "secret.person@example.com", "alias_mode": "plus"})
    con = sqlite3.connect(tmp_path / "datacleaner.db")
    dump = "\n".join(con.iterdump())
    con.close()
    assert "secret.person" not in dump


def test_unsubscribe_body_is_ours(session, now):
    from datacleaner.spam.unsubscribe import UnsubInfo, record, unsubscribe

    record(session, [UnsubInfo("x@news.example", "N", "s", now, None, "mailto:x@news.example?subject=stop&body=PHISHING", None)])
    sender = session.scalars(select(MailingSender)).one()
    unsubscribe(session, sender, now=now)
    assert session.scalars(select(OutboxMessage)).one().body == "unsubscribe"


def test_blank_secret_settings_round_trip(session):
    from datacleaner.models import Setting
    from datacleaner.settings import Settings

    s = Settings(session)
    s.set("smtp_password", "")
    s.set("from_address", "")
    assert s.get("smtp_password") == "" and s.get("from_address") == ""
    # Rows written by earlier versions: flagged secret, stored as a plain "".
    session.merge(Setting(key="imap_password", value="", secret=True))
    assert s.get("imap_password") == ""


def test_saving_blank_settings_keeps_the_app_working(client):
    login(client)
    blank = {k: "" for k in ("smtp_host", "smtp_username", "smtp_password", "from_address", "from_name",
                             "imap_host", "imap_username", "imap_password", "notify_email", "alias_domain")}
    r = client.post("/settings", data={"csrf": csrf(client, "/settings"), **blank}, follow_redirects=True)
    assert r.status_code == 200 and "Settings saved" in r.text
    assert client.get("/settings").status_code == 200 and client.get("/").status_code == 200


def test_compose_uses_a_named_volume():
    # A bind-mounted ./data is created root-owned on Linux, and the non-root container can't write it.
    import pathlib

    import yaml

    compose = yaml.safe_load((pathlib.Path(__file__).parents[1] / "docker-compose.yml").read_text())
    assert "datacleaner-data:/data" in compose["services"]["datacleaner"]["volumes"]
    assert "datacleaner-data" in compose["volumes"]
