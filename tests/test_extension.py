"""The browser extension's API: pairing, scoping, and marking forms submitted."""

import io
import re
import zipfile
from datetime import timedelta

from sqlalchemy import select

from datacleaner.db import session_scope
from datacleaner.models import Broker, ExtensionToken, RemovalRequest, RequestStatus, utcnow
from datacleaner.removal import engine

from .conftest import make_profile
from .test_web import client, csrf, login  # noqa: F401  (client is a fixture)


def _pair(c, name="Laptop Chrome"):
    r = c.post("/account/extension/pair", data={"csrf": csrf(c, "/account"), "name": name})
    assert r.status_code == 200
    m = re.search(r"dcx_[A-Za-z0-9_-]{40,}", r.text)
    assert m, "pairing code not shown"
    return m.group(0)


def _requests():
    with session_scope() as s:
        p = make_profile(s)
        form, _ = engine.create_request(s, p, s.scalars(select(Broker).where(Broker.slug == "fastpeoplesearch")).one(), now=utcnow())
        email, _ = engine.create_request(s, p, s.scalars(select(Broker).where(Broker.slug == "mylife")).one(), now=utcnow())
        return form.id, email.id


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_pairing_lists_only_form_tasks_without_personal_details(client):
    login(client)
    form_id, email_id = _requests()
    token = _pair(client)
    # Shown once: not on the next page load.
    assert token not in client.get("/account").text
    assert "Laptop Chrome" in client.get("/account").text

    r = client.get("/api/ext/tasks", headers=auth(token))
    assert r.status_code == 200
    tasks = r.json()["tasks"]
    assert [t["id"] for t in tasks] == [form_id]  # the email request is a draft, not a form task
    task = tasks[0]
    assert task["broker"] == "FastPeopleSearch" and task["url"].startswith("https://")
    assert "fastpeoplesearch.com" in task["domains"]
    for pii in ("Jane", "Doe", "Market St", "555", "jane.doe"):
        assert pii not in r.text


def test_fill_returns_values_and_is_logged(client):
    login(client)
    form_id, email_id = _requests()
    token = _pair(client)
    r = client.get(f"/api/ext/tasks/{form_id}/fill", headers=auth(token))
    assert r.status_code == 200
    data = r.json()
    v = data["values"]
    assert v["first_name"] == "Jane" and v["last_name"] == "Doe" and v["city"] == "San Francisco" and v["state"] == "CA"
    assert v["email"].startswith("jane.doe+dc-fastpeoplesearch-")  # the broker's own alias
    assert "dob" not in v  # birth date is only shared when the person opted in
    assert dict(data["patterns"])["email"]
    with session_scope() as s:
        req = s.get(RemovalRequest, form_id)
        assert any("browser extension (Laptop Chrome)" in e.summary for e in req.events)
    # Requests that aren't waiting on a web form can't be read.
    assert client.get(f"/api/ext/tasks/{email_id}/fill", headers=auth(token)).status_code == 404


def test_mark_submitted_starts_followups(client):
    login(client)
    form_id, _ = _requests()
    token = _pair(client)
    # Plain JSON with only the bearer token: no cookie, no CSRF token.
    client.cookies.clear()
    r = client.post(f"/api/ext/tasks/{form_id}/submitted", json={"note": "Confirmation 123"}, headers=auth(token))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == RequestStatus.SENT and r.json()["next_action_at"]
    with session_scope() as s:
        req = s.get(RemovalRequest, form_id)
        assert req.status == RequestStatus.SENT and req.next_action_at is not None
        assert any("Submitted with the browser extension: Confirmation 123" in e.summary for e in req.events)
    assert client.get("/api/ext/tasks", headers=auth(token)).json()["tasks"] == []
    assert client.post(f"/api/ext/tasks/{form_id}/submitted", json={}, headers=auth(token)).status_code == 404


def test_api_needs_a_valid_pairing(client):
    login(client)
    form_id, _ = _requests()
    # Signed in with a cookie, but no pairing code: the API doesn't accept the session.
    assert client.get("/api/ext/tasks").status_code == 401
    assert client.get(f"/api/ext/tasks/{form_id}/fill").status_code == 401
    assert client.post(f"/api/ext/tasks/{form_id}/submitted", json={}).status_code == 401
    assert client.get("/api/ext/tasks", headers=auth("dcx_" + "x" * 43)).status_code == 401
    assert client.get("/api/ext/tasks", headers={"Authorization": "Basic abc"}).status_code == 401


def test_pairing_is_stored_hashed_and_can_be_revoked(client, tmp_path):
    login(client)
    token = _pair(client)
    assert client.get("/api/ext/whoami", headers=auth(token)).json()["user"] == "admin"
    with session_scope() as s:
        row = s.scalars(select(ExtensionToken)).one()
        assert row.token_hash != token and len(row.token_hash) == 64
        tid = row.id
    assert token.encode() not in b"".join(p.read_bytes() for p in tmp_path.glob("datacleaner.db*"))
    client.post(f"/account/extension/{tid}/revoke", data={"csrf": csrf(client, "/account")})
    assert client.get("/api/ext/whoami", headers=auth(token)).status_code == 401


def test_sign_out_everywhere_and_idle_expiry_end_pairings(client):
    login(client)
    token = _pair(client)
    with session_scope() as s:
        s.scalars(select(ExtensionToken)).one().last_used_at = utcnow() - timedelta(days=61)
    assert client.get("/api/ext/whoami", headers=auth(token)).status_code == 401

    token = _pair(client, "Firefox")
    assert client.get("/api/ext/whoami", headers=auth(token)).status_code == 200
    client.post("/account/signout-all", data={"csrf": csrf(client, "/account")})
    assert client.get("/api/ext/whoami", headers=auth(token)).status_code == 401


def test_extension_download(client):
    assert client.get("/account/extension.zip", follow_redirects=False).status_code == 303  # sign in first
    login(client)
    r = client.get("/account/extension.zip")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    for f in ("manifest.json", "popup.html", "popup.js", "fill.js", "icons/icon-128.png"):
        assert f"datacleaner-extension/{f}" in names


def test_csrf_still_applies_outside_the_extension_api(client):
    login(client)
    # Paths under /api/ext/ that aren't extension endpoints get no CSRF exemption.
    assert client.post("/api/ext/../account/signout-all").status_code in (400, 404)
    assert client.post("/account/signout-all").status_code == 400  # no CSRF token


def test_pairing_codes_are_redacted_from_logs():
    from datacleaner.logredact import redact

    assert "abcdefghijklmnopqrstuvwxyz" not in redact("token dcx_abcdefghijklmnopqrstuvwxyz0123 rejected")
