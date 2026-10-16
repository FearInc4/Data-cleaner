"""End to end: the real extension in Chromium, against a live server and a fake broker form.

Skipped unless Playwright and its Chromium are installed (`pip install -e ".[browser]"`,
then `playwright install chromium`). Set DATACLEANER_TEST_CHROMIUM to use another Chromium binary.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import shutil
import socket
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import select

from datacleaner.db import session_scope
from datacleaner.models import Broker, RemovalRequest, RequestStatus, User, utcnow
from datacleaner.removal import engine
from datacleaner.security import hash_password
from datacleaner.web.routes.extension import pair_browser

from .conftest import make_profile

sync_api = pytest.importorskip("playwright.sync_api")
uvicorn = pytest.importorskip("uvicorn")

EXTENSION = Path(__file__).resolve().parents[1] / "src" / "datacleaner" / "extension"

FORM = """<!doctype html><html><head><title>Opt out</title></head><body>
<h1>Remove my information</h1>
<form>
  <label for="fn">First Name *</label><input id="fn" name="fname">
  <input name="lastName" placeholder="Last name">
  <label>Email address <input type="email" name="contact"></label>
  <input type="tel" name="phone_number" aria-label="Phone">
  <input name="town" autocomplete="address-level2">
  <label for="st">State</label>
  <select id="st" name="st"><option value="">Choose…</option><option value="TX">Texas</option><option value="CA">California</option></select>
  <label for="u">Link to your listing</label><input id="u" name="profile_url">
  <label for="z">ZIP</label><input id="z" name="zip" value="00000">
  <input type="hidden" name="csrf" value="keep">
  <input name="secret_city" style="display:none">
  <label><input type="checkbox" name="agree"> I agree</label>
  <button type="submit">Submit</button>
</form></body></html>"""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _extension_id(path: Path) -> str:
    # How Chromium names an unpacked extension: SHA-256 of its absolute path, hex digits mapped to a-p.
    digest = hashlib.sha256(str(path).encode()).hexdigest()[:32]
    return "".join(chr(ord("a") + int(c, 16)) for c in digest)


class _FormHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = FORM.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture()
def live(config, tmp_path):
    """A live Data Cleaner (with one web-form request) and a fake broker opt-out page."""
    from datacleaner.web.app import create_app

    form_port, app_port = _free_port(), _free_port()
    form_server = http.server.ThreadingHTTPServer(("127.0.0.1", form_port), _FormHandler)
    threading.Thread(target=form_server.serve_forever, daemon=True).start()
    server = uvicorn.Server(uvicorn.Config(create_app(config), host="127.0.0.1", port=app_port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    # After start-up, which re-syncs the broker catalog: point one broker at the fake form.
    with session_scope() as s:
        user = User(username="admin", password_hash=hash_password("correct horse battery"))
        s.add(user)
        s.flush()
        broker = s.scalars(select(Broker).where(Broker.slug == "fastpeoplesearch")).one()
        broker.opt_out_url = f"http://localhost:{form_port}/removal"
        broker.domains = ["localhost"]
        req, _ = engine.create_request(s, make_profile(s), broker, now=utcnow())
        token, rid = pair_browser(s, user, "Chromium test"), req.id
    yield {"base": f"http://localhost:{app_port}", "form": f"http://localhost:{form_port}/removal",
           "other": f"http://127.0.0.1:{form_port}/removal", "token": token, "rid": rid}
    server.should_exit = True
    form_server.shutdown()


@pytest.fixture()
def browser(tmp_path):
    # Grant the test hosts up front, as the person would when pairing (the prompt can't be clicked here).
    ext = tmp_path / "extension"
    shutil.copytree(EXTENSION, ext)
    manifest = json.loads((ext / "manifest.json").read_text())
    manifest["host_permissions"] = ["http://localhost/*", "http://127.0.0.1/*"]
    (ext / "manifest.json").write_text(json.dumps(manifest))
    with sync_api.sync_playwright() as p:
        try:
            ctx = p.chromium.launch_persistent_context(
                str(tmp_path / "profile"), channel="chromium", headless=True,
                executable_path=os.environ.get("DATACLEANER_TEST_CHROMIUM") or None,
                args=[f"--disable-extensions-except={ext}", f"--load-extension={ext}"],
            )
        except Exception as exc:  # no Chromium installed
            pytest.skip(f"Chromium not available: {exc}")
        yield ctx, _extension_id(ext)
        ctx.close()


def test_extension_pairs_fills_and_marks_submitted(live, browser):
    ctx, ext_id = browser
    form = ctx.new_page()
    form.goto(live["form"])
    popup = ctx.new_page()
    popup.goto(f"chrome-extension://{ext_id}/popup.html")

    # Pair through the popup's own form.
    popup.fill("#base", live["base"])
    popup.fill("#token", live["token"])
    popup.click("#pair-form button[type=submit]")
    popup.wait_for_selector("#main-view:not([hidden])")
    # The main view shows before its task list arrives from the server: wait for the text, don't read it once.
    sync_api.expect(popup.locator("#message")).to_contain_text("Paired as admin")
    sync_api.expect(popup.locator("#tasks")).to_contain_text("FastPeopleSearch")

    # With the broker's page in front, the popup offers to fill it.
    form.bring_to_front()
    popup.evaluate("DataCleaner.render()")
    popup.wait_for_selector("#here:not([hidden])")
    sync_api.expect(popup.locator("#here-broker")).to_contain_text("FastPeopleSearch")
    popup.click("#fill")
    sync_api.expect(popup.locator("#message")).to_contain_text("Filled")

    assert form.input_value("#fn") == "Jane"
    assert form.input_value("[name=lastName]") == "Doe"
    assert form.input_value("[name=contact]").startswith("jane.doe+dc-fastpeoplesearch-")
    assert form.input_value("[name=phone_number]") == "(415) 555-0134"
    assert form.input_value("[name=town]") == "San Francisco"
    assert form.input_value("#st") == "CA"
    assert form.input_value("#z") == "00000"  # never overwrites what's there
    assert form.input_value("[name=csrf]") == "keep" and form.input_value("[name=secret_city]") == ""
    assert "Data Cleaner filled" in form.inner_text("#datacleaner-banner")

    # A look-alike page on another host gets nothing.
    other = ctx.new_page()
    other.goto(live["other"])
    result = popup.evaluate("""async (url) => {
        const [tab] = await chrome.tabs.query({url: url});
        return DataCleaner.fillTab(tab.id, %d);
    }""" % live["rid"], live["other"].split("/removal")[0] + "/*")
    assert result == {"ok": False, "reason": "domain", "host": "127.0.0.1"}
    assert other.input_value("#fn") == ""

    # "I submitted it" closes the loop in Data Cleaner.
    form.bring_to_front()
    popup.evaluate("DataCleaner.render()")
    popup.wait_for_selector("#here:not([hidden])")
    popup.fill("#note", "Ref 42")
    popup.click("#submitted")
    sync_api.expect(popup.locator("#message")).to_contain_text("Recorded")
    with session_scope() as s:
        req = s.get(RemovalRequest, live["rid"])
        assert req.status == RequestStatus.SENT and req.next_action_at is not None
        assert any("Submitted with the browser extension: Ref 42" in e.summary for e in req.events)
    popup.wait_for_selector("#empty:not([hidden])")
