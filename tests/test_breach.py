import hashlib
from datetime import timedelta

import httpx
from sqlalchemy import select

from datacleaner.breach.passwords import pwned_count
from datacleaner.breach.providers import (
    HaveIBeenPwned,
    LeakCheckPublic,
    XposedOrNot,
    advice_for,
    run_breach_check,
)
from datacleaner.models import Finding, FindingKind, FindingStatus


def mock(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


XON = {
    "ExposedBreaches": {"breaches_details": [
        {"breach": "Canva", "domain": "canva.com", "xposed_date": "2019", "xposed_data": "Email addresses;Names;Passwords",
         "xposed_records": 137000000, "details": "In May 2019...", "references": "https://example.org/canva"},
    ]},
    "PastesSummary": {"cnt": 2, "domain": "", "first_seen": "2020", "last_seen": "2021"},
    "ExposedPastes": [],
}


def test_xposedornot_parses_breaches_and_paste_summary():
    def handler(req):
        assert req.url.path == "/v1/breach-analytics" and req.url.params["email"] == "jane.doe@example.com"
        return httpx.Response(200, json=XON)

    out = XposedOrNot(client=mock(handler)).lookup("jane.doe@example.com", "email")
    assert [e.kind for e in out] == ["breach", "paste"]
    assert out[0].name == "Canva" and out[0].data_classes == ["Email addresses", "Names", "Passwords"]
    assert XposedOrNot(client=mock(lambda r: httpx.Response(404, json={"Error": "Not found"}))).lookup("x@y.z", "email") == []


def test_leakcheck():
    payload = {"success": True, "found": 2, "fields": ["username", "password"],
               "sources": [{"name": "Twitter.com", "date": "2022-07"}, {"name": "Unknown", "date": ""}]}
    out = LeakCheckPublic(client=mock(lambda r: httpx.Response(200, json=payload))).lookup("janedoe85", "username")
    assert [e.name for e in out] == ["Twitter.com", "Unknown"] and out[0].data_classes == ["username", "password"]
    nf = LeakCheckPublic(client=mock(lambda r: httpx.Response(200, json={"success": False, "error": "Not found"})))
    assert nf.lookup("x", "email") == []


def test_hibp_breaches_and_pastes():
    def handler(req):
        assert req.headers["hibp-api-key"] == "k"
        if "/breachedaccount/" in req.url.path:
            return httpx.Response(200, json=[{"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04",
                                              "DataClasses": ["Email addresses", "Password hints", "Passwords"]}])
        return httpx.Response(200, json=[{"Source": "Pastebin", "Id": "8Q0BvKD8", "Title": "dump", "Date": "2014-03-04T19:14:54Z"}])

    out = HaveIBeenPwned("k", client=mock(handler)).lookup("jane.doe@example.com", "email")
    assert out[0].url == "https://haveibeenpwned.com/Breach/Adobe"
    assert out[1].kind == "paste" and out[1].url == "https://pastebin.com/8Q0BvKD8" and out[1].date == "2014-03-04"


def test_run_breach_check_dedupes(session, profile, now):
    provider = XposedOrNot(client=mock(lambda r: httpx.Response(200, json=XON)))
    run = run_breach_check(session, profile, [provider], now=now, delay=0)
    assert run.summary["exposures"] == 2 and run.summary["new"] == 2
    run = run_breach_check(session, profile, [provider], now=now, delay=0)
    assert run.summary["new"] == 0
    kinds = sorted(f.kind for f in session.scalars(select(Finding)))
    assert kinds == [FindingKind.BREACH, FindingKind.PASTE]


def test_resolved_breach_stays_resolved(session, profile, now):
    provider = XposedOrNot(client=mock(lambda r: httpx.Response(200, json=XON)))
    run_breach_check(session, profile, [provider], now=now, delay=0)
    for f in session.scalars(select(Finding)):
        f.status = FindingStatus.RESOLVED
    # Providers report the same breaches on every weekly check.
    run = run_breach_check(session, profile, [provider], now=now + timedelta(days=7), delay=0)
    assert run.summary["new"] == 0
    assert {f.status for f in session.scalars(select(Finding))} == {FindingStatus.RESOLVED}


def test_provider_errors_are_reported_not_raised(session, profile, now):
    provider = XposedOrNot(client=mock(lambda r: httpx.Response(429)))
    run = run_breach_check(session, profile, [provider], now=now, delay=0)
    assert run.summary["errors"] and run.summary["exposures"] == 0


def test_pwned_passwords_k_anonymity():
    pw = "password123"
    digest = hashlib.sha1(pw.encode()).hexdigest().upper()
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        return httpx.Response(200, text=f"0000000000000000000000000000000000A:0\n{digest[5:]}:2254650\n")

    assert pwned_count(pw, client=mock(handler)) == 2254650
    assert seen["path"] == f"/range/{digest[:5]}"  # only the prefix leaves the machine
    assert pwned_count("not-in-list", client=mock(lambda r: httpx.Response(200, text="ABC:1\n"))) == 0


def test_advice():
    tips = advice_for(["Email addresses", "Passwords", "Phone numbers"])
    assert any("two-factor" in t for t in tips) and any("SIM-swap" in t for t in tips)
    assert advice_for([]) == []
