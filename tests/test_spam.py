import httpx
from sqlalchemy import select

from datacleaner.models import MailingSender, OutboxMessage
from datacleaner.spam import dnc
from datacleaner.spam.checklist import items_for
from datacleaner.spam.unsubscribe import UnsubInfo, is_public_https, parse_headers, parse_list_unsubscribe, record, unsubscribe


def test_dnc_api_and_csv_parsing(session):
    page = {"data": [
        {"type": "dnc_complaint", "id": "1", "attributes": {"company-phone-number": "8005551234", "created-date": "2026-03-01 10:00:00",
                                                            "consumer-state": "Texas", "subject": "Warranties", "recorded-message-or-robocall": "Y"}},
        {"type": "dnc_complaint", "id": "2", "attributes": {"company-phone-number": "1-800-555-1234", "created-date": "2026-03-02 10:00:00",
                                                            "consumer-state": "Ohio", "subject": "Medicare", "recorded-message-or-robocall": "N"}},
        {"type": "dnc_complaint", "id": "3", "attributes": {"company-phone-number": "12", "created-date": "2026-03-02"}},
    ]}
    complaints = dnc.parse_api_page(page)
    assert [c.number for c in complaints] == ["8005551234", "8005551234"]
    csv_text = "Company_Phone_Number,Created_Date,Violation_Date,Consumer_City,Consumer_State,Consumer_Area_Code,Subject,Recorded_Message_Or_Robocall\n" \
               "2125550000,2026-03-03 09:00:00,,NYC,New York,212,Debt reduction,Y\n"
    complaints += dnc.parse_csv(csv_text)
    assert dnc.ingest(session, complaints) == 2
    row = dnc.lookup(session, "(800) 555-1234")
    assert row.reports == 2 and row.robocall_reports == 1 and row.last_reported == "2026-03-02"
    assert set(row.subjects) == {"Warranties", "Medicare"}
    top = dnc.top_numbers(session, min_reports=2)
    assert [r.number for r in top] == ["8005551234"]


def test_dnc_fetch_paginates():
    calls = []

    def handler(req):
        calls.append(int(req.url.params["offset"]))
        n = 50 if len(calls) == 1 else 3
        return httpx.Response(200, json={"data": [{"attributes": {"company-phone-number": f"80055500{i:02d}"}} for i in range(n)]})

    out = dnc.fetch_api("KEY", state="TX", client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert calls == [0, 50] and len(out) == 53


def test_vcard_chunks():
    v = dnc.to_vcard([f"80055500{i:02d}" for i in range(5)], per_contact=2)
    assert v.count("BEGIN:VCARD") == 3 and "FN:Spam Blocklist 3" in v and "TEL;TYPE=VOICE:+18005550004" in v


def test_list_unsubscribe_parsing():
    oc, mt, web = parse_list_unsubscribe("<mailto:unsub@news.example?subject=stop>, <https://news.example/u/1>", "List-Unsubscribe=One-Click")
    assert oc == "https://news.example/u/1" and mt == "mailto:unsub@news.example?subject=stop" and web is None
    oc, mt, web = parse_list_unsubscribe("<https://news.example/u/1>", None)
    assert oc is None and web == "https://news.example/u/1"
    raw = (b"From: Shop <deals@shop.example>\r\nSubject: Sale!\r\nDate: Mon, 02 Mar 2026 10:00:00 +0000\r\n"
           b"List-Unsubscribe: <https://shop.example/unsub?id=9>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n\r\n")
    info = parse_headers(raw)
    assert info.sender == "deals@shop.example" and info.one_click_url == "https://shop.example/unsub?id=9"


def test_unsubscribe_one_click_and_mailto(session, now):
    record(session, [
        UnsubInfo("deals@shop.example", "Shop", "Sale", now, "https://shop.example/unsub?id=9", None, None),
        UnsubInfo("news@paper.example", "Paper", "News", now, None, "mailto:leave@paper.example?subject=unsubscribe%20me", None),
        UnsubInfo("x@web.example", "Web", "Hi", now, None, None, "https://web.example/u"),
        UnsubInfo("evil@lan.example", "LAN", "Hi", now, "https://192.168.1.1/admin", None, None),
    ])
    senders = {s.sender: s for s in session.scalars(select(MailingSender))}
    posted = {}

    def handler(req):
        posted["body"] = req.content.decode()
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert unsubscribe(session, senders["deals@shop.example"], now=now, client=client) == "unsubscribed"
    assert posted["body"] == "List-Unsubscribe=One-Click"
    assert unsubscribe(session, senders["news@paper.example"], now=now) == "queued"
    msg = session.scalars(select(OutboxMessage)).one()
    assert msg.to_address == "leave@paper.example" and msg.subject == "unsubscribe me"
    assert unsubscribe(session, senders["x@web.example"], now=now) == "manual"
    assert unsubscribe(session, senders["evil@lan.example"], now=now, client=client) == "failed"


def test_is_public_https():
    assert is_public_https("https://news.example/u")
    assert not is_public_https("http://news.example/u")
    assert not is_public_https("https://localhost/u")
    assert not is_public_https("https://10.0.0.5/u")
    assert not is_public_https("https://router.lan/u")


def test_checklist_by_country():
    us_ca = {i.id for i in items_for("US", "CA")}
    assert {"ca-drop", "us-dnc", "us-freeze"} <= us_ca
    assert "ca-drop" not in {i.id for i in items_for("US", "TX")}
    uk = {i.id for i in items_for("GB", None)}
    assert {"uk-tps", "uk-open-register", "eu-object"} <= uk and "us-dnc" not in uk
    assert "au-dnc" in {i.id for i in items_for("AU", "NSW")}
