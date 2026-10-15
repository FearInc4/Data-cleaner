from datetime import timedelta
from email.message import EmailMessage

import pytest
from sqlalchemy import select

from datacleaner.mail.inbox import match_request, process_inbox
from datacleaner.mail.parse import ReplyKind, classify, find_reference, parse_message, verification_links
from datacleaner.mail.smtp import drain_outbox
from datacleaner.models import Broker, RequestStatus
from datacleaner.removal import engine
from datacleaner.settings import Settings

from .test_engine import FakeMailer, _configure


def build(subject, body, *, sender="privacy@mylife.com", html=None, in_reply_to=None, headers=None):
    m = EmailMessage()
    m["From"] = f"MyLife Privacy <{sender}>"
    m["To"] = "privacy@me.example"
    m["Subject"] = subject
    m["Message-ID"] = "<reply-1@mylife.com>"
    m["Date"] = "Mon, 09 Mar 2026 10:00:00 +0000"
    if in_reply_to:
        m["In-Reply-To"] = in_reply_to
        m["References"] = in_reply_to
    for k, v in (headers or {}).items():
        m[k] = v
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    return m.as_bytes()


class FakeSource:
    def __init__(self, raws):
        self.raws = raws

    def fetch_new(self, session):
        return [parse_message(r, uid=str(i)) for i, r in enumerate(self.raws)]


@pytest.mark.parametrize("body,kind", [
    ("Your information has been removed from our site.", ReplyKind.COMPLETED),
    ("We have deleted the records associated with your request.", ReplyKind.COMPLETED),
    ("Please click the link below to verify your request.", ReplyKind.NEEDS_VERIFICATION),
    ("We were unable to locate any records matching your information.", ReplyKind.NOT_FOUND),
    ("To proceed, please provide a copy of your government ID.", ReplyKind.NEEDS_INFO),
    ("Please use our online privacy portal to submit requests.", ReplyKind.NEEDS_INFO),
    ("We are unable to honor your request because this right only applies to residents of California.", ReplyKind.REJECTED),
    ("Thank you for contacting us. We will respond within 10 business days.", ReplyKind.ACKNOWLEDGED),
    ("Hello there.", ReplyKind.UNKNOWN),
])
def test_classify(body, kind):
    assert classify(parse_message(build("Re: request", body))).kind == kind


def test_classify_ignores_our_quoted_request():
    body = "Thanks for your request.\n\nOn Mon, Mar 2, 2026 Jane wrote:\n> Delete all personal information. It has been removed?"
    assert classify(parse_message(build("Re: request", body))).kind == ReplyKind.ACKNOWLEDGED


def test_bounce_and_auto_reply():
    bounce = parse_message(build("Undelivered Mail Returned to Sender", "Original-Message-ID: <dc-abc.1@me.example>", sender="MAILER-DAEMON@mx.example"))
    assert classify(bounce).kind == ReplyKind.BOUNCE
    auto = parse_message(build("Automatic reply: request", "I'm away", headers={"Auto-Submitted": "auto-replied"}))
    assert classify(auto).kind == ReplyKind.AUTO_REPLY


def test_verification_links_only_on_broker_domains():
    html = ('<p>Confirm: <a href="https://www.mylife.com/privacy/confirm?token=abc&amp;x=1">here</a> '
            '<a href="https://evil.example/verify?t=1">phish</a> <a href="https://www.mylife.com/unsubscribe?verify=1">no</a> '
            '<a href="http://www.mylife.com/verify">insecure</a></p>')
    msg = parse_message(build("Verify", "Click the link below to confirm your request.", html=html))
    assert verification_links(msg, ["mylife.com"]) == ["https://www.mylife.com/privacy/confirm?token=abc&x=1"]


def test_find_reference():
    msg = parse_message(build("Re: CCPA Request [Ref DC-ABCDEFGH]", "ok"))
    assert find_reference(msg) == "DC-ABCDEFGH"


def _sent_request(session, profile, now, slug="mylife"):
    _configure(session)
    broker = session.scalars(select(Broker).where(Broker.slug == slug)).one()
    req, _ = engine.create_request(session, profile, broker, now=now)
    engine.approve(session, req, now=now)
    mailer = FakeMailer()
    drain_outbox(session, mailer, now=now)
    return req, mailer.sent[0]["Message-ID"]


def test_match_by_thread_reference_and_domain(session, profile, now):
    req, msg_id = _sent_request(session, profile, now)
    by_thread = parse_message(build("Re: hi", "x", in_reply_to=msg_id, sender="someone@other.example"))
    assert match_request(session, by_thread) == (req, "thread")
    by_ref = parse_message(build(f"Re: [Ref {req.reference}]", "x", sender="someone@other.example"))
    assert match_request(session, by_ref) == (req, "reference")
    by_domain = parse_message(build("Your request", "x", sender="noreply@mylife.com"))
    assert match_request(session, by_domain) == (req, "domain")
    stranger = parse_message(build("Hello", "x", sender="news@shop.example"))
    assert match_request(session, stranger) == (None, "")


def test_inbox_completes_request(session, profile, now):
    req, msg_id = _sent_request(session, profile, now)
    later = now + timedelta(days=3)
    stats = process_inbox(session, FakeSource([build("Re: request", "Your profile has been removed.", in_reply_to=msg_id)]), now=later)
    assert stats["matched"] == 1 and stats["completed"] == 1
    assert req.status == RequestStatus.COMPLETED and req.last_reply_at == later
    # The same message delivered again is ignored.
    stats = process_inbox(session, FakeSource([build("Re: request", "Your profile has been removed.", in_reply_to=msg_id)]), now=later)
    assert stats["matched"] == 0


def test_inbox_clicks_safe_verification_link(session, profile, now):
    req, msg_id = _sent_request(session, profile, now)
    clicked = []
    html = '<a href="https://www.mylife.com/optout/verify?token=xyz">Verify</a> <a href="https://tracker.example/c?u=1">x</a>'
    raw = build("Please verify", "Please click the button below to verify your request.", html=html, in_reply_to=msg_id)
    process_inbox(session, FakeSource([raw]), now=now, clicker=lambda url: clicked.append(url) or 200)
    assert clicked == ["https://www.mylife.com/optout/verify?token=xyz"]
    assert req.status == RequestStatus.ACKNOWLEDGED
    assert any(e.type == "verified" for e in req.events)


def test_inbox_verification_disabled_hands_to_user(session, profile, now):
    req, msg_id = _sent_request(session, profile, now)
    Settings(session).set("auto_click_verification", False)
    raw = build("Please verify", "Please confirm your request: https://www.mylife.com/verify?t=1", in_reply_to=msg_id)
    process_inbox(session, FakeSource([raw]), now=now, clicker=lambda url: pytest.fail("must not click"))
    assert req.status == RequestStatus.NEEDS_VERIFICATION and req.next_action_at is None


def test_inbox_bounce_flags_request(session, profile, now):
    req, msg_id = _sent_request(session, profile, now)
    raw = build("Delivery Status Notification (Failure)", f"Message-ID: {msg_id}\nAddress not found", sender="mailer-daemon@googlemail.com")
    stats = process_inbox(session, FakeSource([raw]), now=now)
    assert stats["bounce"] == 1 and req.status == RequestStatus.NEEDS_USER_ACTION


def test_inbox_unknown_reply_keeps_clock_running(session, profile, now):
    req, msg_id = _sent_request(session, profile, now)
    process_inbox(session, FakeSource([build("Re: request", "Hello, who is this?", in_reply_to=msg_id)]), now=now)
    assert req.status == RequestStatus.ACKNOWLEDGED
    assert req.next_action_at == now + timedelta(days=45)
    assert any(e.type == "review" for e in req.events)
