import smtplib
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select

from datacleaner.mail.smtp import MAX_ATTEMPTS, drain_outbox
from datacleaner.models import Broker, OutboxMessage, RemovalRequest, RequestStatus
from datacleaner.removal import engine
from datacleaner.removal.engine import Step, cadence
from datacleaner.settings import Settings


class FakeMailer:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    def send(self, message):
        if self.fail:
            raise OSError("connection refused")
        self.sent.append(message)


def _configure(session):
    s = Settings(session)
    s.set("smtp_host", "smtp.example.com")
    s.set("from_address", "privacy@me.example")
    s.set("from_name", "Jane Doe")


def _broker(session, slug="mylife"):
    return session.scalars(select(Broker).where(Broker.slug == slug)).one()


def test_cadence_shapes():
    steps = cadence(45, [10, 25], 30, 6)
    assert steps[:4] == [Step(10, "followup"), Step(25, "followup"), Step(45, "final_notice"), Step(52, "escalate")]
    assert [s.offset_days for s in steps[4:]] == [82, 112, 142]
    assert sum(s.action != "escalate" for s in steps) == 6
    # Follow-ups past the deadline are dropped; a tight cap keeps the final notice.
    assert cadence(30, [10, 40], 30, 2) == [Step(10, "followup"), Step(30, "final_notice"), Step(37, "escalate")]
    assert cadence(30, [10, 20], 30, 1) == [Step(30, "final_notice"), Step(37, "escalate")]


def test_email_request_full_lifecycle(session, profile, now):
    _configure(session)
    mailer = FakeMailer()
    req, created = engine.create_request(session, profile, _broker(session), now=now)
    assert created and req.status == RequestStatus.DRAFT and req.to_address == "privacy@mylife.com"
    # A second create returns the same open request.
    again, created2 = engine.create_request(session, profile, _broker(session), now=now)
    assert again.id == req.id and not created2

    engine.approve(session, req, now=now)
    assert req.status == RequestStatus.QUEUED
    assert drain_outbox(session, mailer, now=now)["sent"] == 1
    assert req.status == RequestStatus.SENT
    assert req.due_at == now + timedelta(days=45)
    assert req.next_action_at == now + timedelta(days=10)
    first = mailer.sent[0]
    assert first["To"] == "privacy@mylife.com" and "[Ref " + req.reference + "]" in first["Subject"]
    first_id = first["Message-ID"]

    # Nothing due yet.
    assert engine.process_due(session, now=now + timedelta(days=9))["followup"] == 0

    # Day 10: follow-up #1, threaded on the original.
    day10 = now + timedelta(days=10)
    assert engine.process_due(session, now=day10)["followup"] == 1
    drain_outbox(session, mailer, now=day10)
    fu = mailer.sent[-1]
    assert fu["In-Reply-To"] == first_id and fu["Subject"].startswith("Follow-up: ")
    assert req.followup_count == 1 and req.next_action_at == now + timedelta(days=25)

    day25 = now + timedelta(days=25)
    engine.process_due(session, now=day25)
    drain_outbox(session, mailer, now=day25)
    assert "follow-up #2" in mailer.sent[-1].get_content()

    day45 = now + timedelta(days=45)
    assert engine.process_due(session, now=day45)["final_notice"] == 1
    drain_outbox(session, mailer, now=day45)
    assert mailer.sent[-1]["Subject"].startswith("Final notice: ")
    assert req.status == RequestStatus.OVERDUE

    day52 = now + timedelta(days=52)
    assert engine.process_due(session, now=day52)["escalate"] == 1
    assert req.escalated_at == day52
    esc = [e for e in req.events if e.type == "escalation_ready"]
    assert esc and "California Privacy Protection Agency" in esc[0].summary
    assert req.next_action_at == now + timedelta(days=82)

    # Ticking twice at the same time does nothing more.
    assert sum(engine.process_due(session, now=day52).values()) == 0

    engine.mark_completed(session, req, now=day52 + timedelta(days=1))
    assert req.status == RequestStatus.COMPLETED and req.next_action_at is None and req.recheck_at is not None
    assert engine.open_request_for(session, profile.id, req.broker_id) is None


def test_acknowledged_skips_early_reminders(session, profile, now):
    _configure(session)
    mailer = FakeMailer()
    req, _ = engine.create_request(session, profile, _broker(session), now=now)
    engine.approve(session, req, now=now)
    drain_outbox(session, mailer, now=now)
    engine.set_status(session, req, RequestStatus.ACKNOWLEDGED, now=now + timedelta(days=2), summary="ack")
    assert req.next_action_at == now + timedelta(days=45)
    assert engine.process_due(session, now=now + timedelta(days=30)) == {"followup": 0, "final_notice": 0, "escalate": 0, "user_action": 0}
    assert engine.process_due(session, now=now + timedelta(days=45))["final_notice"] == 1
    assert req.followup_count == 1  # only the final notice was actually sent


def test_needs_verification_pauses_clock_until_resumed(session, profile, now):
    _configure(session)
    req, _ = engine.create_request(session, profile, _broker(session), now=now)
    engine.approve(session, req, now=now)
    drain_outbox(session, FakeMailer(), now=now)
    engine.set_status(session, req, RequestStatus.NEEDS_VERIFICATION, now=now, summary="verify")
    assert req.next_action_at is None
    engine.resume(session, req, now=now + timedelta(days=1))
    assert req.status == RequestStatus.SENT and req.next_action_at == now + timedelta(days=10)


def test_form_request_hands_back_to_user(session, profile, now):
    broker = _broker(session, "fastpeoplesearch")  # form only, no email
    req, _ = engine.create_request(session, profile, broker, now=now)
    assert req.method == "form" and req.status == RequestStatus.AWAITING_USER
    engine.mark_submitted(session, req, now=now)
    assert req.status == RequestStatus.SENT and req.next_action_at == now + timedelta(days=10)
    stats = engine.process_due(session, now=now + timedelta(days=10))
    assert stats["user_action"] == 1 and req.status == RequestStatus.NEEDS_USER_ACTION
    assert session.scalars(select(OutboxMessage)).all() == []


def test_form_request_followups_use_privacy_email_when_known(session, profile, now):
    _configure(session)
    broker = _broker(session, "nuwber")  # form preferred? no: email + form, so email is preferred
    req, _ = engine.create_request(session, profile, broker, now=now, method="form")
    engine.mark_submitted(session, req, now=now)
    assert req.to_address == "support@nuwber.com"
    assert engine.process_due(session, now=now + timedelta(days=10))["followup"] == 1
    msg = session.scalars(select(OutboxMessage)).one()
    assert "(submitted via web form)" in msg.body


def test_auto_approve_and_rate_limit(session, profile, now):
    _configure(session)
    s = Settings(session)
    s.set("auto_approve", True)
    s.set("rate_limit_per_hour", 2)
    for slug in ("mylife", "nuwber", "beenverified"):
        engine.create_request(session, profile, _broker(session, slug), now=now)
    mailer = FakeMailer()
    assert drain_outbox(session, mailer, now=now) == {"sent": 2, "failed": 0, "deferred": 1}
    assert drain_outbox(session, mailer, now=now + timedelta(minutes=30))["sent"] == 0
    assert drain_outbox(session, mailer, now=now + timedelta(minutes=61))["sent"] == 1


class RaisingMailer:
    def __init__(self, exc):
        self.exc, self.calls = exc, 0

    def send(self, message):
        self.calls += 1
        raise self.exc


def test_send_failures_back_off_then_flag(session, profile, now):
    _configure(session)
    req, _ = engine.create_request(session, profile, _broker(session), now=now)
    engine.approve(session, req, now=now)
    bad = RaisingMailer(OSError("connection refused"))
    assert drain_outbox(session, bad, now=now)["failed"] == 0
    # Retrying on every 5-minute tick would use up every attempt within half an hour.
    for minutes in range(1, 5):
        drain_outbox(session, bad, now=now + timedelta(minutes=minutes))
    assert bad.calls == 1
    msg = session.scalars(select(OutboxMessage)).one()
    for _ in range(MAX_ATTEMPTS - 2):
        t = msg.next_attempt_at
        assert drain_outbox(session, bad, now=t)["failed"] == 0
    assert req.status == RequestStatus.QUEUED and t - now > timedelta(days=1)
    assert drain_outbox(session, bad, now=msg.next_attempt_at)["failed"] == 1
    assert bad.calls == MAX_ATTEMPTS and req.status == RequestStatus.NEEDS_USER_ACTION


def test_short_outage_recovers(session, profile, now):
    _configure(session)
    req, _ = engine.create_request(session, profile, _broker(session), now=now)
    engine.approve(session, req, now=now)
    drain_outbox(session, RaisingMailer(OSError("network unreachable")), now=now)
    ok = FakeMailer()
    assert drain_outbox(session, ok, now=now + timedelta(minutes=5))["sent"] == 1
    assert req.status == RequestStatus.SENT


@pytest.mark.parametrize("exc", [
    smtplib.SMTPRecipientsRefused({"privacy@mylife.com": (550, b"no such user")}),
    smtplib.SMTPDataError(554, b"message rejected"),
    httpx.HTTPStatusError("bad request", request=httpx.Request("POST", "https://gmail.example"), response=httpx.Response(400)),
])
def test_permanent_send_errors_fail_at_once(session, profile, now, exc):
    _configure(session)
    req, _ = engine.create_request(session, profile, _broker(session), now=now)
    engine.approve(session, req, now=now)
    assert drain_outbox(session, RaisingMailer(exc), now=now)["failed"] == 1
    assert req.status == RequestStatus.NEEDS_USER_ACTION


def test_bad_smtp_password_keeps_mail_queued(session, profile, now):
    _configure(session)
    req, _ = engine.create_request(session, profile, _broker(session), now=now)
    engine.approve(session, req, now=now)
    stats = drain_outbox(session, RaisingMailer(smtplib.SMTPAuthenticationError(535, b"bad credentials")), now=now)
    assert stats["deferred"] == 1 and stats["failed"] == 0
    msg = session.scalars(select(OutboxMessage)).one()
    assert msg.status == "queued" and msg.attempts == 0 and req.status == RequestStatus.QUEUED


def _sent(session, profile, now, mailer=None):
    _configure(session)
    req, _ = engine.create_request(session, profile, _broker(session), now=now)
    engine.approve(session, req, now=now)
    drain_outbox(session, mailer or FakeMailer(), now=now)
    return req


def test_cancel_withdraws_queued_mail(session, profile, now):
    _configure(session)
    req, _ = engine.create_request(session, profile, _broker(session), now=now)
    engine.approve(session, req, now=now)
    engine.set_status(session, req, RequestStatus.CANCELLED, now=now, summary="Cancelled")
    mailer = FakeMailer()
    drain_outbox(session, mailer, now=now)
    assert mailer.sent == [] and req.status == RequestStatus.CANCELLED and req.next_action_at is None
    assert session.scalars(select(OutboxMessage)).one().status == "cancelled"


def test_completed_request_with_queued_followup_stays_completed(session, profile, now):
    req = _sent(session, profile, now)
    later = now + timedelta(days=10)
    assert engine.process_due(session, now=later)["followup"] == 1
    engine.mark_completed(session, req, now=later, summary="Broker confirmed")
    mailer = FakeMailer()
    drain_outbox(session, mailer, now=later)
    assert mailer.sent == [] and req.status == RequestStatus.COMPLETED and req.next_action_at is None


def test_mail_sent_after_completion_does_not_reopen(session, profile, now):
    _configure(session)
    req, _ = engine.create_request(session, profile, _broker(session), now=now)
    msg = engine.approve(session, req, now=now)
    req.status = RequestStatus.COMPLETED  # changed while the message was being handed to the provider
    engine.on_message_sent(session, msg, now=now)
    assert req.status == RequestStatus.COMPLETED and req.next_action_at is None


def test_resume_without_any_send_goes_back_to_draft(session, profile, now):
    _configure(session)
    req, _ = engine.create_request(session, profile, _broker(session), now=now)
    engine.approve(session, req, now=now)
    drain_outbox(session, RaisingMailer(smtplib.SMTPRecipientsRefused({"x": (550, b"no")})), now=now)
    assert req.status == RequestStatus.NEEDS_USER_ACTION and req.first_sent_at is None
    engine.resume(session, req, now=now)
    assert req.status == RequestStatus.DRAFT and req.next_action_at is None

    # Same for a re-send that failed, even though an earlier attempt did go out.
    engine.approve(session, req, now=now)
    drain_outbox(session, FakeMailer(), now=now)
    engine.set_status(session, req, RequestStatus.REJECTED, now=now, summary="declined")
    engine.approve(session, req, now=now + timedelta(days=5))
    drain_outbox(session, RaisingMailer(smtplib.SMTPRecipientsRefused({"x": (550, b"no")})), now=now + timedelta(days=5))
    engine.resume(session, req, now=now + timedelta(days=5))
    assert req.status == RequestStatus.DRAFT and req.next_action_at is None

    form, _ = engine.create_request(session, profile, _broker(session, "fastpeoplesearch"), now=now)
    form.status = RequestStatus.NEEDS_USER_ACTION
    engine.resume(session, form, now=now)
    assert form.status == RequestStatus.AWAITING_USER


def test_overdue_steps_after_downtime_dont_burst(session, profile, now):
    req = _sent(session, profile, now)
    back = now + timedelta(days=50)  # down through both reminders and the 45-day deadline
    assert engine.process_due(session, now=back) == {"followup": 0, "final_notice": 1, "escalate": 0, "user_action": 0}
    drain_outbox(session, FakeMailer(), now=back)
    for minutes in (5, 10, 15):
        assert sum(engine.process_due(session, now=back + timedelta(minutes=minutes)).values()) == 0
    # The final notice promised 7 days before a complaint is drafted.
    assert req.next_action_at == back + timedelta(days=7)
    assert engine.process_due(session, now=back + timedelta(days=7))["escalate"] == 1


def test_resend_after_rejection_gets_fresh_followups(session, profile, now):
    mailer = FakeMailer()
    req = _sent(session, profile, now, mailer)
    for days in (10, 25):
        engine.process_due(session, now=now + timedelta(days=days))
        drain_outbox(session, mailer, now=now + timedelta(days=days))
    assert req.followup_count == 2
    engine.set_status(session, req, RequestStatus.REJECTED, now=now + timedelta(days=30), summary="declined")
    again = now + timedelta(days=60)
    engine.approve(session, req, now=again)
    drain_outbox(session, mailer, now=again)
    assert req.status == RequestStatus.SENT and req.followup_count == 0
    assert req.due_at == again + timedelta(days=45) and req.next_action_at == again + timedelta(days=10)


def test_resubmitted_form_restarts_schedule(session, profile, now):
    req, _ = engine.create_request(session, profile, _broker(session, "fastpeoplesearch"), now=now)
    engine.mark_submitted(session, req, now=now)
    engine.process_due(session, now=now + timedelta(days=10))
    assert req.status == RequestStatus.NEEDS_USER_ACTION
    later = now + timedelta(days=30)
    engine.mark_submitted(session, req, now=later, note="Resubmitted the form")
    assert req.first_sent_at == later and req.next_action_at == later + timedelta(days=10)


def test_unconfigured_mail_defers(session, profile, now):
    req, _ = engine.create_request(session, profile, _broker(session), now=now)
    req.status = RequestStatus.DRAFT
    engine.approve(session, req, now=now)
    assert drain_outbox(session, None, now=now) == {"sent": 0, "failed": 0, "deferred": 1}
    assert session.scalars(select(RemovalRequest)).one().status == RequestStatus.QUEUED
