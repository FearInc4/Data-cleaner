from datetime import timedelta

from sqlalchemy import select

from datacleaner.mail.smtp import drain_outbox
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


def test_send_failures_retry_then_flag(session, profile, now):
    _configure(session)
    req, _ = engine.create_request(session, profile, _broker(session), now=now)
    engine.approve(session, req, now=now)
    bad = FakeMailer(fail=True)
    for i in range(4):
        assert drain_outbox(session, bad, now=now + timedelta(minutes=i))["failed"] == 0
    assert drain_outbox(session, bad, now=now + timedelta(minutes=5))["failed"] == 1
    assert req.status == RequestStatus.NEEDS_USER_ACTION


def test_unconfigured_mail_defers(session, profile, now):
    req, _ = engine.create_request(session, profile, _broker(session), now=now)
    req.status = RequestStatus.DRAFT
    engine.approve(session, req, now=now)
    assert drain_outbox(session, None, now=now) == {"sent": 0, "failed": 0, "deferred": 1}
    assert session.scalars(select(RemovalRequest)).one().status == RequestStatus.QUEUED
