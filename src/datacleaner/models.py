from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from .crypto import get_vault
from .db import Base


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class EncryptedText(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return get_vault().encrypt(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return get_vault().decrypt(value)


class EncryptedJSON(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return get_vault().encrypt_json(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return get_vault().decrypt_json(value)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Relation:
    SELF = "self"
    AGENT = "agent"  # authorized agent acting for a family member / client


class Profile(Base):
    """A person whose data we are cleaning up. PII is one encrypted JSON blob.

    pii keys: first_name, middle_name, last_name, aliases[], birth_date,
    emails[], phones[], addresses[{street, city, region, postal_code, country, current}],
    usernames[].
    """

    __tablename__ = "profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    label: Mapped[str] = mapped_column(String(120))
    relation: Mapped[str] = mapped_column(String(20), default=Relation.SELF)
    # Jurisdiction is kept in clear so the scheduler can pick laws without decrypting.
    country: Mapped[str] = mapped_column(String(2), default="US")
    region: Mapped[str | None] = mapped_column(String(10), nullable=True)
    pii: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON, default=dict)
    attested_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    agent_authorization_on_file: Mapped[bool] = mapped_column(Boolean, default=False)
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_scan_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_breach_check_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    requests: Mapped[list["RemovalRequest"]] = relationship(back_populates="profile", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="profile", cascade="all, delete-orphan")

    # Convenience accessors -------------------------------------------------
    def get(self, key: str, default: Any = None) -> Any:
        return (self.pii or {}).get(key, default)

    @property
    def full_name(self) -> str:
        parts = [self.get("first_name"), self.get("middle_name"), self.get("last_name")]
        return " ".join(p for p in parts if p)

    @property
    def short_name(self) -> str:
        return " ".join(p for p in [self.get("first_name"), self.get("last_name")] if p)

    @property
    def emails(self) -> list[str]:
        return [e for e in self.get("emails", []) if e]

    @property
    def phones(self) -> list[str]:
        return [p for p in self.get("phones", []) if p]

    @property
    def addresses(self) -> list[dict[str, Any]]:
        return [a for a in self.get("addresses", []) if a]

    @property
    def current_address(self) -> dict[str, Any] | None:
        addrs = self.addresses
        for a in addrs:
            if a.get("current"):
                return a
        return addrs[0] if addrs else None

    @property
    def contact_email(self) -> str | None:
        emails = self.emails
        return emails[0] if emails else None


class BrokerCategory:
    PEOPLE_SEARCH = "people_search"
    BACKGROUND_CHECK = "background_check"
    MARKETING = "marketing"
    RISK_IDENTITY = "risk_identity"
    GENEALOGY = "genealogy"
    FACE_SEARCH = "face_search"
    B2B = "b2b"
    OTHER = "other"

    ALL = [PEOPLE_SEARCH, BACKGROUND_CHECK, MARKETING, RISK_IDENTITY, GENEALOGY, FACE_SEARCH, B2B, OTHER]


class Broker(Base):
    __tablename__ = "brokers"

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(120), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    website: Mapped[str | None] = mapped_column(String(500), nullable=True)
    domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    category: Mapped[str] = mapped_column(String(40), default=BrokerCategory.OTHER)
    regions: Mapped[list[str]] = mapped_column(JSON, default=list)  # e.g. ["US"], ["EU","UK"], ["*"]
    priority: Mapped[int] = mapped_column(Integer, default=3)  # 1 crucial, 2 high, 3 normal
    privacy_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    opt_out_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    search_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    methods: Mapped[list[str]] = mapped_column(JSON, default=list)  # email, form, phone, mail, portal
    requires: Mapped[list[str]] = mapped_column(JSON, default=list)  # captcha, email_verification, profile_url, id_document, phone_call, account
    parent: Mapped[str | None] = mapped_column(String(200), nullable=True)
    owns: Mapped[list[str]] = mapped_column(JSON, default=list)
    steps: Mapped[list[str]] = mapped_column(JSON, default=list)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(60), default="catalog")
    registries: Mapped[list[str]] = mapped_column(JSON, default=list)  # CA, VT, TX, OR
    verified: Mapped[bool] = mapped_column(Boolean, default=True)  # opt-out link confirmed by a contributor
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    @property
    def preferred_method(self) -> str:
        if "email" in self.methods and self.privacy_email:
            return "email"
        if "form" in self.methods and self.opt_out_url:
            return "form"
        return "manual"


class RequestStatus:
    DRAFT = "draft"
    QUEUED = "queued"  # email waiting in outbox
    AWAITING_USER = "awaiting_user"  # form/manual: human has to submit
    SENT = "sent"
    NEEDS_VERIFICATION = "needs_verification"
    ACKNOWLEDGED = "acknowledged"
    NEEDS_USER_ACTION = "needs_user_action"
    OVERDUE = "overdue"
    COMPLETED = "completed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"

    OPEN = {QUEUED, SENT, NEEDS_VERIFICATION, ACKNOWLEDGED, OVERDUE}
    NEEDS_HUMAN = {DRAFT, AWAITING_USER, NEEDS_USER_ACTION, REJECTED}
    TERMINAL = {COMPLETED, CANCELLED}
    ALL = [
        DRAFT, QUEUED, AWAITING_USER, SENT, NEEDS_VERIFICATION, ACKNOWLEDGED,
        NEEDS_USER_ACTION, OVERDUE, COMPLETED, REJECTED, CANCELLED,
    ]


def new_reference() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "DC-" + "".join(secrets.choice(alphabet) for _ in range(8))


class RemovalRequest(Base):
    __tablename__ = "removal_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    profile_id: Mapped[int] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"))
    broker_id: Mapped[int] = mapped_column(ForeignKey("brokers.id"))
    method: Mapped[str] = mapped_column(String(20))  # email, form, manual
    law_key: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30), default=RequestStatus.DRAFT)
    reference: Mapped[str] = mapped_column(String(20), unique=True, default=new_reference)
    to_address: Mapped[str | None] = mapped_column(String(320), nullable=True)
    listing_url: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    first_sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_action_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    followup_count: Mapped[int] = mapped_column(Integer, default=0)  # follow-up emails actually queued
    cadence_step: Mapped[int] = mapped_column(Integer, default=0)  # steps of the cadence consumed
    last_reply_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    recheck_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    paused: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)

    profile: Mapped[Profile] = relationship(back_populates="requests")
    broker: Mapped[Broker] = relationship()
    events: Mapped[list["RequestEvent"]] = relationship(
        back_populates="request", cascade="all, delete-orphan", order_by="RequestEvent.at"
    )


class RequestEvent(Base):
    __tablename__ = "request_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("removal_requests.id", ondelete="CASCADE"))
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    type: Mapped[str] = mapped_column(String(40))
    direction: Mapped[str] = mapped_column(String(10), default="system")  # out, in, system
    summary: Mapped[str] = mapped_column(String(500), default="")
    body: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    message_id: Mapped[str | None] = mapped_column(String(300), nullable=True, index=True)

    request: Mapped[RemovalRequest] = relationship(back_populates="events")


class OutboxMessage(Base):
    """Outgoing mail, drained by the scheduler under a rate limit."""

    __tablename__ = "outbox"

    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[int | None] = mapped_column(ForeignKey("removal_requests.id", ondelete="CASCADE"), nullable=True)
    kind: Mapped[str] = mapped_column(String(30), default="initial")  # initial, followup, final_notice, unsubscribe, digest
    to_address: Mapped[str] = mapped_column(String(320))
    subject: Mapped[str] = mapped_column(EncryptedText)
    body: Mapped[str] = mapped_column(EncryptedText)
    message_id: Mapped[str] = mapped_column(String(300))
    in_reply_to: Mapped[str | None] = mapped_column(String(300), nullable=True)
    references: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued, sent, failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class FindingKind:
    LISTING = "listing"  # direct hit on a broker site
    SEARCH = "search"  # search engine result
    BREACH = "breach"
    PASTE = "paste"
    CODE = "code"  # public source code


class FindingStatus:
    NEW = "new"
    REMOVAL_REQUESTED = "removal_requested"
    REMOVED = "removed"
    DISMISSED = "dismissed"
    RESOLVED = "resolved"  # breach: actions taken


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("profile_id", "fingerprint"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    profile_id: Mapped[int] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(20))
    source: Mapped[str] = mapped_column(String(80))
    fingerprint: Mapped[str] = mapped_column(String(64))
    url: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    title: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    snippet: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    data_classes: Mapped[list[str]] = mapped_column(JSON, default=list)
    matched_fields: Mapped[list[str]] = mapped_column(JSON, default=list)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    occurred_on: Mapped[str | None] = mapped_column(String(20), nullable=True)  # breach date
    broker_id: Mapped[int | None] = mapped_column(ForeignKey("brokers.id"), nullable=True)
    check_state: Mapped[str | None] = mapped_column(String(20), nullable=True)  # found, not_found, blocked, error
    status: Mapped[str] = mapped_column(String(30), default=FindingStatus.NEW)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    profile: Mapped[Profile] = relationship(back_populates="findings")
    broker: Mapped[Broker | None] = relationship()


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    profile_id: Mapped[int] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(20))  # search, brokers, breach
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="running")
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    profile: Mapped[Profile] = relationship()


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    secret: Mapped[bool] = mapped_column(Boolean, default=False)


class SpamNumber(Base):
    """Phone numbers reported to the FTC Do Not Call complaint feed, cached locally."""

    __tablename__ = "spam_numbers"

    number: Mapped[str] = mapped_column(String(20), primary_key=True)
    reports: Mapped[int] = mapped_column(Integer, default=0)
    robocall_reports: Mapped[int] = mapped_column(Integer, default=0)
    last_reported: Mapped[str | None] = mapped_column(String(20), nullable=True)
    subjects: Mapped[list[str]] = mapped_column(JSON, default=list)
    states: Mapped[list[str]] = mapped_column(JSON, default=list)


class MailingSender(Base):
    """A sender found in the inbox with a List-Unsubscribe header (spam/unsubscribe helper)."""

    __tablename__ = "mailing_senders"

    id: Mapped[int] = mapped_column(primary_key=True)
    sender: Mapped[str] = mapped_column(String(320), unique=True)
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    sample_subject: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    messages: Mapped[int] = mapped_column(Integer, default=0)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    one_click_url: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    mailto: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    web_url: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="new")  # new, unsubscribed, kept, failed
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
