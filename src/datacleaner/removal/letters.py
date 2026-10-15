"""Render request, follow-up, final-notice and escalation letters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from ..jurisdictions import Law, Regulator, resolve_law
from ..models import Broker, Profile, Relation

_env = Environment(
    loader=PackageLoader("datacleaner.removal", "letters"),
    autoescape=False,  # plain-text email
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
    undefined=StrictUndefined,
)


@dataclass
class Letter:
    subject: str
    body: str


def fmt_date(d: date | datetime | None) -> str:
    if d is None:
        return ""
    return f"{d:%B} {d.day}, {d.year}"


def address_oneline(a: dict[str, Any]) -> str:
    parts = [a.get("street"), a.get("city"), " ".join(p for p in [a.get("region"), a.get("postal_code")] if p), a.get("country")]
    return ", ".join(p for p in parts if p)


class PersonView:
    """What a letter is allowed to see about a person. Only fields the user chose to share."""

    def __init__(self, profile: Profile):
        self.full_name = profile.full_name
        self.aliases = [a for a in profile.get("aliases", []) if a]
        self.emails = profile.emails
        self.phones = profile.phones
        self.addresses = [dict(a, oneline=address_oneline(a)) for a in profile.addresses]
        self.birth_date = profile.get("birth_date") if profile.get("share_birth_date") else None


def _agent_context(profile: Profile, law: Law) -> dict[str, str] | None:
    if profile.relation != Relation.AGENT:
        return None
    law_ref = ""
    if law.key == "us_ca":
        law_ref = "Cal. Civ. Code § 1798.135"
    elif law.key == "gdpr":
        law_ref = "Article 80 GDPR"
    return {"subject_name": profile.full_name, "law_ref": law_ref}


def _sender_name(profile: Profile, agent_name: str | None) -> str:
    if profile.relation == Relation.AGENT and agent_name:
        return f"{agent_name}, authorized agent for {profile.full_name}"
    return profile.full_name


def _subject(prefix: str, law: Law, reference: str) -> str:
    title = {
        "us_ca": "CCPA Request to Delete and Opt Out",
        "us_state": "Consumer Privacy Request to Delete and Opt Out",
        "us_none": "Request to Delete My Personal Information",
        "generic": "Request to Delete My Personal Information",
        "gdpr": ("UK GDPR" if law.extra.get("uk") else "GDPR") + " Article 17 Erasure Request",
        "uk_gdpr": "UK GDPR Article 17 Erasure Request",
        "pipeda": "PIPEDA Request: Withdrawal of Consent and Deletion",
        "quebec": "Law 25 Request: Deletion and Withdrawal of Consent",
        "au_privacy": "Privacy Act Request: Direct Marketing Opt-Out and Deletion",
    }.get(law.key, "Privacy Request")
    return f"{prefix}{title} [Ref {reference}]"


def render_initial(
    profile: Profile, broker: Broker, reference: str, *, sent_on: date, listing_url: str | None = None,
    agent_name: str | None = None, law: Law | None = None,
) -> Letter:
    law = law or resolve_law(profile.country, profile.region)
    deadline = sent_on + timedelta(days=law.deadline_days)
    body = _env.get_template(f"{law.template}.j2").render(
        broker=broker, law=law, person=PersonView(profile), reference=reference,
        deadline=fmt_date(deadline), listing_url=listing_url,
        agent=_agent_context(profile, law), sender=_sender_name(profile, agent_name),
    )
    return Letter(subject=_subject("", law, reference), body=_tidy(body))


def render_followup(
    profile: Profile, broker: Broker, reference: str, *, original_date: date, original_body: str,
    followup_number: int, today: date, agent_name: str | None = None,
) -> Letter:
    law = resolve_law(profile.country, profile.region)
    deadline = original_date + timedelta(days=law.deadline_days)
    body = _env.get_template("followup.j2").render(
        broker=broker, law=law, reference=reference, original_date=fmt_date(original_date),
        original_body=original_body, followup_number=followup_number,
        days_left=(deadline - today).days, deadline=fmt_date(deadline),
        sender=_sender_name(profile, agent_name),
    )
    return Letter(subject=_subject("Follow-up: ", law, reference), body=_tidy(body))


def render_final_notice(
    profile: Profile, broker: Broker, reference: str, *, original_date: date, original_body: str,
    agent_name: str | None = None,
) -> Letter:
    law = resolve_law(profile.country, profile.region)
    deadline = original_date + timedelta(days=law.deadline_days)
    body = _env.get_template("final_notice.j2").render(
        broker=broker, law=law, reference=reference, original_date=fmt_date(original_date),
        original_body=original_body, deadline=fmt_date(deadline), sender=_sender_name(profile, agent_name),
    )
    return Letter(subject=_subject("Final notice: ", law, reference), body=_tidy(body))


def render_escalation(
    profile: Profile, broker: Broker, reference: str, *, to_address: str | None, original_date: date,
    timeline: list[dict[str, str]], followups: int, replies: int, regulator: Regulator | None = None,
) -> tuple[Regulator, str]:
    law = resolve_law(profile.country, profile.region)
    regulator = regulator or (law.regulators[0] if law.regulators else Regulator("Federal Trade Commission", "https://reportfraud.ftc.gov/"))
    deadline = original_date + timedelta(days=law.deadline_days)
    body = _env.get_template("escalation.j2").render(
        regulator=regulator, broker=broker, law=law, reference=reference, to_address=to_address,
        original_date=fmt_date(original_date), deadline=fmt_date(deadline), timeline=timeline,
        followups=followups, replies=replies, person=PersonView(profile),
    )
    return regulator, _tidy(body)


def render_agent_authorization(profile: Profile, agent_name: str) -> str:
    return _tidy(
        _env.get_template("agent_authorization.j2").render(
            subject_name=profile.full_name, agent_name=agent_name, emails=profile.emails, phones=profile.phones,
        )
    )


def _tidy(text: str) -> str:
    lines = [ln.rstrip() for ln in text.strip().splitlines()]
    out: list[str] = []
    for ln in lines:
        if ln == "" and out and out[-1] == "":
            continue
        out.append(ln)
    return "\n".join(out) + "\n"
