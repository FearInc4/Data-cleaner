from datetime import date

import pytest
from sqlalchemy import select

from datacleaner.jurisdictions import broker_serves, resolve_law, supports_drop
from datacleaner.models import Broker, Relation
from datacleaner.removal import letters

from .conftest import make_profile


@pytest.mark.parametrize("country,region,key,days,regulator", [
    ("US", "CA", "us_ca", 45, "California Privacy Protection Agency"),
    ("US", "TX", "us_state", 45, "Texas Attorney General"),
    ("US", "WY", "us_none", 45, "Federal Trade Commission"),
    ("FR", None, "gdpr", 30, "Commission nationale de l'informatique et des libertés (CNIL)"),
    ("HR", None, "gdpr", 30, "your national data protection authority"),
    ("GB", None, "uk_gdpr", 30, "Information Commissioner's Office (ICO)"),
    ("CA", "QC", "quebec", 30, "Commission d'accès à l'information du Québec"),
    ("CA", "ON", "pipeda", 30, "Office of the Privacy Commissioner of Canada"),
    ("AU", "NSW", "au_privacy", 30, "Office of the Australian Information Commissioner (OAIC)"),
])
def test_resolve_law(country, region, key, days, regulator):
    law = resolve_law(country, region)
    assert law.key == key
    assert law.deadline_days == days
    assert law.regulators[0].name == regulator


def test_drop_and_broker_regions():
    assert supports_drop("US", "CA") and not supports_drop("US", "NV") and not supports_drop("CA", "ON")
    assert broker_serves(["US"], "US") and not broker_serves(["US"], "FR")
    assert broker_serves(["EU"], "DE") and broker_serves(["UK"], "GB") and broker_serves(["*"], "AU")


@pytest.mark.parametrize("country,region,needle", [
    ("US", "CA", "§ 1798.105"),
    ("US", "VA", "Virginia Consumer Data Protection Act"),
    ("US", "WY", "Many companies extend these rights"),
    ("DE", None, "Article 17 GDPR"),
    ("GB", None, "Article 17 UK GDPR"),
    ("CA", "QC", "section 28.1"),
    ("CA", "BC", "Principle 4.3.8"),
    ("AU", "VIC", "APP 7.6"),
])
def test_initial_letters_render(session, country, region, needle):
    p = make_profile(session, country=country, region=region)
    broker = session.scalars(select(Broker).where(Broker.slug == "spokeo")).one()
    letter = letters.render_initial(p, broker, "DC-ABCDEFGH", sent_on=date(2026, 3, 2),
                                    listing_url="https://www.spokeo.com/Jane-Doe/x")
    assert needle in letter.body
    assert "[Ref DC-ABCDEFGH]" in letter.subject
    assert "Jane Q Doe" in letter.body
    assert "jane.doe@example.com" in letter.body
    assert "Previous address: 9 Old Rd" in letter.body
    assert "My record on your site: https://www.spokeo.com/Jane-Doe/x" in letter.body
    # Date of birth is withheld unless the person opted in.
    assert "1985-04-12" not in letter.body
    assert "\n\n\n" not in letter.body
    law = resolve_law(country, region)
    expected = {45: "April 16, 2026", 30: "April 1, 2026"}[law.deadline_days]
    assert expected in letter.body


def test_birth_date_shared_when_opted_in(session):
    p = make_profile(session, share_birth_date=True)
    broker = session.scalars(select(Broker).where(Broker.slug == "spokeo")).one()
    assert "Date of birth: 1985-04-12" in letters.render_initial(p, broker, "DC-ABCDEFGH", sent_on=date(2026, 3, 2)).body


def test_agent_letter_and_authorization(session):
    p = make_profile(session, relation=Relation.AGENT)
    broker = session.scalars(select(Broker).where(Broker.slug == "mylife")).one()
    letter = letters.render_initial(p, broker, "DC-ABCDEFGH", sent_on=date(2026, 3, 2), agent_name="Sam Doe")
    assert "authorized agent of Jane Q Doe" in letter.body
    assert "Cal. Civ. Code § 1798.135" in letter.body
    assert letter.body.rstrip().endswith("Sam Doe, authorized agent for Jane Q Doe")
    auth = letters.render_agent_authorization(p, "Sam Doe")
    assert "I, Jane Q Doe, authorize Sam Doe" in auth and "Signature:" in auth


def test_followup_final_and_escalation(session):
    p = make_profile(session)
    broker = session.scalars(select(Broker).where(Broker.slug == "mylife")).one()
    f = letters.render_followup(p, broker, "DC-ABCDEFGH", original_date=date(2026, 3, 2), original_body="ORIGINAL",
                                followup_number=2, today=date(2026, 3, 27))
    assert f.subject.startswith("Follow-up: ") and "20 days left" in f.body and "ORIGINAL" in f.body
    final = letters.render_final_notice(p, broker, "DC-ABCDEFGH", original_date=date(2026, 3, 2), original_body="ORIGINAL")
    assert "California Privacy Protection Agency and California Attorney General" in final.body
    reg, draft = letters.render_escalation(p, broker, "DC-ABCDEFGH", to_address="privacy@mylife.com",
                                           original_date=date(2026, 3, 2), timeline=[{"at": "2026-03-02", "summary": "Sent"}],
                                           followups=3, replies=0)
    assert reg.url.startswith("https://cppa.ca.gov")
    assert "has not responded" in draft and "- 2026-03-02: Sent" in draft
