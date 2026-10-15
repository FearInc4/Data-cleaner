from __future__ import annotations

from datetime import datetime

import pytest

from datacleaner import app_state
from datacleaner.config import Config
from datacleaner.db import new_session
from datacleaner.models import Profile, Relation


@pytest.fixture()
def config(tmp_path):
    cfg = Config(data_dir=tmp_path, scheduler_enabled=False)
    app_state.init(cfg)
    return cfg


@pytest.fixture()
def session(config):
    s = new_session()
    yield s
    s.rollback()
    s.close()


@pytest.fixture()
def now():
    return datetime(2026, 3, 2, 12, 0, 0)


def make_profile(session, *, country="US", region="CA", relation=Relation.SELF, **pii) -> Profile:
    data = {
        "first_name": "Jane", "middle_name": "Q", "last_name": "Doe",
        "aliases": ["Jane Smith"], "birth_date": "1985-04-12", "share_birth_date": False,
        "emails": ["jane.doe@example.com"], "phones": ["(415) 555-0134"],
        "addresses": [
            {"street": "1 Market St", "city": "San Francisco", "region": region, "postal_code": "94105", "country": country, "current": True},
            {"street": "9 Old Rd", "city": "Oakland", "region": region, "postal_code": "94601", "country": country, "current": False},
        ],
        "usernames": ["janedoe85"],
    }
    data.update(pii)
    p = Profile(label="Me", relation=relation, country=country, region=region, pii=data, attested_at=datetime(2026, 1, 1))
    session.add(p)
    session.flush()
    return p


@pytest.fixture()
def profile(session):
    return make_profile(session)
