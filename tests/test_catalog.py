import pytest
from sqlalchemy import select

from datacleaner.brokers import (
    BrokerSpec,
    CatalogError,
    host_matches,
    load_catalog,
    registrable_domain,
    render_search_url,
    search_values_for,
    sync_catalog,
)
from datacleaner.brokers.registry_import import import_registry_csv, map_columns
from datacleaner.models import Broker


def test_catalog_loads_and_is_valid():
    specs = load_catalog()
    assert len(specs) >= 50
    slugs = [s.slug for s in specs]
    assert len(slugs) == len(set(slugs))
    for s in specs:
        assert s.domains, s.slug
        if "email" in s.methods:
            assert "@" in s.privacy_email


def test_catalog_validation_rejects_bad_entries():
    with pytest.raises(CatalogError):
        BrokerSpec.from_dict({"slug": "x", "name": "X", "methods": ["email"]})  # email w/o address
    with pytest.raises(CatalogError):
        BrokerSpec.from_dict({"slug": "x", "name": "X", "website": "http://insecure.example"})
    with pytest.raises(CatalogError):
        BrokerSpec.from_dict({"slug": "x", "name": "X", "bogus": 1})


def test_sync_is_idempotent(session):
    first = sync_catalog(session)  # app_state already synced once
    second = sync_catalog(session)
    assert first["created"] == 0 and second["created"] == 0
    assert session.scalar(select(Broker).where(Broker.slug == "spokeo")).name == "Spokeo"


def test_domains():
    assert registrable_domain("https://www.fastpeoplesearch.com/name/x") == "fastpeoplesearch.com"
    assert registrable_domain("https://www.192.com/") == "192.com"
    assert registrable_domain("https://shop.example.co.uk/a") == "example.co.uk"
    assert host_matches("mailer.intelius.com", ["intelius.com"])
    assert not host_matches("intelius.com.evil.net", ["intelius.com"])


def test_search_url_rendering(profile):
    values = search_values_for(profile)
    assert values["state_name"] == "California"
    url = render_search_url("https://www.fastpeoplesearch.com/name/{first:slug}-{last:slug}_{city:slug}-{state:slug}", values)
    assert url == "https://www.fastpeoplesearch.com/name/jane-doe_san-francisco-ca"
    url = render_search_url("https://www.spokeo.com/{First:Slug}-{Last:Slug}/{state_name:Slug}/{city:Slug}", values)
    assert url == "https://www.spokeo.com/Jane-Doe/California/San-Francisco"
    url = render_search_url("https://x.example/s?name={first:q}%20{last:q}&st={state:upper}", values)
    assert url == "https://x.example/s?name=Jane%20Doe&st=CA"
    assert render_search_url("https://x.example/{zip}/{middle}", {"zip": "1"}) is None


CA_CSV = """Data broker name,Email address,Website URL,"How a consumer may exercise their privacy rights, including deletion (URL)",Data broker primary physical address
Acme People Finder LLC,privacy@acmepeople.example,https://www.acmepeople.example,https://www.acmepeople.example/delete,"1 Main St, Reno NV"
Spokeo Inc,privacy@spokeo.com,https://www.spokeo.com,https://www.spokeo.com/privacy-request,"Pasadena CA"
,,,,
Bare Domain Data,contact us at rights@bare.example please,bare.example,,
"""


def test_registry_column_mapping():
    cols = map_columns(["Data broker name", "Email address", "Website URL",
                        "How a consumer may exercise their privacy rights, including deletion (URL)", "Data broker primary physical address"])
    assert cols.name == "Data broker name"
    assert cols.email == "Email address"
    assert cols.website == "Website URL"
    assert cols.optout.startswith("How a consumer")


def test_registry_import_creates_and_merges(session):
    spokeo_before = session.scalars(select(Broker).where(Broker.slug == "spokeo")).one()
    assert spokeo_before.privacy_email is None
    result = import_registry_csv(session, CA_CSV.encode(), "CA")
    assert result.created == 2 and result.updated == 1 and result.skipped == 1
    acme = session.scalars(select(Broker).where(Broker.slug == "acmepeople-example")).one()
    assert acme.privacy_email == "privacy@acmepeople.example"
    assert acme.opt_out_url == "https://www.acmepeople.example/delete"
    assert set(acme.methods) == {"email", "form"}
    assert acme.registries == ["CA"]
    spokeo = session.scalars(select(Broker).where(Broker.slug == "spokeo")).one()
    # Curated opt-out URL is kept; the registry only fills the missing email.
    assert spokeo.opt_out_url == "https://www.spokeo.com/optout"
    assert spokeo.privacy_email == "privacy@spokeo.com"
    assert "CA" in spokeo.registries
    bare = session.scalars(select(Broker).where(Broker.slug == "bare-example")).one()
    assert bare.website == "https://bare.example" and bare.privacy_email == "rights@bare.example"
    # Re-import doesn't duplicate.
    again = import_registry_csv(session, CA_CSV, "CA")
    assert again.created == 0


def test_registry_import_reports_unusable_file(session):
    result = import_registry_csv(session, "foo,bar\n1,2\n", "VT")
    assert result.errors
