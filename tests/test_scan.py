import httpx
from sqlalchemy import select

from datacleaner.models import Broker, Finding, FindingKind, FindingStatus
from datacleaner.scan.brokers import check_brokers, check_listing
from datacleaner.scan.matcher import phone_formats, profile_terms, score_text
from datacleaner.scan.search import SearchResult, SearxngProvider, build_queries, run_search_scan


def test_matcher(profile):
    terms = profile_terms(profile)
    score, matched = score_text("Jane Doe, age 40, San Francisco, CA. Phone 415.555.0134", terms)
    assert set(matched) >= {"name", "city", "state", "phone"} and score >= 0.9
    # Location alone is not a match.
    assert score_text("Lovely day in San Francisco, CA", terms) == (0.0, [])
    # Alias counts as a name; email alone counts.
    assert "name" in score_text("Jane Smith of Oakland", terms)[1]
    assert score_text("contact jane.doe@example.com", terms)[1] == ["email"]
    # Word boundaries: "Jane Doerr" is someone else.
    assert "name" not in score_text("Jane Doerr", terms)[1]
    assert phone_formats("+1 (415) 555-0134")[0] == "415-555-0134"


def test_build_queries(profile):
    qs = build_queries(profile)
    assert '"Jane Doe" "San Francisco"' in qs
    assert '"Jane Doe" "California"' in qs
    assert '"jane.doe@example.com"' in qs
    assert '"415-555-0134"' in qs
    assert '"janedoe85"' in qs


class FakeProvider:
    name = "fake"

    def __init__(self, results):
        self.results = results
        self.queries = []

    def search(self, query):
        self.queries.append(query)
        return self.results


def test_search_scan_records_matching_results(session, profile, now):
    provider = FakeProvider([
        SearchResult("https://www.spokeo.com/Jane-Doe/California/San-Francisco", "Jane Doe, San Francisco CA | Spokeo", "Age 40, phone (415) 555-0134"),
        SearchResult("https://blog.example/post", "Jane Doe's recipe blog", "Hello from San Francisco"),
        SearchResult("https://news.example/weather", "Weather in San Francisco", "Sunny"),
    ])
    run = run_search_scan(session, profile, provider, now=now, delay=0)
    assert run.summary["findings"] == 2 and run.summary["new"] == 2
    spokeo = session.scalars(select(Finding).where(Finding.source == "spokeo")).one()
    assert spokeo.broker.slug == "spokeo" and spokeo.kind == FindingKind.SEARCH
    # Re-running doesn't duplicate.
    run2 = run_search_scan(session, profile, provider, now=now, delay=0)
    assert run2.summary["new"] == 0


def test_searxng_provider_parses_json():
    def handler(request):
        assert request.url.params["format"] == "json"
        return httpx.Response(200, json={"results": [{"url": "https://a.example", "title": "A", "content": "c", "engines": ["ddg"]}]})

    p = SearxngProvider("http://searxng:8080", client=httpx.Client(transport=httpx.MockTransport(handler)))
    [r] = p.search('"Jane Doe"')
    assert r.url == "https://a.example" and r.engine == "ddg"


def _client(pages):
    def handler(request):
        for needle, resp in pages.items():
            if needle in str(request.url):
                return resp
        return httpx.Response(404, text="nope")
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_check_listing_states(profile):
    found = _client({"x": httpx.Response(200, text="<h1>Jane Doe</h1><p>Lives in San Francisco, CA</p>")})
    assert check_listing(found, "https://x.example", profile).state == "found"
    blocked = _client({"x": httpx.Response(403, text="Just a moment...")})
    assert check_listing(blocked, "https://x.example", profile).state == "blocked"
    captcha = _client({"x": httpx.Response(200, text="<div class='cf-challenge'>verify you are human</div>")})
    assert check_listing(captcha, "https://x.example", profile).state == "blocked"
    none = _client({"x": httpx.Response(200, text="No results found for Jane Doe")})
    assert check_listing(none, "https://x.example", profile).state == "not_found"
    other = _client({"x": httpx.Response(200, text="John Smith, Denver")})
    assert check_listing(other, "https://x.example", profile).state == "not_found"


def test_check_brokers_tracks_removal(session, profile, now):
    target = session.scalars(select(Broker).where(Broker.slug == "fastpeoplesearch")).one()
    listing = httpx.Response(200, text="Jane Doe age 40 San Francisco CA")
    run = check_brokers(session, profile, client=_client({"fastpeoplesearch": listing}), broker_ids=[target.id], now=now, delay=0)
    assert run.summary["found"] == 1
    f = session.scalars(select(Finding).where(Finding.kind == FindingKind.LISTING)).one()
    assert f.check_state == "found" and f.url.endswith("/name/jane-doe_san-francisco-ca")
    f.status = FindingStatus.REMOVAL_REQUESTED
    run = check_brokers(session, profile, client=_client({}), broker_ids=[target.id], now=now, delay=0)
    assert run.summary["removed"] == 1 and f.status == FindingStatus.REMOVED
    # It came back: reopened as new.
    check_brokers(session, profile, client=_client({"fastpeoplesearch": listing}), broker_ids=[target.id], now=now, delay=0)
    assert f.status == FindingStatus.NEW


def test_check_brokers_skips_other_regions(session, now):
    from .conftest import make_profile

    uk = make_profile(session, country="GB", region=None)
    run = check_brokers(session, uk, client=_client({}), now=now, delay=0)
    assert run.summary["checked"] == 0


def test_found_beats_embedded_captcha(profile):
    page = _client({"x": httpx.Response(200, text="<script src='recaptcha.js'></script>captcha<h1>Jane Doe</h1> San Francisco, CA")})
    assert check_listing(page, "https://x.example", profile).state == "found"
