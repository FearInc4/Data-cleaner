"""Decide whether a piece of web text is about this person, and how sure we are."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..jurisdictions import US_STATE_NAMES
from ..models import Profile


def digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")


def national_number(phone: str) -> str:
    d = digits(phone)
    if len(d) == 11 and d.startswith("1"):
        d = d[1:]
    return d


def phone_formats(phone: str) -> list[str]:
    d = national_number(phone)
    if len(d) != 10:
        return [phone] if phone else []
    a, b, c = d[:3], d[3:6], d[6:]
    return [f"{a}-{b}-{c}", f"({a}) {b}-{c}", f"{a}.{b}.{c}", d]


@dataclass
class Terms:
    names: list[str]
    cities: list[str]
    states: list[str]
    phones: list[str]  # national digits
    emails: list[str]
    usernames: list[str]
    birth_year: str | None


def profile_terms(profile: Profile) -> Terms:
    names = []
    if profile.short_name:
        names.append(profile.short_name)
    if profile.full_name and profile.full_name != profile.short_name:
        names.append(profile.full_name)
    names += [a for a in profile.get("aliases", []) if a]
    cities, states = [], []
    for a in profile.addresses:
        if a.get("city"):
            cities.append(a["city"])
        if a.get("region"):
            states.append(a["region"].upper())
    bd = profile.get("birth_date") or ""
    return Terms(
        names=names,
        cities=sorted(set(cities)),
        states=sorted(set(states)),
        phones=[national_number(p) for p in profile.phones if len(national_number(p)) >= 7],
        emails=[e.lower() for e in profile.emails],
        usernames=[u for u in profile.get("usernames", []) if u],
        birth_year=bd[:4] if re.match(r"\d{4}", bd) else None,
    )


def _has_word(text: str, phrase: str) -> bool:
    if not phrase:
        return False
    pattern = r"(?<![A-Za-z0-9])" + r"\s+".join(re.escape(p) for p in phrase.split()) + r"(?![A-Za-z0-9])"
    return re.search(pattern, text, re.I) is not None


def score_text(text: str, terms: Terms) -> tuple[float, list[str]]:
    matched: list[str] = []
    score = 0.0
    if any(_has_word(text, n) for n in terms.names):
        matched.append("name")
        score += 0.4
    if any(_has_word(text, c) for c in terms.cities):
        matched.append("city")
        score += 0.2
    for st in terms.states:
        if _has_word(text, US_STATE_NAMES.get(st, "")) or re.search(rf"(?<![A-Za-z]){st}(?![A-Za-z])", text):
            matched.append("state")
            score += 0.1
            break
    text_digits = set(re.findall(r"\d[\d\-\.\s\(\)]{6,}\d", text))
    nums = {national_number(t) for t in text_digits}
    if any(p in nums for p in terms.phones):
        matched.append("phone")
        score += 0.3
    low = text.lower()
    if any(e in low for e in terms.emails):
        matched.append("email")
        score += 0.4
    if any(_has_word(text, u) for u in terms.usernames):
        matched.append("username")
        score += 0.2
    if terms.birth_year and terms.birth_year in text:
        matched.append("birth_year")
        score += 0.1
    # A location without a name or contact detail is not evidence of anything.
    if not {"name", "phone", "email", "username"} & set(matched):
        return 0.0, []
    return min(score, 1.0), matched
