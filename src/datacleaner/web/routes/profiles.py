from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...jurisdictions import AU_STATES, CANADA_PROVINCES, COUNTRY_NAMES, US_STATE_NAMES, resolve_law, supports_drop
from ...models import Profile, Relation, User, utcnow
from ...removal.letters import render_agent_authorization
from ...settings import Settings
from ..deps import current_user, flash, get_db, redirect, render

router = APIRouter(prefix="/profiles")

REGION_CHOICES = {"US": US_STATE_NAMES, "CA": CANADA_PROVINCES, "AU": AU_STATES}


def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in re.split(r"[\n,;]+", text or "") if ln.strip()]


def _parse_prev_addresses(text: str, country: str) -> list[dict]:
    out = []
    for line in (text or "").splitlines():
        parts = [p.strip() for p in line.split(",") if p.strip()]
        if not parts:
            continue
        a = {"street": "", "city": "", "region": "", "postal_code": "", "country": country, "current": False}
        if len(parts) >= 4:
            a.update(street=parts[0], city=parts[1], region=parts[2].upper(), postal_code=parts[3])
        elif len(parts) == 3:
            a.update(street=parts[0], city=parts[1], region=parts[2].upper())
        elif len(parts) == 2:
            a.update(city=parts[0], region=parts[1].upper())
        else:
            a.update(city=parts[0])
        out.append(a)
    return out


def _form_ctx(profile: Profile | None) -> dict:
    pii = (profile.pii if profile else {}) or {}
    cur = (profile.current_address if profile else None) or {}
    prev = [a for a in (profile.addresses if profile else []) if not a.get("current")]
    return {
        "profile": profile, "pii": pii, "cur": cur,
        "prev_text": "\n".join(", ".join(x for x in [a.get("street"), a.get("city"), a.get("region"), a.get("postal_code")] if x) for a in prev),
        "countries": COUNTRY_NAMES, "region_choices": REGION_CHOICES,
    }


@router.get("")
def list_profiles(request: Request, db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    profiles = db.scalars(select(Profile).order_by(Profile.id)).all()
    return render(request, db, "profiles.html", profiles=profiles, resolve_law=resolve_law)


@router.get("/new")
def new_profile(request: Request, db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    return render(request, db, "profile_form.html", **_form_ctx(None))


@router.get("/{profile_id}")
def edit_profile(profile_id: int, request: Request, db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    profile = db.get(Profile, profile_id)
    if not profile:
        raise HTTPException(404)
    law = resolve_law(profile.country, profile.region)
    return render(request, db, "profile_form.html", law=law, drop=supports_drop(profile.country, profile.region), **_form_ctx(profile))


@router.post("/save")
def save_profile(
    request: Request,
    profile_id: int | None = Form(None),
    label: str = Form(...),
    relation: str = Form(Relation.SELF),
    country: str = Form("US"),
    region_US: str = Form(""),
    region_CA: str = Form(""),
    region_AU: str = Form(""),
    region_other: str = Form(""),
    first_name: str = Form(...),
    middle_name: str = Form(""),
    last_name: str = Form(...),
    aliases: str = Form(""),
    birth_date: str = Form(""),
    share_birth_date: bool = Form(False),
    emails: str = Form(""),
    phones: str = Form(""),
    street: str = Form(""),
    city: str = Form(""),
    postal_code: str = Form(""),
    previous_addresses: str = Form(""),
    usernames: str = Form(""),
    attest: bool = Form(False),
    agent_authorization_on_file: bool = Form(False),
    monitoring_enabled: bool = Form(False),
    db: Session = Depends(get_db, scope="function"),
    user: User = Depends(current_user),
):
    if not attest:
        flash(request, "Please confirm that this is you, or someone who has authorized you to act for them.", "error")
        return redirect(f"/profiles/{profile_id}" if profile_id else "/profiles/new")
    profile = db.get(Profile, profile_id) if profile_id else None
    if profile is None:
        profile = Profile(owner_id=user.id)
        db.add(profile)
    country = (country or "US").upper()[:2]
    region_raw = {"US": region_US, "CA": region_CA, "AU": region_AU}.get(country, region_other)
    region = (region_raw or "").strip().upper()[:10] or None
    if country in REGION_CHOICES and region and region not in REGION_CHOICES[country]:
        region = None
    addresses = []
    if street or city or postal_code:
        addresses.append({"street": street.strip(), "city": city.strip(), "region": region or "",
                          "postal_code": postal_code.strip(), "country": country, "current": True})
    addresses += _parse_prev_addresses(previous_addresses, country)
    profile.label = label.strip()[:120] or f"{first_name} {last_name}"
    profile.relation = Relation.AGENT if relation == Relation.AGENT else Relation.SELF
    profile.country = country
    profile.region = region
    profile.pii = {
        "first_name": first_name.strip(), "middle_name": middle_name.strip(), "last_name": last_name.strip(),
        "aliases": _lines(aliases), "birth_date": birth_date.strip(), "share_birth_date": bool(share_birth_date),
        "emails": [e.lower() for e in _lines(emails)], "phones": _lines(phones), "addresses": addresses,
        "usernames": _lines(usernames),
    }
    profile.attested_at = utcnow()
    profile.agent_authorization_on_file = bool(agent_authorization_on_file)
    profile.monitoring_enabled = bool(monitoring_enabled)
    db.flush()
    request.session["profile_id"] = profile.id
    if profile.relation == Relation.AGENT and not profile.agent_authorization_on_file:
        flash(request, "Download the authorization letter, have them sign it, and keep it on file before sending requests.", "warn")
    flash(request, f"Saved {profile.label}.", "success")
    if not profile_id:
        return redirect(f"/requests/new?profile_id={profile.id}")
    return redirect(f"/profiles/{profile.id}")


@router.post("/{profile_id}/delete")
def delete_profile(profile_id: int, request: Request, db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    profile = db.get(Profile, profile_id)
    if profile:
        db.delete(profile)
        request.session.pop("profile_id", None)
        flash(request, "Profile and all its requests and findings were deleted.", "success")
    return redirect("/profiles")


@router.get("/{profile_id}/authorization.txt")
def authorization_letter(profile_id: int, db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    profile = db.get(Profile, profile_id)
    if not profile:
        raise HTTPException(404)
    agent = Settings(db).from_name or user.username
    text = render_agent_authorization(profile, agent)
    return PlainTextResponse(text, headers={"Content-Disposition": f'attachment; filename="authorization-{profile.id}.txt"'})
