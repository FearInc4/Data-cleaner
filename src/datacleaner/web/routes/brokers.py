from __future__ import annotations

import re

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ...brokers import registrable_domain, render_search_url, search_values_for
from ...brokers.registry_import import import_registry_csv
from ...models import Broker, BrokerCategory, User
from ..deps import current_user, flash, get_db, redirect, render, selected_profile

router = APIRouter(prefix="/brokers")


@router.get("")
def list_brokers(request: Request, q: str = "", category: str = "", method: str = "", source: str = "",
                 db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    stmt = select(Broker).where(Broker.active.is_(True))
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(Broker.name.ilike(like), Broker.website.ilike(like), Broker.slug.ilike(like)))
    if category:
        stmt = stmt.where(Broker.category == category)
    if source == "catalog":
        stmt = stmt.where(Broker.source == "catalog")
    elif source == "registry":
        stmt = stmt.where(Broker.source != "catalog")
    brokers = db.scalars(stmt.order_by(Broker.priority, Broker.name)).all()
    if method:
        brokers = [b for b in brokers if method in (b.methods or [])]
    return render(request, db, "brokers.html", brokers=brokers, q=q, category=category, method=method, source=source,
                  categories=BrokerCategory.ALL)


@router.get("/import")
def import_page(request: Request, db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    return render(request, db, "broker_import.html")


@router.post("/import")
async def import_submit(request: Request, registry: str = Form(...), file: UploadFile = File(...),
                        db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    data = await file.read()
    if len(data) > 20 * 1024 * 1024:
        flash(request, "That file is too large (20 MB max).", "error")
        return redirect("/brokers/import")
    result = import_registry_csv(db, data, registry)
    if result.errors:
        for e in result.errors:
            flash(request, e, "error")
    else:
        flash(request, f"Imported {registry} registry: {result.created} new brokers, {result.updated} updated, {result.skipped} skipped.", "success")
    return redirect("/brokers?source=registry")


@router.get("/new")
def new_broker(request: Request, db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    return render(request, db, "broker_new.html", categories=BrokerCategory.ALL)


@router.post("/new")
def create_broker(request: Request, name: str = Form(...), website: str = Form(""), privacy_email: str = Form(""),
                  opt_out_url: str = Form(""), category: str = Form(BrokerCategory.OTHER), notes: str = Form(""),
                  db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    slug = re.sub(r"[^a-z0-9]+", "-", (registrable_domain(website) if website else name).lower()).strip("-")[:100]
    if db.scalars(select(Broker).where(Broker.slug == slug)).first():
        flash(request, "A broker with that name/domain already exists.", "error")
        return redirect(f"/brokers?q={name}")
    methods = []
    if privacy_email.strip():
        methods.append("email")
    if opt_out_url.strip():
        methods.append("form")
    b = Broker(slug=slug, name=name.strip(), website=website.strip() or None,
               domains=[registrable_domain(website)] if website else [],
               category=category if category in BrokerCategory.ALL else BrokerCategory.OTHER, regions=["*"], priority=3,
               privacy_email=privacy_email.strip() or None, opt_out_url=opt_out_url.strip() or None, methods=methods,
               requires=[], owns=[], steps=[], notes=notes.strip() or None, source="user", registries=[])
    db.add(b)
    db.flush()
    flash(request, f"Added {b.name}.", "success")
    return redirect(f"/brokers/{b.slug}")


@router.get("/{slug}")
def broker_detail(slug: str, request: Request, db: Session = Depends(get_db, scope="function"), user: User = Depends(current_user)):
    broker = db.scalars(select(Broker).where(Broker.slug == slug)).first()
    if not broker:
        raise HTTPException(404)
    profile = selected_profile(request, db, None)
    search_link = None
    if profile and broker.search_url:
        search_link = render_search_url(broker.search_url, search_values_for(profile))
    return render(request, db, "broker_detail.html", broker=broker, profile=profile, search_link=search_link)
