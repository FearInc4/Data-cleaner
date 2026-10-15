from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...models import User
from ...security import hash_password, verify_password
from ..deps import flash, get_db, redirect, render

router = APIRouter()

# Simple brute-force brake: 5 failures per username+IP per 15 minutes.
_failures: dict[tuple[str, str], list[float]] = {}
MAX_FAILURES, WINDOW_SECONDS = 5, 15 * 60


def _throttled(key: tuple[str, str]) -> bool:
    now = time.monotonic()
    recent = [t for t in _failures.get(key, []) if now - t < WINDOW_SECONDS]
    _failures[key] = recent
    return len(recent) >= MAX_FAILURES


def _user_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User)) or 0


@router.get("/setup")
def setup_page(request: Request, db: Session = Depends(get_db)):
    if _user_count(db):
        return redirect("/login")
    return render(request, db, "setup.html")


@router.post("/setup")
def setup_submit(request: Request, username: str = Form(...), password: str = Form(...), password2: str = Form(...),
                 db: Session = Depends(get_db)):
    if _user_count(db):
        return redirect("/login")
    if len(password) < 10:
        flash(request, "Use at least 10 characters for the password.", "error")
        return redirect("/setup")
    if password != password2:
        flash(request, "Passwords don't match.", "error")
        return redirect("/setup")
    user = User(username=username.strip()[:80] or "admin", password_hash=hash_password(password))
    db.add(user)
    db.flush()
    request.session.clear()
    request.session["uid"] = user.id
    flash(request, "Welcome! Start by adding the person whose data you want to clean up.", "success")
    return redirect("/profiles/new")


@router.get("/login")
def login_page(request: Request, db: Session = Depends(get_db)):
    if not _user_count(db):
        return redirect("/setup")
    return render(request, db, "login.html")


@router.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    key = (username.strip().lower(), request.client.host if request.client else "")
    if _throttled(key):
        flash(request, "Too many failed attempts. Wait 15 minutes and try again.", "error")
        return redirect("/login")
    user = db.scalars(select(User).where(User.username == username.strip())).first()
    if not user or not verify_password(password, user.password_hash):
        _failures.setdefault(key, []).append(time.monotonic())
        flash(request, "Wrong username or password.", "error")
        return redirect("/login")
    _failures.pop(key, None)
    request.session.clear()
    request.session["uid"] = user.id
    return redirect("/")


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/login")
