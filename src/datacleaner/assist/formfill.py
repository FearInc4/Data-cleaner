"""Human-in-the-loop opt-out form filling (optional; needs `pip install datacleaner[browser]`).

Opens the broker's opt-out page in a visible Chromium window, fills every field
it can recognise from the profile, then hands control to you: solve the
CAPTCHA, check the values, and press Submit yourself. When you close the
window, the request is marked as submitted.

Field detection is heuristic (label/name/placeholder/autocomplete text), so it
works on most forms without per-site scripts.
"""

from __future__ import annotations

import re

from ..jurisdictions import US_STATE_NAMES
from ..models import Profile

FIELD_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"e-?mail", re.I)),
    ("first_name", re.compile(r"first|given|fname|forename", re.I)),
    ("middle_name", re.compile(r"middle", re.I)),
    ("last_name", re.compile(r"last|surname|family|lname", re.I)),
    ("full_name", re.compile(r"^(full ?)?name$|your name|full_?name", re.I)),
    ("phone", re.compile(r"phone|mobile|tel", re.I)),
    ("street", re.compile(r"street|address ?(line)? ?1?$|addr1|address$", re.I)),
    ("city", re.compile(r"city|town|locality", re.I)),
    ("state", re.compile(r"state|province|region", re.I)),
    ("zip", re.compile(r"zip|postal|postcode", re.I)),
    ("url", re.compile(r"url|link|profile|listing|record", re.I)),
    ("dob", re.compile(r"birth|dob", re.I)),
]


def values_for(profile: Profile, listing_url: str | None, *, email: str | None = None) -> dict[str, str]:
    addr = profile.current_address or {}
    state = (addr.get("region") or profile.region or "").upper()
    vals = {
        "email": email or profile.contact_email or "",
        "first_name": profile.get("first_name") or "",
        "middle_name": profile.get("middle_name") or "",
        "last_name": profile.get("last_name") or "",
        "full_name": profile.short_name,
        "phone": (profile.phones or [""])[0],
        "street": addr.get("street") or "",
        "city": addr.get("city") or "",
        "state": state,
        "state_name": US_STATE_NAMES.get(state, state),
        "zip": addr.get("postal_code") or "",
        "url": listing_url or "",
        "dob": profile.get("birth_date") or "" if profile.get("share_birth_date") else "",
    }
    return {k: v for k, v in vals.items() if v}


def classify_field(descriptor: str) -> str | None:
    for key, pat in FIELD_PATTERNS:
        if pat.search(descriptor):
            return key
    return None


# JavaScript run in the page: describe each visible input so Python can decide what goes where.
_DESCRIBE_JS = """
() => Array.from(document.querySelectorAll('input, select, textarea')).map((el, i) => {
  const r = el.getBoundingClientRect();
  const label = (el.labels && el.labels[0] && el.labels[0].innerText) || '';
  el.setAttribute('data-dc-idx', String(i));
  return {idx: i, tag: el.tagName.toLowerCase(), type: (el.type || '').toLowerCase(),
          name: el.name || '', id: el.id || '', placeholder: el.placeholder || '',
          autocomplete: el.autocomplete || '', aria: el.getAttribute('aria-label') || '', label,
          visible: r.width > 0 && r.height > 0, value: el.value || ''};
})
"""


def run_assisted(url: str, values: dict[str, str], *, headless: bool = False, timeout_minutes: int = 15) -> dict[str, int]:
    """Open the page, fill what we can, wait for the human to close the window."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("Assisted mode needs Playwright: pip install 'datacleaner[browser]'") from exc

    filled = 0
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        page = browser.new_page()
        page.goto(url, wait_until="domcontentloaded")
        page.wait_for_timeout(1500)
        for field in page.evaluate(_DESCRIBE_JS):
            if not field["visible"] or field["value"] or field["type"] in ("hidden", "submit", "button", "checkbox", "radio", "file", "password"):
                continue
            desc = " ".join(field[k] for k in ("label", "name", "id", "placeholder", "autocomplete", "aria"))
            key = "email" if field["type"] == "email" else ("phone" if field["type"] == "tel" else classify_field(desc))
            if key is None:
                continue
            value = values.get(key)
            if key == "state" and field["tag"] == "select":
                selector = f'[data-dc-idx="{field["idx"]}"]'
                for candidate in (values.get("state"), values.get("state_name")):
                    if not candidate:
                        continue
                    try:
                        page.select_option(selector, label=candidate)
                        filled += 1
                        break
                    except Exception:
                        try:
                            page.select_option(selector, value=candidate)
                            filled += 1
                            break
                        except Exception:
                            continue
                continue
            if not value or field["tag"] == "select":
                continue
            page.fill(f'[data-dc-idx="{field["idx"]}"]', value)
            filled += 1
        page.evaluate(
            "() => { const d = document.createElement('div'); d.textContent = 'Data Cleaner filled what it could. "
            "Check the fields, solve any CAPTCHA, press Submit, then close this window.';"
            "d.style.cssText='position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#1f6feb;color:#fff;"
            "padding:10px;font:14px sans-serif;text-align:center'; document.body.appendChild(d); }"
        )
        if not headless:
            try:
                page.wait_for_event("close", timeout=timeout_minutes * 60 * 1000)
            except Exception:
                pass
        browser.close()
    return {"filled": filled}
