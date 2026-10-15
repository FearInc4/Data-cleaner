"""Runtime settings stored in the database (editable on the Settings page)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from .crypto import get_vault
from .models import Setting


@dataclass(frozen=True)
class SettingDef:
    key: str
    default: Any
    kind: str = "str"  # str, int, bool, secret (encrypted, hidden), private (encrypted, shown), choice
    label: str = ""
    help: str = ""
    group: str = "General"
    choices: tuple[str, ...] = ()


DEFS: list[SettingDef] = [
    # Outgoing mail
    SettingDef("smtp_host", "", label="SMTP host", group="Email (sending)", help="e.g. smtp.gmail.com, smtp.fastmail.com"),
    SettingDef("smtp_port", 587, "int", "SMTP port", group="Email (sending)"),
    SettingDef("smtp_security", "starttls", "choice", "SMTP security", group="Email (sending)", choices=("starttls", "ssl", "none")),
    SettingDef("smtp_username", "", "private", label="SMTP username", group="Email (sending)"),
    SettingDef("smtp_password", "", "secret", "SMTP password / app password", group="Email (sending)",
               help="Use an app password, not your main password."),
    SettingDef("from_address", "", "private", label="From address", group="Email (sending)",
               help="Requests are sent from and replies come back to this address. A dedicated privacy alias is ideal."),
    SettingDef("from_name", "", "private", label="From name", group="Email (sending)"),
    # Incoming mail
    SettingDef("imap_host", "", label="IMAP host", group="Email (reading replies)", help="e.g. imap.gmail.com"),
    SettingDef("imap_port", 993, "int", "IMAP port", group="Email (reading replies)"),
    SettingDef("imap_username", "", "private", label="IMAP username", group="Email (reading replies)"),
    SettingDef("imap_password", "", "secret", "IMAP password / app password", group="Email (reading replies)"),
    SettingDef("imap_folder", "INBOX", label="Folder to watch", group="Email (reading replies)"),
    # Per-broker addresses
    SettingDef("alias_mode", "plus", "choice", "Give each broker its own address", group="Per-broker addresses",
               choices=("plus", "catchall", "off"),
               help="plus: you+dc-spokeo-1@gmail.com (works with Gmail, Outlook, iCloud, Fastmail…). catchall: dc-spokeo-1@yourdomain. off: your plain address."),
    SettingDef("alias_domain", "", "private", label="Catch-all domain", group="Per-broker addresses",
               help="Only for catchall mode: a domain whose catch-all delivers to your connected mailbox."),
    # Sign-in apps (OAuth clients)
    SettingDef("google_client_id", "", label="Google OAuth client ID", group="Sign-in apps"),
    SettingDef("google_client_secret", "", "secret", "Google OAuth client secret", group="Sign-in apps"),
    SettingDef("microsoft_client_id", "", label="Microsoft application (client) ID", group="Sign-in apps"),
    SettingDef("microsoft_client_secret", "", "secret", "Microsoft client secret value", group="Sign-in apps"),
    # Removal engine
    SettingDef("auto_approve", False, "bool", "Queue new email requests immediately", group="Removal requests",
               help="Off: new requests wait as drafts until you press Send."),
    SettingDef("auto_click_verification", True, "bool", "Auto-open verification links from brokers", group="Removal requests",
               help="Only links on the broker's own domains are ever opened."),
    SettingDef("rate_limit_per_hour", 20, "int", "Max emails per hour", group="Removal requests"),
    SettingDef("followup_days", "10,25", label="Follow-up schedule (days after first send)", group="Removal requests",
               help="Comma-separated. A final notice is always sent at the statutory deadline."),
    SettingDef("repeat_days", 30, "int", "Reminder interval once overdue (days)", group="Removal requests"),
    SettingDef("max_followups", 6, "int", "Stop after this many follow-ups", group="Removal requests"),
    SettingDef("recheck_days", 90, "int", "Re-check a broker this many days after removal", group="Removal requests"),
    # Monitoring
    SettingDef("scan_interval_days", 30, "int", "Exposure scan every N days", group="Monitoring"),
    SettingDef("breach_interval_days", 7, "int", "Breach check every N days", group="Monitoring"),
    SettingDef("searxng_url", "", label="SearXNG URL", group="Monitoring",
               help="Self-hosted metasearch. docker-compose ships one at http://searxng:8080"),
    SettingDef("brave_api_key", "", "secret", "Brave Search API key", group="Monitoring", help="Optional alternative to SearXNG."),
    SettingDef("xposedornot_enabled", True, "bool", "Use XposedOrNot (free)", group="Monitoring"),
    SettingDef("leakcheck_enabled", True, "bool", "Use LeakCheck public API (free)", group="Monitoring"),
    SettingDef("hibp_api_key", "", "secret", "Have I Been Pwned API key", group="Monitoring", help="Paid; enables paste monitoring."),
    SettingDef("github_token", "", "secret", "GitHub token", group="Monitoring", help="Searches public code for your emails/phones."),
    SettingDef("psbdmp_enabled", False, "bool", "Search psbdmp paste dumps (experimental)", group="Monitoring"),
    # Spam
    SettingDef("datagov_api_key", "", "secret", "api.data.gov key (FTC complaint data)", group="Spam blocking",
               help="Free at https://api.data.gov/signup/"),
    # Notifications
    SettingDef("notify_email", "", "private", label="Send alerts to", group="Notifications", help="Your own address, for digests of new findings."),
    SettingDef("ntfy_url", "", label="ntfy topic URL", group="Notifications", help="e.g. https://ntfy.sh/your-secret-topic"),
]

DEF_BY_KEY = {d.key: d for d in DEFS}
# Internal keys that are not shown on the settings page.
INTERNAL_KEYS = {"imap_uidvalidity", "imap_last_uid", "last_tick_at", "last_digest_at", "checklist_done", "mail_account_id"}


def _coerce(defn: SettingDef | None, raw: str | None) -> Any:
    if defn is None:
        return raw
    if raw is None:
        return defn.default
    if defn.kind == "int":
        try:
            return int(raw)
        except ValueError:
            return defn.default
    if defn.kind == "bool":
        return raw.lower() in {"1", "true", "yes", "on"}
    return raw


class Settings:
    """Read-through accessor. Construct per session; cheap."""

    def __init__(self, session: Session):
        self.session = session

    def get(self, key: str) -> Any:
        row = self.session.get(Setting, key)
        defn = DEF_BY_KEY.get(key)
        if row is None or row.value is None:
            return defn.default if defn else None
        raw = get_vault().decrypt(row.value) if row.secret else row.value
        return _coerce(defn, raw)

    def set(self, key: str, value: Any) -> None:
        defn = DEF_BY_KEY.get(key)
        secret = bool(defn and defn.kind in ("secret", "private"))
        if isinstance(value, bool):
            raw = "true" if value else "false"
        else:
            raw = "" if value is None else str(value)
        stored = get_vault().encrypt(raw) if (secret and raw) else raw
        row = self.session.get(Setting, key)
        if row is None:
            row = Setting(key=key)
            self.session.add(row)
        row.value = stored
        row.secret = secret

    def followup_days(self) -> list[int]:
        out = []
        for part in str(self.get("followup_days")).split(","):
            part = part.strip()
            if part.isdigit() and int(part) > 0:
                out.append(int(part))
        return sorted(set(out))

    def __getattr__(self, key: str) -> Any:
        if key in DEF_BY_KEY or key in INTERNAL_KEYS:
            return self.get(key)
        raise AttributeError(key)
