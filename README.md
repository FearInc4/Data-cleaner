# Data Cleaner

**A free, self-hosted tool to get your personal data off data broker sites, find where it's exposed, and stop the spam it feeds.**

Paid services like DeleteMe, Optery, and Incogni charge $100–$250 a year for something that's mostly public knowledge plus persistence. Data Cleaner does the same work for free, on your own machine:

- **Find where you appear.** It checks people-search sites directly and searches the web (through a private, self-hosted SearXNG instance) for your name, phones, emails, and usernames.
- **Demand removal.** It sends legally grounded deletion and opt-out requests (CCPA/CPRA, 18 other US state laws, GDPR, UK GDPR, PIPEDA, Quebec Law 25, and Australia's Privacy Act) to 58 curated brokers. You can add hundreds more by importing the California, Vermont, Texas, and Oregon data broker registries.
- **Pester until they respond.** Follow-ups go out on a schedule. A final notice goes out at the legal deadline. If the broker still doesn't comply, you get a ready-to-file regulator complaint.
- **Read the replies for you.** Over IMAP it matches broker replies to requests, recognizes "done", "verify", "need more info", and "rejected", and opens verification links (only ones on the broker's own domain).
- **Monitor breaches and pastes.** It uses XposedOrNot and LeakCheck (both free), Have I Been Pwned (bring your own key), and GitHub code search. Passwords are checked with k-anonymity.
- **Stop the spam.** It builds a phone blocklist from FTC complaint data, unsubscribes you from mailing lists in one click (RFC 8058), and gives you a country-specific checklist (Do Not Call registries, credit freezes, prescreened offers, and more).

Your data never leaves your machine except in the requests you approve. Personal data and secrets are encrypted at rest.

> Not legal advice. The letter templates cite real statutes, but you're responsible for what you send.

---

## Quick start

### Docker (recommended)

```bash
git clone https://github.com/FearInc4/Data-cleaner.git
cd Data-cleaner
cp .env.example .env   # optional: set DATACLEANER_SECRET_KEY and SEARXNG_SECRET
docker compose up -d
```

Open <http://localhost:8080>, create your login, and follow the "Get started" checklist.

This starts two containers. `datacleaner` serves the app on localhost only. `searxng` is a private search backend that isn't exposed to the network. Everything is stored in `./data`.

### Without Docker

You need Python 3.12 or newer.

```bash
pip install -e .            # or: uv pip install -e .
datacleaner serve           # http://127.0.0.1:8080
```

For web search without Docker, run your own SearXNG or add a Brave Search API key in Settings.

**Assisted form filling (optional, desktop only).** Data Cleaner can open a broker's opt-out form in a real browser window, pre-filled with your details. You check it, solve the CAPTCHA, and submit.

```bash
pip install -e ".[browser]" && playwright install chromium
```

---

## How it works

```
1. Add yourself     →  name, emails, phones, current + past addresses (encrypted)
2. Connect email    →  SMTP to send, IMAP to read replies (use a dedicated alias + app password)
3. Pick brokers     →  crucial people-search sites are pre-selected
4. Review & send    →  every email is shown to you before it goes out
5. Walk away        →  the scheduler sends follow-ups, reads replies, escalates, and re-checks
```

**Default follow-up cadence** (adjustable in Settings):

| Day | What happens |
|---|---|
| 0 | Request sent |
| 10 | Follow-up #1 |
| 25 | Follow-up #2, citing the legal deadline |
| 45 (US) / 30 (EU, UK, CA, AU) | Final notice; request marked **overdue** |
| deadline + 7 | Regulator complaint draft ready (CPPA, state AG, FTC, ICO, CNIL, OPC, OAIC…) |
| every 30 days after | Reminder, up to 6 emails total |
| 90 days after removal | Re-check; a listing that came back is flagged again |

Web-form brokers (most people-search sites) can't be emailed. For those, Data Cleaner gives you one-click links, copy buttons for every field (or a pre-filled browser window), and tracks the request the same way once you click **I submitted it**.

**California residents** should also use the state's free [DROP platform](https://consumer.drop.privacy.ca.gov). One request there reaches every registered broker. Data Cleaner covers everything else.

### Scheduler

By default the scheduler runs inside the web process every 5 minutes. To drive it from cron or systemd instead, set `DATACLEANER_SCHEDULER=0` and run:

```bash
*/10 * * * * datacleaner tick
```

---

## Configuration

Most settings live on the in-app **Settings** page. Process-level options are environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `DATACLEANER_DATA_DIR` | `./data` | Database and key file |
| `DATACLEANER_SECRET_KEY` | *(generated `secret.key`)* | Encryption key or passphrase. Set it to keep the key out of backups of the data dir. |
| `DATACLEANER_HOST` / `DATACLEANER_PORT` | `127.0.0.1` / `8080` | Listen address |
| `DATACLEANER_SCHEDULER` | `1` | Run the scheduler in-process |
| `DATACLEANER_SCHEDULER_INTERVAL` | `300` | Seconds between ticks |
| `DATACLEANER_SEARXNG_URL` | | Default SearXNG URL (compose sets this) |
| `DATACLEANER_SECURE_COOKIES` | `0` | Set to `1` when served over HTTPS |
| `DATACLEANER_DATABASE_URL` | SQLite in the data dir | Any SQLAlchemy URL |

**Email providers.** Use an app password, not your main password.

| Provider | SMTP | IMAP |
|---|---|---|
| Gmail | smtp.gmail.com:587 starttls | imap.gmail.com:993 |
| Outlook | smtp-mail.outlook.com:587 starttls | outlook.office365.com:993 |
| Fastmail | smtp.fastmail.com:465 ssl | imap.fastmail.com:993 |
| iCloud | smtp.mail.me.com:587 starttls | imap.mail.me.com:993 |

**Remote access.** The app listens on localhost by default. To reach it from your phone, use [Tailscale](https://tailscale.com) or a reverse proxy with HTTPS (Caddy, Traefik, nginx), and set `DATACLEANER_SECURE_COOKIES=1`. Don't expose it to the internet over plain HTTP.

**Backups.** Back up the `data/` directory. If you set `DATACLEANER_SECRET_KEY`, store it separately, because the database is useless without it.

---

## Importing state broker registries

Registered data brokers must publish a contact email and a deletion link. Import a registry to add hundreds of brokers that Data Cleaner can then email automatically:

1. California: download the CSV from <https://cppa.ca.gov/data_broker_registry/>
2. In the app, go to **Brokers → Import a state registry**. From the command line: `datacleaner import-registry CA registry.csv`

The importer matches columns by name, so new yearly formats keep working. It never overwrites curated catalog entries; it only fills gaps.

---

## Security and privacy

- PII, email bodies, and secrets are encrypted at rest with Fernet (AES-128-CBC + HMAC-SHA256). The database file alone reveals nothing.
- The data directory is owner-only (umask 077), and the key file is 0600.
- There's a single admin login (scrypt), with signed `SameSite=Strict` session cookies, CSRF tokens on every form, a strict CSP, and lockout after failed logins.
- Verification links are only opened if they're on the broker's own domain. Unsubscribe URLs pointing at private or local networks are refused.
- Breach providers return metadata only. Data Cleaner never downloads dumps or crawls dark-web markets itself.
- **No doxxing.** Every profile needs an attestation that it's you or someone who authorized you in writing. Agent profiles can't send requests until the signed authorization letter (generated by the app) is on file. Scans run only against saved profiles.

---

## Contributing

The most valuable contribution is **keeping the broker catalog accurate**. Brokers change their opt-out pages constantly.

- Catalog files: `src/datacleaner/brokers/data/*.yaml`. The field reference is in `src/datacleaner/brokers/__init__.py`.
- Mark anything you couldn't confirm with `verified: false`.
- Run the checks with `pip install -e ".[dev]" && datacleaner check-catalog && pytest`.

See [PLAN.md](PLAN.md) for the architecture, legal basis per region, and roadmap.

### Credits

Broker research draws on the volunteer [Big Ass Data Broker Opt-Out List](https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List) (CC BY-NC-SA), the [Privacy Rights Clearinghouse](https://www.privacyrights.org/data-brokers) database, and state data broker registries. Catalog descriptions are our own; facts (URLs, addresses) are credited to those sources.

## License

[AGPL-3.0-or-later](LICENSE). If you run a modified version as a service for others, you must share your changes.
