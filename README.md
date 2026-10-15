# Data Cleaner

**A free, self-hosted tool to get your personal data off data broker sites, find where it's exposed, and stop the spam it feeds.**

Paid services like DeleteMe, Optery, and Incogni charge $100–$250 a year for something that's mostly public knowledge plus persistence. Data Cleaner does the same work for free, on your own machine:

- **Find where you appear.** It checks people-search sites directly and searches the web (through a private, self-hosted SearXNG instance) for your name, phones, emails, and usernames.
- **Sign in with Google or Microsoft.** It sends from your own Gmail or Outlook / Microsoft 365 account and reads the replies, with no SMTP or app passwords. Each broker gets its own address (`you+dc-spokeo-1@gmail.com`), so every reply is matched automatically, and you'll know who leaked your address if spam ever arrives at one.
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

Then run `docker compose logs datacleaner` and open the **setup link** it prints (`http://localhost:25326/setup?token=…`). Port 25326 spells CLEAN on a phone keypad and was picked because other apps don't use it; set `DATACLEANER_PORT` in `.env` to change it. The one-time token makes sure nobody else can claim your install. A short guided setup takes it from there: connect your email, add your details, pick brokers, send.

This starts two containers. `datacleaner` serves the app on localhost only. `searxng` is a private search backend that isn't exposed to the network. Everything is stored in the `datacleaner-data` Docker volume.

### Without Docker

You need Python 3.12 or newer.

```bash
pip install -e .            # or: uv pip install -e .
datacleaner serve           # prints your setup link
```

For web search without Docker, run your own SearXNG or add a Brave Search API key in Settings.

**Assisted form filling (optional, desktop only).** Data Cleaner can open a broker's opt-out form in a real browser window, pre-filled with your details. You check it, solve the CAPTCHA, and submit. The [browser extension](#browser-extension) does the same in your everyday browser and also works with Docker or a remote install.

```bash
pip install -e ".[browser]" && playwright install chromium
```

### Browser extension

Most opt-outs are web forms. The Data Cleaner extension fills them for you in Chrome, Edge, Brave or Firefox: open the broker's form, click the extension, choose **Fill the form**, check the details, solve any CAPTCHA and press Submit. Then choose **I submitted it**, and Data Cleaner schedules the follow-ups.

1. In Data Cleaner, open **Account & security → Browser extension** and download the extension. Unzip it.
2. **Chrome / Edge / Brave:** go to `chrome://extensions`, turn on **Developer mode**, choose **Load unpacked** and pick the unzipped folder. **Firefox:** go to `about:debugging#/runtime/this-firefox` and choose **Load Temporary Add-on** (Firefox removes temporary add-ons when it restarts until the extension is published on addons.mozilla.org).
3. Create a pairing code on the same page, open the extension, and enter your Data Cleaner address and the code.

The extension only fills forms on the broker's own website, over HTTPS. It fetches your details for one form at a time and never stores them, and it can't see anything else in Data Cleaner. Unpair a browser any time on the Account page.

---

## Sign in with Google / Microsoft

Each install uses **its own** OAuth app, so your mailbox access belongs to you. No shared developer account sits in the middle, and there's nothing for anyone to sell. It's a one-time setup of about 5 minutes. The app shows these same steps, with your exact redirect URI and copy buttons, under **Settings → Sign-in apps**.

**Google (Gmail / Google Workspace)**
1. In [Google Cloud Console](https://console.cloud.google.com/projectcreate), create a project and enable the **Gmail API**.
2. Go to **Google Auth Platform**. Under Branding, set an app name and your email. Under Audience, choose External and add yourself as a test user. Under Data Access, add the scopes `gmail.send` and `gmail.readonly`.
3. Under **Clients**, create a **Web application** client with the redirect URI `http://localhost:25326/auth/google/callback` (or your `DATACLEANER_BASE_URL` + `/auth/google/callback`).
4. Paste the client ID and secret on the setup page or in Settings, or set `DATACLEANER_GOOGLE_CLIENT_ID` / `_SECRET` in `.env`.
5. Recommended: **Publish** the app. Apps left in "Testing" must be reconnected every 7 days. You'll see an "unverified app" notice when connecting, which is normal for a private app you made yourself.

**Microsoft (Outlook.com, Hotmail, Microsoft 365)**
1. Under [App registrations](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade), choose New registration, with account type **"any organizational directory and personal Microsoft accounts"**.
2. Add a **Web** redirect URI: `http://localhost:25326/auth/microsoft/callback`.
3. Under Certificates & secrets, create a client secret and copy its **Value**.
4. Under API permissions → Microsoft Graph (Delegated), add `Mail.Send`, `Mail.Read`, `User.Read` and `offline_access`.
5. Paste the Application (client) ID and secret, or set `DATACLEANER_MICROSOFT_CLIENT_ID` / `_SECRET`.

Prefer not to? Any provider still works over SMTP/IMAP with an app password (**Settings → Use another email provider**).

### Per-broker addresses

With Gmail, Outlook, iCloud, Fastmail, Proton and most custom domains, the part after a `+` is delivered to you as normal. Data Cleaner gives every broker its own:

- Email requests set `Reply-To: you+dc-spokeo-1@gmail.com`.
- Web-form requests show that address to paste into the broker's form (assisted fill and the browser extension use it).
- Incoming mail to it is matched to the right request, even when the broker's system never quotes our reference.
- Mail at that address from anyone other than the broker is flagged: *"Spokeo may have shared or leaked your address."*

If a form rejects the `+`, switch that one request to your plain address. If you own a domain with a catch-all, choose **catchall** mode for `dc-spokeo-1@yourdomain`. Yahoo/AOL don't support plus-addressing, so aliases are skipped there.

### Light and dark mode

The theme follows your system by default. The button in the top bar cycles **system → light → dark** and remembers your choice.

---

## How it works

```
1. Add yourself     →  name, emails, phones, current + past addresses (encrypted)
2. Connect email    →  one click for Gmail / Outlook (or SMTP + IMAP for anything else)
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
| `DATACLEANER_HOST` / `DATACLEANER_PORT` | `127.0.0.1` / `25326` | Listen address |
| `DATACLEANER_SCHEDULER` | `1` | Run the scheduler in-process |
| `DATACLEANER_SCHEDULER_INTERVAL` | `300` | Seconds between ticks |
| `DATACLEANER_SEARXNG_URL` | | Default SearXNG URL (compose sets this) |
| `DATACLEANER_BASE_URL` | | The address you open in the browser, e.g. `https://privacy.example.com`. Used for OAuth redirect URIs and the Host allow-list. `https://` also turns on secure cookies and HSTS. |
| `DATACLEANER_ALLOWED_HOSTS` | | Extra hostnames allowed in the Host header (comma-separated), e.g. a Tailscale name. Blocks DNS-rebinding attacks. |
| `DATACLEANER_GOOGLE_CLIENT_ID` / `_SECRET` | | Google OAuth client (or set them in the app) |
| `DATACLEANER_MICROSOFT_CLIENT_ID` / `_SECRET` | | Microsoft OAuth client (or set them in the app) |
| `DATACLEANER_SECURE_COOKIES` | `0` | Set to `1` when served over HTTPS (automatic if the base URL is https) |
| `DATACLEANER_DATABASE_URL` | SQLite in the data dir | Any SQLAlchemy URL |

**Email over SMTP/IMAP** (if you don't connect Gmail/Outlook directly). Use an app password, not your main password.

| Provider | SMTP | IMAP |
|---|---|---|
| Gmail | smtp.gmail.com:587 starttls | imap.gmail.com:993 |
| Outlook | smtp-mail.outlook.com:587 starttls | outlook.office365.com:993 |
| Fastmail | smtp.fastmail.com:465 ssl | imap.fastmail.com:993 |
| iCloud | smtp.mail.me.com:587 starttls | imap.mail.me.com:993 |

**Remote access.** The app listens on localhost by default. To reach it from your phone, use [Tailscale](https://tailscale.com) or a reverse proxy with HTTPS (Caddy, Traefik, nginx), and set `DATACLEANER_BASE_URL=https://your-name` (add the new redirect URIs to your Google/Microsoft apps). Don't expose it to the internet over plain HTTP.

**Backups.** With Docker, copy the data volume out (stop the app first so the database is consistent):

```bash
docker compose stop datacleaner
docker compose cp datacleaner:/data ./datacleaner-backup
docker compose start datacleaner
```

The copy holds your encrypted personal data, so keep it somewhere private.

Without Docker, back up the `data/` directory. If you set `DATACLEANER_SECRET_KEY`, store it separately, because the database is useless without it.

---

## Importing state broker registries

Registered data brokers must publish a contact email and a deletion link. Import a registry to add hundreds of brokers that Data Cleaner can then email automatically:

1. California: download the CSV from <https://cppa.ca.gov/data_broker_registry/>
2. In the app, go to **Brokers → Import a state registry**. From the command line: `datacleaner import-registry CA registry.csv`

The importer matches columns by name, so new yearly formats keep working. It never overwrites curated catalog entries; it only fills gaps.

---

## Security and privacy

See **[SECURITY.md](SECURITY.md)** for the full threat model and how to report a vulnerability. In short:

- PII, email bodies, OAuth tokens and secrets are encrypted at rest. Files are owner-only.
- A fresh install can only be claimed with its one-time setup token.
- Google/Microsoft sign-in uses PKCE, state, nonce and signature-verified ID tokens, and matches people by account id, never by email.
- Sessions expire, and you can sign out everywhere. CSRF tokens, a strict CSP, a Host allow-list and no-store caching protect the web UI.
- Broker replies only change a request when they're provably from that broker (thread match or DMARC/DKIM pass). Spoofed "we deleted your data" emails go to you for review.
- Links from emails and search results can never reach your local network (SSRF guard at every redirect).
- Logs are scrubbed of emails, phone numbers and tokens.
- Dependencies are hash-pinned, the image runs read-only as non-root, and CI fails on known CVEs (pip-audit, bandit, Trivy).
- **No doxxing.** Every profile requires an attestation, and agent profiles need a signed authorization letter before any request goes out.
- **Erase everything** (Account page) wipes all data and revokes mailbox access in one step.

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
