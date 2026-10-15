# Data Cleaner: Project Plan

A free, open-source, self-hosted tool that helps people:

1. **Find** where their personal data shows up: people-search sites, search engines, breach dumps, paste sites.
2. **Remove** it: send legally grounded deletion/opt-out requests to data brokers, follow up on a schedule until they answer, and escalate to regulators when they don't.
3. **Stop the spam**: cut off the data supply that feeds spam calls, texts, and email, and give people tools to block what still gets through.

The paid services (DeleteMe, Optery, Incogni, Kanary) do roughly this for $100–$250/year. Most of the work is public knowledge (broker lists, opt-out URLs, statutory request letters). The rest is persistence: someone has to send the follow-ups. Software can do that for free.

---

## 1. Decisions made so far

| Decision | Choice | Why |
|---|---|---|
| Regions for v1 | US, EU/UK, Canada, Australia | Chosen by project owner. US first (largest broker industry), then GDPR-style templates. |
| Hosting model | **Single-user / household self-host first**, multi-user later | Each person's PII stays on their own box (laptop, Pi, NAS, VPS). A central server holding thousands of people's addresses/DOBs would be a high-value target. The data model already carries `owner_id` so multi-user is an additive change. |
| Form automation | **Human-in-the-loop** | Emails go out fully automatically. Web forms get pre-filled by a local browser and the human solves CAPTCHAs. Verification links that brokers email back are clicked automatically, but only for links on that broker's own domains. |
| Dark web / breach | **Breach-intel APIs + public paste monitoring** | Aggregators (HIBP, XposedOrNot, LeakCheck) already crawl leak forums and markets. Querying them gives the same findings without the app downloading stolen data, touching Tor markets, or risking illegal content. |
| Stack | Python 3.12+, FastAPI, SQLAlchemy + SQLite, Jinja templates, stdlib SMTP/IMAP, optional Playwright | One process, one container, no JS build step. Python has the best scraping and browser-automation ecosystem. SQLite means zero-ops backups (one file). |
| License | AGPL-3.0 for code | Keeps hosted forks open. Anyone who runs a modified version as a public service has to share their changes. |
| Mail transport | **Gmail API / Microsoft Graph via OAuth**, with SMTP/IMAP as fallback | One-click setup with no app passwords. Least-privilege scopes, revocable. Raw MIME keeps threading headers intact. |
| OAuth apps | **One OAuth client per install** (the owner's own Google Cloud / Entra app) | No central developer account that could be compromised, sold, or have to pass Google's restricted-scope security assessment (CASA) for everyone. Costs each self-hoster about 5 minutes. |
| Reply tracking | **Per-broker plus-address aliases** + thread headers + reference token | Matches even form-generated confirmation emails, and attributes leaks to the broker that sold the address. |
| Trust in replies | Only thread-matched or DMARC-authenticated replies change state | Stops spoofed "we deleted your data" emails from silencing follow-ups. |

---

## 2. Architecture

```
                 ┌──────────────────────────────────────────────────────┐
                 │                Data Cleaner (one process)            │
 Browser ───────►│  Web UI (FastAPI + Jinja)   CLI (python -m datacleaner)│
                 │        │                           │                  │
                 │        ▼                           ▼                  │
                 │  ┌───────────┐  ┌─────────────┐  ┌────────────────┐   │
                 │  │ Profiles  │  │ Broker      │  │ Removal engine │   │
                 │  │ (PII,     │  │ catalog     │  │ letters, state │   │
                 │  │ encrypted)│  │ YAML + gov  │  │ machine, cadence│  │
                 │  └───────────┘  │ registries  │  └───────┬────────┘   │
                 │                 └─────────────┘          │            │
                 │  ┌───────────┐  ┌─────────────┐  ┌───────▼────────┐   │
                 │  │ Exposure  │  │ Breach/paste│  │ Scheduler tick │   │
                 │  │ scanner   │  │ monitors    │  │ (every N min)  │   │
                 │  └─────┬─────┘  └──────┬──────┘  └───────┬────────┘   │
                 └────────┼───────────────┼─────────────────┼────────────┘
                          ▼               ▼                 ▼
                SearXNG / Brave     XposedOrNot, HIBP,   Your mailbox
                broker search pages LeakCheck, PwnedPw   (SMTP out, IMAP in)
```

### Components

| Module | Responsibility |
|---|---|
| `datacleaner.models` | Profiles, brokers, removal requests, request events, findings, scan runs, settings. |
| `datacleaner.crypto` | Fernet encryption for PII and secrets at rest. The key comes from an env var or a `0600` key file. |
| `datacleaner.brokers` | Curated YAML catalog plus importers for state data broker registries (CA, VT, TX, OR CSV exports). |
| `datacleaner.jurisdictions` | Maps a profile's country/state to the law to cite, the statutory deadline, and the regulator for escalation. |
| `datacleaner.removal` | Renders request, follow-up, and escalation letters. Owns the request state machine and the follow-up cadence. |
| `datacleaner.mail` | SMTP sending, IMAP polling, matching replies to requests, classifying replies, extracting verification links. |
| `datacleaner.scheduler` | Idempotent `tick()`: send queued mail, poll the inbox, send due follow-ups, mark overdue, run due scans. Runs in-process every N minutes, or from cron with `python -m datacleaner tick`. |
| `datacleaner.scan` | Search-engine exposure scan (self-hosted SearXNG or Brave API), direct broker listing checks, result matching. |
| `datacleaner.breach` | Breach and paste providers behind one interface, plus a k-anonymity Pwned Passwords check. |
| `datacleaner.spam` | FTC Do Not Call complaint data turned into a phone blocklist (vCard), an inbox unsubscribe helper (RFC 8058 one-click), and region-specific do-not-call/mail checklists. |
| `datacleaner.assist` | Optional Playwright helper: opens a broker's opt-out form in a visible browser, pre-fills it, and hands control to the human. |
| `datacleaner.web` | Server-rendered UI with single-admin auth and CSRF protection. |

---

## 3. Data broker sources

Brokers come from four places, merged by domain into one catalog:

1. **Curated catalog** (`src/datacleaner/brokers/data/*.yaml`). Hand-maintained entries for the high-impact people-search sites and the big marketing brokers: opt-out URL, privacy email, search URL template, what the process requires (CAPTCHA, email verification, profile URL, ID, phone call), parent company, and sister sites. Contributions come in as pull requests.
2. **California Data Broker Registry** (CPPA): 500–600+ registered brokers, CSV download at <https://cppa.ca.gov/data_broker_registry/>. Each entry includes a contact email and a deletion-request link. The CSV importer maps columns by header keywords so it survives yearly format changes.
3. **Vermont, Texas, and Oregon registries**: same importer. Vermont and Texas don't offer bulk CSV, so users export their search results or use the consolidated [Privacy Rights Clearinghouse database](https://www.privacyrights.org/data-brokers).
4. **Community references**, used for research only and not redistributed: the [Big Ass Data Broker Opt-Out List](https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List) (CC BY-NC-SA) and Michael Bazzell's Extreme Privacy workbook. Opt-out URLs and emails are facts. Our catalog descriptions are written fresh, and the sources are credited.

**California residents** get a top-level prompt to use **DROP** (<https://consumer.drop.privacy.ca.gov>). One verified request there covers every registered broker, and brokers must process it every 45 days (obligation started 2026-08-01). The app tracks DROP as a single "meta-request" and still handles unregistered and non-compliant sites directly.

### Removal methods, in order of preference

1. **Email**: fully automated. The letter cites the right law, includes a reference token, and gets followed up on schedule.
2. **Web form**: human-in-the-loop. The app opens the form pre-filled (Playwright locally, or a guided copy/paste panel in Docker), the human submits, and the app watches the inbox for the confirmation link.
3. **Portal or account**: guided steps.
4. **Phone or postal mail**: guided steps, plus a printable letter.

---

## 4. Legal basis by region

| Region | Law cited | Deadline | Escalation |
|---|---|---|---|
| California | CCPA/CPRA (Cal. Civ. Code §1798.100 et seq.): delete, opt out of sale/sharing, limit sensitive PI. Delete Act / DROP for registered brokers. | 45 days (+45 extension) | California Privacy Protection Agency, CA AG |
| ~18 other US states with comprehensive laws (VA, CO, CT, UT, TX, OR, MT, IA, DE, NH, NJ, NE, TN, MN, MD, IN, KY, RI) | State act, cited by name and code chapter (kept in a data table) | 45 days (+45) | State Attorney General |
| Other US states | Polite request. Many brokers honor deletion nationwide. Also cites FTC Act §5 on deceptive practices if the broker's own privacy policy promises opt-outs. | Policy: 45 days | FTC (reportfraud.ftc.gov), state AG |
| EU | GDPR Art. 17 (erasure), Art. 21(2)–(3) (absolute right to object to direct marketing), Art. 15 (confirm source), Art. 19 (notify recipients) | 1 month (+2) | National DPA (the list is in the data table) |
| UK | UK GDPR + DPA 2018, same articles | 1 month (+2) | ICO |
| Canada | PIPEDA Principle 4.3.8 (withdraw consent), 4.5.3 (destroy), s.8(3) access; Quebec Law 25 ss. 28, 28.1 | 30 days | OPC; CAI (Quebec) |
| Australia | Privacy Act 1988: APP 7.6 (direct-marketing opt-out + disclose source), APP 11.2 (destroy/de-identify), APP 12/13. Businesses that trade in personal information are covered regardless of turnover (s 6D(4)(c)–(d)). | 30 days (reasonable period) | OAIC |

*Not legal advice. Templates are reviewed against statute text but should get a once-over from a privacy lawyer before v1.0.*

The **authorized agent** flow for family members (CCPA §1798.135 and most state laws allow it) generates a signed-permission letter for the person to sign. Requests sent for someone else attach or reference it.

---

## 5. The "pester until they respond" scheduler

Each removal request is a small state machine:

```
draft ──send──► sent ──reply──► acknowledged ──► completed ──(recheck 90d)──► verify_removed
  │               │  └─verification link──► needs_verification ──auto-click──┘
  │               │  └─"need more info"/rejected──► needs_user_action
  │               └─no reply by deadline──► overdue ──► escalation drafted
  └─ manual/form ──► awaiting_user (guided) ──user marks submitted──► sent
```

**Default cadence** (configurable in Settings):

| When (from first send) | Action |
|---|---|
| Day 0 | Initial request. |
| Day 10, no reply | Follow-up #1: polite reminder, references the original. |
| Day 25, no reply | Follow-up #2: cites the statutory deadline. |
| Statutory deadline (US 45 / EU 30 / CA 30 / AU 30 days) | Final notice: "you are now out of compliance; next step is a complaint to {regulator}." Status becomes `overdue`. |
| Deadline + 1 day | Escalation draft: a pre-filled regulator complaint with the full email timeline, ready for the human to file (regulators require a human submission). |
| Every 30 days after that, up to the max-follow-ups cap | Reminder. |
| 90 days after `completed` | Re-scan the broker listing. Data often reappears, and a new request is queued if it has. |

**Guardrails**: rate limit (default 20 emails/hour), a cap on follow-ups, reference tokens in the subject line (`[Ref DC-XXXXXX]`), and RFC 5322 `Message-ID`/`In-Reply-To` threading so replies match reliably. Verification links are only auto-followed if their host matches the broker's known domains. Any other link goes to the human.

**Reply classification** uses transparent keyword rules (a "completed", "verify", "need more info", or "rejected" signal). It's deliberately simple and auditable, and an optional LLM classifier could slot in behind the same interface later.

---

## 6. Exposure scanning ("show me where I appear")

1. **Search-engine scan**: queries built from the profile (`"First Last" City`, each email, each phone in several formats, usernames) and sent to a **self-hosted SearXNG** container (shipped in docker-compose, so there are no API keys and nothing reaches Google tied to an account) or the Brave Search API. Results get scored on how many profile fields they match (name + city/state/phone/email/age). Results on known broker domains link straight to that broker's opt-out.
2. **Direct broker checks**: for catalog brokers with a `search_url` template, the app builds the URL and checks the page. Many people-search sites sit behind bot protection, so the result is one of `found`, `not_found`, `blocked` (open it yourself, one click), or `error`. We never fake certainty.
3. **Findings** are deduplicated by fingerprint and tracked over time (`new`, `removal_requested`, `removed`, `dismissed`). "Request removal" on a finding creates the request with the listing URL attached, which many broker forms require.
4. **Google "Results about you"** and Bing's removal form are surfaced for search-engine de-indexing.

## 7. Breach and paste monitoring

| Provider | Key needed | What it gives |
|---|---|---|
| XposedOrNot | No (free, 1 req/s) | Breaches per email, exposed data classes, paste summary |
| LeakCheck public | No (limited) | Breach sources for an email or username |
| Have I Been Pwned | Yes (paid key) | Authoritative breach list and **paste** appearances per email |
| Pwned Passwords | No | k-anonymity password check: only the first 5 hex chars of the SHA-1 leave the machine |
| GitHub code search | Token (free) | Emails and phones leaked in public code |
| psbdmp (Pastebin dumps) | Varies | Experimental, off by default |

Each finding records which data classes leaked (passwords, phones, addresses, SSNs) and maps to concrete actions: change that password, enable 2FA, freeze credit (with links to Equifax, Experian, TransUnion, Innovis, and ChexSystems), or get an IRS IP PIN if an SSN leaked.

## 8. Stopping spam

Spam is a supply problem. Removing your phone and email from brokers is the root fix, and the removal engine does that. Beyond it:

**Calls and texts**
- Region checklists: US National DNC Registry, Canada DNCL, UK TPS, Australia Do Not Call Register, and EU Robinson lists. Also carrier blocking tools (AT&T ActiveArmor, Verizon Call Filter, T-Mobile Scam Shield), OS features (Silence Unknown Callers, Android call screening), and forwarding spam texts to 7726.
- **Blocklist builder**: pulls the FTC's public Do Not Call reported-calls data (free api.data.gov key) for your state and area code, ranks the most-reported numbers, and exports a **vCard** you import on your phone and block as one contact.
- **"Who called me?"** lookup against the locally cached complaint data.

**Email**
- **Unsubscribe helper**: scans your inbox over IMAP for `List-Unsubscribe` headers and groups by sender. Click to unsubscribe via RFC 8058 one-click POST or the `mailto:` method. Plain unsubscribe links that aren't one-click are shown, not auto-fetched, because fetching them can confirm your address to spammers.
- Aliasing guidance: SimpleLogin and addy.io are both open source and self-hostable. Give every site its own alias.

**Postal and prescreened offers**: OptOutPrescreen, DMAchoice, CatalogChoice, Valpak.

---

## 9. Security and abuse model

- **PII stays local.** It's encrypted at rest (Fernet/AES-128-CBC+HMAC), secrets are encrypted, and the only outbound traffic is what each feature needs (and the user can see it).
- **Single admin password** (scrypt), signed session cookie, CSRF tokens on every form. The server binds to `127.0.0.1` by default, and docker-compose maps to localhost only. Remote access is documented via Tailscale or a reverse proxy with TLS.
- **Anti-doxxing safeguards.** A people-search tool can be turned on other people. Mitigations:
  - Every profile requires an attestation: "this is me", or "I am an authorized agent", with a signed authorization letter generated for the subject.
  - Scans run only against saved profiles, never ad-hoc names, and they're rate-limited.
  - Results show *where* data appears and link to it. The app doesn't scrape and compile dossiers from broker pages.
  - Multi-user mode (later) will add email verification of the profile's own address before scans run.
- **Breach data handling.** We never download dumps. Providers return metadata (breach name, date, data classes), and passwords are only checked with k-anonymity.

---

## 10. Roadmap

### Phase 1: Local MVP (built)
- [x] Plan
- [x] Profiles with encrypted PII, attestation, authorized-agent letter
- [x] Broker catalog (58 curated entries, YAML) + state registry CSV importer
- [x] Letter templates for US (CCPA, state laws, generic), GDPR, UK GDPR, PIPEDA, Quebec, Australia, plus follow-up, final notice, and escalation
- [x] SMTP send, IMAP reply matching, reply classification, safe verification-link clicking
- [x] Scheduler with configurable cadence, rate limiting, CLI `tick`
- [x] Exposure scanner (SearXNG/Brave + direct broker checks)
- [x] Breach and paste monitors + Pwned Passwords
- [x] Spam tools: checklists, FTC DNC blocklist vCard, unsubscribe helper
- [x] Assisted form fill (Playwright, optional extra)
- [x] Web UI
- [x] Tests (89, all network calls mocked)

Not yet verified against live services from the build environment (its network blocks them): broker
search-URL patterns, the FTC DNC API field names, XposedOrNot/LeakCheck response shapes (taken from
their official SDKs), and psbdmp. All parsers are defensive, and failures show up in the UI rather than
crashing. **First task for v0.2: run each integration once against the real service.**

### Phase 1.5: Accounts, mail, security (built)
- [x] Sign in with Google / Microsoft (OIDC + PKCE + nonce, JWKS-verified, subject-based identity), password optional
- [x] Connected Gmail / Outlook mailboxes for sending and reading, with token refresh and reconnect prompts
- [x] Per-broker aliases (plus or catch-all), alias-based reply matching, leak attribution
- [x] Guided onboarding, redesigned Settings, Account & security page, light/dark/system theme
- [x] Security audit: setup token, session revocation/expiry, Host allow-list, SSRF guard, reply authentication, log redaction, mailto hardening, no-store, erase-everything
- [x] Supply chain: hash-pinned lock file, digest-pinned base image, read-only non-root container, CI pip-audit + bandit + Trivy, Dependabot

### Phase 2: Self-hosting for everyone
- [x] Dockerfile + docker-compose with SearXNG, healthcheck, volume for `/data`
- [ ] One-line install script, Raspberry Pi (arm64) image, Unraid/TrueNAS/CasaOS templates
- [ ] Backup/restore (encrypted export), upgrade path (Alembic migrations)
- [x] Notifications via email digest and ntfy (Apprise later)
- [ ] Docs site: setup, Gmail/Outlook/Fastmail app passwords, remote access via Tailscale

### Phase 3: Community scale
- [ ] Multi-user mode (accounts, per-user keys, email verification of profile owners)
- [ ] Broker catalog as its own repo with CI that checks opt-out URLs weekly and flags dead ones
- [ ] Shared, anonymous "broker response stats" (opt-in): how fast each broker responds, which methods work
- [x] Browser extension for one-click form fill on any broker page (an alternative to Playwright)
- [ ] Desktop packaging (Tauri) for non-technical users
- [ ] Translations of templates and UI (EU languages, French for Quebec)
- [ ] Lawyer review of all templates

---

## 11. Recommended next steps

Highest impact first:

1. **Run every integration against the real services once** (Gmail, Graph, XposedOrNot, LeakCheck, FTC, broker search pages) and fix any response-shape surprises. The test suite fakes them all.
2. ~~**Browser extension for form filling.**~~ Done: `src/datacleaner/extension/` (Manifest V3, Chrome and Firefox), paired per browser with revocable codes. Next: publish it on the Chrome Web Store and addons.mozilla.org so people don't need Developer mode, and fill forms inside iframes (OneTrust-style portals).
3. **One-click installers:** a Raspberry Pi / NAS image (Umbrel, CasaOS, Unraid, TrueNAS apps), and a desktop bundle (Tauri) that runs locally with no Docker. Non-technical people won't run `docker compose`.
4. **Encrypted backup and restore** (passphrase-protected export) and an upgrade path with Alembic.
5. **Distroless or Wolfi base image** to remove the Debian packages that carry unfixed CVEs.
6. **Survivor-safety mode** with a DV advocacy group: a quick-exit button, a neutral app name and favicon, no email digests, and Address Confidentiality Program guidance per state.
7. **Broker catalog as a shared data repo** with a weekly CI job that checks every opt-out URL and flags dead or changed ones. Optional anonymous response-time stats per broker.
8. **Alias services:** SimpleLogin / addy.io API integration for real per-broker aliases (not just `+` tags), so a leaking broker's address can be switched off.
9. **Accessibility and translations:** a WCAG 2.2 AA pass, and Spanish/French UI and letters.
10. **Lawyer review** of every letter template, and a public hosted instance only after that (it would need Google CASA verification, a privacy policy, and probably a nonprofit).

## 12. Open questions for the project owner

1. **Name/branding.** Keep "Data Cleaner" or pick something else for the public release?
2. **Multi-user hosting.** Do you want to run a public instance yourself eventually? That changes the threat model a lot: it needs legal review, a privacy policy, and probably a nonprofit wrapper.
3. **Paid APIs.** HIBP is the best paste source but needs a paid key (a few dollars a month). Keep it bring-your-own-key, or pool one for a hosted instance?
4. **Postal mail.** Some brokers only accept mail. Should we integrate a print-and-mail API (Lob, ~$1/letter), or just generate a PDF?
5. **Catalog governance.** Should the broker catalog live in this repo or a separate data repo that other tools can reuse?
