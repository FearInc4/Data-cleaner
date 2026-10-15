# Security

Data Cleaner holds exactly the information a stalker, scammer or identity thief would want: names, every address someone has lived at, phone numbers, emails, and access to a mailbox. It is used by people who may already be at risk. Security is therefore a core feature, not an add-on.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private vulnerability reporting (Security → "Report a vulnerability") on this repository. We aim to acknowledge reports within 3 days and to ship a fix for confirmed high-severity issues within 14 days. Please give us a reasonable chance to fix the problem before you disclose it.

## Threat model

| Threat | Mitigation |
|---|---|
| Stolen or leaked database file (backup, sync folder, lost disk) | PII, email bodies, OAuth tokens and secrets are encrypted with Fernet (AES-128-CBC + HMAC-SHA256). Set `DATACLEANER_SECRET_KEY` to keep the key out of the data directory. Files are created owner-only (umask 077). |
| Someone else claiming a fresh install | The first account can only be created with a one-time setup token. It's printed to the server console and stored in `data/setup-token`, and deleted once used. |
| Password guessing | scrypt hashes, a 12-character minimum, 5 failures per 15 minutes per username and IP, and constant-time behaviour for unknown usernames. Google/Microsoft sign-in inherits their 2-step verification. |
| Account takeover through a look-alike Google/Microsoft account ("nOAuth") | Accounts are matched on the provider's stable subject id (Google `sub`, Microsoft `tid`+`oid`), never on the email claim. Only identities linked by the owner can sign in. |
| OAuth code interception, login CSRF, token replay | Authorization-code flow with PKCE (S256), `state` bound to the session, a `nonce` checked in the ID token, and an ID token signature verified against the provider's JWKS with `iss`/`aud`/`exp` checks. |
| Stolen session cookie | The cookie is signed, `HttpOnly`, `SameSite=Lax`, and `Secure` when served over HTTPS. Sessions expire after 24 hours idle and 7 days absolute. "Sign out everywhere" and password changes revoke every session server-side. |
| CSRF, clickjacking, XSS | CSRF tokens on every POST. `frame-ancestors 'none'`. Strict CSP (no inline script or style). Autoescaped templates. Links from untrusted sources pass through a `safe_url` filter that only allows http(s). |
| DNS rebinding against a local install | The Host header is checked against localhost, `DATACLEANER_BASE_URL` and `DATACLEANER_ALLOWED_HOSTS`. |
| SSRF via links in emails, search results or imported registries | Verification links are only opened if they're on the broker's own domain. Every untrusted fetch goes through a client that refuses private, loopback, link-local, metadata and non-https targets at every redirect hop. |
| Spoofed broker replies ("your data was deleted") | A reply only changes a request if it quotes our unguessable Message-ID or request reference, or if our mail provider's topmost `Authentication-Results` shows DMARC/aligned-DKIM passing for the broker's domain. Anything else is flagged for the person to review, and follow-ups continue. |
| Spammers abusing the unsubscribe helper | One-click unsubscribe only goes to public https hosts. A `mailto:` unsubscribe always sends our own fixed body to a single recipient; the sender can't choose what is sent from your account. |
| Personal data in logs | A log filter redacts emails, phone numbers, OAuth codes, tokens and API keys from application and access logs, including tracebacks. |
| Browser and proxy caching | `Cache-Control: no-store` on every page. |
| Mailbox access abuse | Least-privilege scopes (`gmail.send` + `gmail.readonly`; Graph `Mail.Send` + `Mail.Read`). Tokens are encrypted, Google tokens are revoked on disconnect, and "Erase everything" wipes all data and revokes access. |
| Malicious or compromised dependency release | Every dependency is pinned by version **and sha256 hash** (`requirements.lock`, installed with `--require-hashes`). The base image is pinned by digest. Dependabot proposes updates weekly. |
| Known CVEs | CI runs `pip-audit` (PyPI + OSV advisories), `bandit`, and a Trivy image scan that fails on fixable HIGH/CRITICAL issues, on every push and weekly. |
| Container breakout / lateral movement | Runs as an unprivileged user, with a read-only root filesystem, all capabilities dropped, `no-new-privileges`, memory/pid limits, and only localhost published. pip is removed from the runtime image. |

## Known limitations

- **Anyone with shell access to the running host can read the data.** Encryption at rest protects copies of the files, not a compromised server. Keep the host patched and its access limited.
- **DNS rebinding between our check and the connection** is theoretically possible for untrusted fetches. The remaining impact is a blind GET/POST without cookies or credentials.
- **Mailboxes connected over IMAP** at providers that don't add their own `Authentication-Results` header get weaker sender verification. Gmail, Outlook and Fastmail add one.
- **Debian base-image CVEs without an upstream fix** are reported but can't be patched by us. None of the affected packages (util-linux, ncurses, systemd libs and similar) are used by the app at runtime. A distroless or Wolfi base image is on the roadmap.
- **Google OAuth apps left in "Testing"** must be reconnected every 7 days. Publishing your own private app avoids this.
- **Single owner per install.** Household members are managed as authorized-agent profiles. True multi-user mode needs per-user encryption keys and is on the roadmap.

## Self-hosting checklist

1. Keep `docker compose` binding to `127.0.0.1` (the default). Reach the app remotely through Tailscale or a reverse proxy with HTTPS, and set `DATACLEANER_BASE_URL=https://…`.
2. Set `DATACLEANER_SECRET_KEY` in `.env`, and store a copy somewhere other than your backups of `./data`.
3. Prefer "Sign in with Google/Microsoft", or use a long passphrase.
4. Use a dedicated mailbox or alias for removal requests if you can.
5. Update regularly: `git pull && docker compose build --pull && docker compose up -d`.
