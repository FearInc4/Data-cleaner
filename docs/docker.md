# Running Data Cleaner with Docker

Data Cleaner ships as one container image. A second, optional container runs [SearXNG](https://docs.searxng.org), a private search backend used to find where you appear on the web.

- **Image:** `ghcr.io/fearinc4/data-cleaner`
- **Platforms:** `linux/amd64` and `linux/arm64` (Raspberry Pi 4/5 with a 64-bit OS, most NAS boxes, Apple Silicon)
- **Tags:** `latest` (newest release), `1.2.3` / `1.2` (a release), `edge` (the main branch, updated on every merge), `sha-abc1234` (one exact build)
- **Port:** `25326` (spells CLEAN on a phone keypad; chosen because other apps don't use it)
- **SearXNG port:** `25328`, inside Docker only (not the image's default 8080, which many other apps use)
- **Data:** everything lives in `/data` inside the container

Contents:
[Quick start](#quick-start) ·
[Add it to your existing stack](#add-it-to-your-existing-stack) ·
[Settings](#settings) ·
[Behind a reverse proxy](#behind-a-reverse-proxy) ·
[Where the data lives](#where-the-data-lives) ·
[Secrets](#secrets) ·
[Using your own SearXNG](#using-your-own-searxng) ·
[Updating](#updating) ·
[Backup and restore](#backup-and-restore) ·
[Portainer, Unraid, Synology](#portainer-unraid-synology-casaos) ·
[Troubleshooting](#troubleshooting)

---

## Quick start

In an empty folder:

```bash
curl -fsSLO https://raw.githubusercontent.com/FearInc4/Data-cleaner/main/deploy/compose/compose.yaml
printf 'DATACLEANER_SECRET_KEY=%s\nSEARXNG_SECRET=%s\n' "$(openssl rand -base64 48)" "$(openssl rand -hex 32)" > .env
chmod 600 .env
docker compose up -d
docker compose logs datacleaner
```

The log prints a one-time setup link, `http://localhost:25326/setup?token=…`. Open it to create your account. The token makes sure nobody else can claim your install.

The app only listens on `127.0.0.1`. To open it from another device, put it [behind a reverse proxy](#behind-a-reverse-proxy) with HTTPS, or use Tailscale.

> Keep a copy of `DATACLEANER_SECRET_KEY` somewhere safe and separate from your backups. It encrypts everything Data Cleaner stores. Without it, the data can't be read, and with it kept apart, a copied backup alone is useless to a thief.

---

## Add it to your existing stack

Paste these into your `docker-compose.yml`. If your file already has top-level `volumes:` or `configs:` sections, add the entries to them instead of creating new ones. Put the variables in the stack's `.env` (the [quick start](#quick-start) shows how to generate them).

```yaml
services:
  datacleaner:
    image: ghcr.io/fearinc4/data-cleaner:latest
    container_name: datacleaner
    restart: unless-stopped
    ports:
      - "127.0.0.1:25326:25326"          # drop this if a reverse proxy on the same network serves it
    environment:
      DATACLEANER_SECRET_KEY: ${DATACLEANER_SECRET_KEY}
      DATACLEANER_BASE_URL: ${DATACLEANER_BASE_URL:-}        # e.g. https://privacy.example.com
      DATACLEANER_TRUSTED_PROXIES: ${DATACLEANER_TRUSTED_PROXIES:-}
      DATACLEANER_SEARXNG_URL: http://searxng:25328          # remove if you skip SearXNG
    volumes:
      - datacleaner-data:/data
    read_only: true
    tmpfs:
      - /tmp:size=64m
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 512m
    pids_limit: 256

  # Optional: private web search. Data Cleaner still checks people-search sites without it.
  searxng:
    image: docker.io/searxng/searxng:latest
    container_name: datacleaner-searxng
    restart: unless-stopped
    configs:
      - source: datacleaner-searxng-settings
        target: /etc/searxng/settings.yml
    environment:
      SEARXNG_BASE_URL: http://searxng:25328/
      GRANIAN_PORT: 25328                # instead of 8080, which many other apps use
      SEARXNG_SECRET: ${SEARXNG_SECRET}
      GRANIAN_HOST: 0.0.0.0              # the image listens on IPv6 only by default
    cap_drop: [ALL]
    cap_add: [CHOWN, SETGID, SETUID]
    security_opt: [no-new-privileges:true]
    mem_limit: 512m

configs:
  datacleaner-searxng-settings:
    content: |
      use_default_settings: true
      server:
        secret_key: "overridden-by-SEARXNG_SECRET"
        limiter: false
        image_proxy: false
      search:
        safe_search: 0
        formats: [html, json]

volumes:
  datacleaner-data:
```

Then `docker compose up -d datacleaner searxng` and `docker logs datacleaner` for the setup link.

Inline `configs:` need Docker Compose 2.23.1 or newer (`docker compose version`). On older versions, save the settings block as `searxng-settings.yml` next to your compose file and use `configs: { datacleaner-searxng-settings: { file: ./searxng-settings.yml } }`.

The hardening lines (`read_only`, `cap_drop`, `security_opt`, the limits) are optional but recommended. The image runs as an unprivileged user and works with all of them.

---

## Settings

Everything else (email accounts, search providers, follow-up schedule) is set in the app's **Settings** page.

| Variable | Default | What it does |
|---|---|---|
| `DATACLEANER_SECRET_KEY` | generated into `/data/secret.key` | Encryption key for everything stored. Set it so the key lives outside the data volume. |
| `DATACLEANER_BASE_URL` | | The address you open in your browser, e.g. `https://privacy.example.com`. Needed behind a reverse proxy and for Google/Microsoft sign-in. `https://` also turns on secure cookies and HSTS. |
| `DATACLEANER_TRUSTED_PROXIES` | loopback | IPs or networks of your reverse proxy (e.g. `172.18.0.0/16`), so sign-in rate limits see real client addresses. |
| `DATACLEANER_ALLOWED_HOSTS` | | Extra host names the app answers to (comma-separated), besides localhost and the `BASE_URL` host. |
| `DATACLEANER_PORT` | `25326` | Port inside the container. If you change it, change the `ports:` line too. |
| `DATACLEANER_SEARXNG_URL` | | SearXNG to use for web search. |
| `DATACLEANER_GOOGLE_CLIENT_ID`, `…_SECRET` | | Your Google OAuth app (see the README). Can also be entered in Settings. |
| `DATACLEANER_MICROSOFT_CLIENT_ID`, `…_SECRET` | | Your Microsoft OAuth app. Can also be entered in Settings. |
| `DATACLEANER_SCHEDULER` | `true` | Run follow-ups and scans inside the web process. |
| `DATACLEANER_SCHEDULER_INTERVAL` | `300` | Seconds between scheduler runs. |

Every secret (`DATACLEANER_SECRET_KEY`, the client IDs and secrets, `DATACLEANER_DATABASE_URL`) can also be read from a file: add `_FILE` to the name. See [Secrets](#secrets).

---

## Behind a reverse proxy

1. Put `datacleaner` on the same Docker network as your proxy, and remove its `ports:` line.
2. Set `DATACLEANER_BASE_URL` to the public address, e.g. `https://privacy.example.com`. The app only answers requests for that host name (this blocks DNS-rebinding attacks), so without it you'll see *"Unknown host"*.
3. Set `DATACLEANER_TRUSTED_PROXIES` to the proxy's network. Find it with
   `docker network inspect <network> -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}'`.
   Without it, the app sees every visitor as the proxy's address.
4. If you use Google or Microsoft sign-in, the redirect URI in your OAuth app must be `DATACLEANER_BASE_URL` + `/auth/google/callback` (or `/auth/microsoft/callback`).

Please only expose Data Cleaner over HTTPS. It holds exactly the information a stalker or identity thief wants.

### Traefik

```yaml
services:
  datacleaner:
    # ...the service from above, without ports:...
    networks: [proxy, default]      # proxy for Traefik, default to reach searxng
    environment:
      DATACLEANER_BASE_URL: https://privacy.example.com
      DATACLEANER_TRUSTED_PROXIES: 172.18.0.0/16      # your proxy network's subnet
    labels:
      - traefik.enable=true
      - traefik.docker.network=proxy
      - traefik.http.routers.datacleaner.rule=Host(`privacy.example.com`)
      - traefik.http.routers.datacleaner.entrypoints=websecure
      - traefik.http.routers.datacleaner.tls.certresolver=letsencrypt
      - traefik.http.services.datacleaner.loadbalancer.server.port=25326

networks:
  proxy:
    external: true
```

`searxng` stays on the stack's default network with no labels, so it's never exposed.

### Caddy

```caddyfile
privacy.example.com {
    reverse_proxy datacleaner:25326
}
```

### Nginx Proxy Manager

Add a **Proxy Host**: domain `privacy.example.com`, scheme `http`, forward hostname `datacleaner`, forward port `25326`. On the SSL tab, request a certificate and turn on **Force SSL**. Set `DATACLEANER_TRUSTED_PROXIES` to NPM's network.

### nginx / SWAG

```nginx
location / {
    proxy_pass http://datacleaner:25326;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### Tailscale instead of a public domain

`tailscale serve --bg 25326` on the Docker host gives you `https://<machine>.<tailnet>.ts.net`, reachable only from your own devices. Set `DATACLEANER_BASE_URL` to that address.

---

## Where the data lives

**A named volume** (`datacleaner-data:/data`, as above) is the simplest choice and needs no permission setup.

**A bind mount** (a folder on the host) must belong to the container's user, `10001`:

```bash
mkdir -p ./datacleaner-data && sudo chown 10001:10001 ./datacleaner-data
```
```yaml
    volumes:
      - ./datacleaner-data:/data
```

**Your own user ID** (like the `PUID`/`PGID` other images use): set `user:` and give that user the bind-mounted folder.

```yaml
    user: "1000:1000"
    volumes:
      - ./datacleaner-data:/data     # owned by 1000:1000
```

A custom `user:` doesn't work with a named volume, because the volume belongs to `10001`. If the folder isn't writable, Data Cleaner stops at start-up and prints the exact `chown` command to run.

Keep `/data` on a local disk. The database is SQLite, which isn't reliable on NFS or SMB shares.

---

## Secrets

A `.env` file with `chmod 600` is fine for most setups. To keep secrets out of environment variables, use Docker secrets with the `_FILE` variants:

```yaml
services:
  datacleaner:
    environment:
      DATACLEANER_SECRET_KEY_FILE: /run/secrets/datacleaner_secret_key
    secrets: [datacleaner_secret_key]

secrets:
  datacleaner_secret_key:
    file: ./secrets/datacleaner_secret_key.txt
```

The container runs as user `10001`, so the file must be readable by it:

```bash
mkdir -p secrets && openssl rand -base64 48 > secrets/datacleaner_secret_key.txt
sudo chown 10001:10001 secrets/datacleaner_secret_key.txt && sudo chmod 400 secrets/datacleaner_secret_key.txt
```

Docker Compose ignores `uid`/`mode` options on secrets outside Swarm, so set the ownership on the file itself.

---

## Using your own SearXNG

Point `DATACLEANER_SEARXNG_URL` at it, e.g. `http://my-searxng:8080` (a stock SearXNG container listens on 8080 unless `GRANIAN_PORT` says otherwise). Your SearXNG must allow JSON results:

```yaml
search:
  formats: [html, json]
```

If its rate limiter (`server.limiter`) is on, allow Data Cleaner's network or the searches will be blocked. Without any SearXNG, you can use a Brave Search API key in Settings, or skip web search. People-search sites are still checked directly.

---

## Updating

```bash
docker compose pull datacleaner && docker compose up -d datacleaner
```

The database upgrades itself on start. To control when updates happen, pin a release (`ghcr.io/fearinc4/data-cleaner:0.1.0`) and let Renovate, Dependabot or Diun tell you about new ones.

Every published image is signed in GitHub Actions with [Sigstore](https://www.sigstore.dev) and carries an SBOM and build provenance. To check an image really came from this repository:

```bash
cosign verify ghcr.io/fearinc4/data-cleaner:latest \
  --certificate-identity-regexp '^https://github.com/FearInc4/Data-cleaner/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

---

## Backup and restore

Stop the app first so the database is consistent:

```bash
docker compose stop datacleaner
docker compose cp datacleaner:/data ./datacleaner-backup
docker compose start datacleaner
```

The backup holds your encrypted personal data, so keep it somewhere private. If you didn't set `DATACLEANER_SECRET_KEY`, the backup includes the key (`secret.key`) and anyone with the backup can read it.

To restore into a new or empty volume (for example on another machine, with the same `DATACLEANER_SECRET_KEY`):

```bash
docker compose create datacleaner
docker compose run --rm --no-deps --user root --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
  -v "$PWD/datacleaner-backup:/backup:ro" --entrypoint sh datacleaner \
  -c 'cp -a /backup/. /data/ && chown -R 10001:10001 /data'
docker compose up -d datacleaner
```

For a bind mount, copy the folder back and run `sudo chown -R 10001:10001` on it.

---

## Portainer, Unraid, Synology, CasaOS

All of these run Docker Compose files:

- **Portainer:** Stacks → Add stack → paste [`compose.yaml`](../deploy/compose/compose.yaml), and add the variables under *Environment variables*.
- **Synology (Container Manager):** Project → Create → upload `compose.yaml` and a `.env`.
- **Unraid:** use the *Compose Manager* plugin and paste the file. Unraid's usual `/mnt/user/appdata/datacleaner` bind mount needs `chown 10001:10001` (see [Where the data lives](#where-the-data-lives)).
- **CasaOS / ZimaOS:** App Store → Custom Install → Import, then paste the file.

If your platform's Compose is older than 2.23.1 and rejects the inline `configs:` block, use the file-based variant described under [Add it to your existing stack](#add-it-to-your-existing-stack).

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Unknown host 'privacy.example.com'` | Set `DATACLEANER_BASE_URL` to the address you open, or add the name to `DATACLEANER_ALLOWED_HOSTS`. |
| `Data Cleaner can't write to its data folder /data` | The bind-mounted folder belongs to someone else. Run the `chown` command from the message. |
| `Can't read DATACLEANER_SECRET_KEY_FILE` | The secret file isn't readable by user `10001`. See [Secrets](#secrets). |
| SearXNG restarts with `Address family not supported by protocol` | Add `GRANIAN_HOST: 0.0.0.0` to the `searxng` service. |
| Web search finds nothing | Check `docker compose logs searxng`. Your SearXNG must allow `json` (see above). |
| Google says `redirect_uri_mismatch` | The OAuth app's redirect URI must be `DATACLEANER_BASE_URL` + `/auth/google/callback`. |
| Google says `Access blocked: … has not completed the Google verification process` | Your Google app is still in Testing. Press **Publish app** on [Audience](https://console.cloud.google.com/auth/audience), or add your address under Test users there. |
| Google won't accept the redirect URI (`must use https` / `must end with a public top-level domain`) | Google allows only `https://` or `http://localhost`. Open Data Cleaner at `http://localhost:25326` (on the server, or through `ssh -L 25326:localhost:25326 you@server`), or put it behind HTTPS. |
| Lost the setup link | `docker compose exec datacleaner cat /data/setup-token`, then open `<your address>/setup?token=<that token>`. It only works until the first account exists. |
| Port 25326 is taken | Change the left side of `ports:` (e.g. `127.0.0.1:8099:25326`), or set `DATACLEANER_PORT`. |
| Is it healthy? | `docker inspect -f '{{.State.Health.Status}}' datacleaner` |
| `docker pull` says unauthorized | Run `docker logout ghcr.io` and try again (an expired login breaks anonymous pulls). |

## Building the image yourself

```bash
git clone https://github.com/FearInc4/Data-cleaner.git && cd Data-cleaner
docker compose up -d --build        # uses the repo's docker-compose.yml, which builds from source
```
