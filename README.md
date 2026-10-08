# Perimeter

Perimeter watches the security posture of your web targets. Give it a list of hostnames or IPs and it runs background scans for open ports, SSL/TLS config (via Qualys SSL Labs), and Content Security Policy headers. Results show up in a simple web dashboard.

> **Status:** work in progress. Auth and accounts exist, but the app is **single-tenant** — every user sees every target. Don't host it for untrusted users yet.

## Features

- Port scanning (TCP connect)
- SSL/TLS grading via the SSL Labs API
- CSP header checks (9 common weaknesses)
- Background workers on a configurable schedule
- Target import from Hetzner Cloud, Hetzner Robot, Namecheap, Gandi, and DNS brute-force
- Webhook notifications
- Web UI with email/password or OIDC login
- SQLite or PostgreSQL storage

## Quick start

Requires Go 1.25+.

```bash
git clone https://github.com/pavel1337/perimeter.git
cd perimeter
cp .env.example .env   # then edit it
make run               # or: go run main.go --targets targets.lst
```

Open http://localhost:3000. The first account you register becomes the admin.

## Config

Set values in `.env` or pass CLI flags (flags win). Common ones:

| Env | Flag | Default | What |
|-----|------|---------|------|
| `HTTP_PORT` | `--port` | `3000` | Web server port |
| `DB_DRIVER` | `--dbDriver` | `sqlite3` | `sqlite3` or `postgres` |
| `DB_PATH` | `--db` | `perimeter.db` | SQLite file path |
| `DB_DSN` | `--dbDSN` | — | Postgres DSN (when driver is `postgres`) |
| `WORKER_COUNT` | `--workers` | `3` | Concurrent scan workers |
| `PORT_INTERVAL` | `--portInterval` | `1h` | Time between port scans |
| `SSL_INTERVAL` | `--sslInterval` | `12h` | Time between SSL scans |
| `CSP_INTERVAL` | `--cspInterval` | `1h` | Time between CSP scans |
| `CERT_EXPIRY_WINDOW` | `--certExpiryWindow` | `720h` | How close to expiry a certificate is flagged on the dashboard |

SSL Labs needs registration details (`FIRST_NAME`, `LAST_NAME`, `EMAIL`, `ORGANIZATION`). OIDC login is optional (`OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URL`).

The email notifier needs an SMTP server: set `SMTP_HOST`, `SMTP_PORT` (default `587`), `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` and `SMTP_TLS` (`starttls` by default, `tls` for implicit TLS on port 465, or `none` for a local relay). Leave `SMTP_HOST` empty to disable email. Notifiers are added on the Settings page, where each one can be limited to some event types.

## Build

```bash
make build                 # static binary (CGO-less)
make generate              # regenerate Ent code after schema changes
make test                  # run tests
make lint                  # golangci-lint + format check
```

## Docker

```bash
docker compose up --build  # app + PostgreSQL
```

The app listens on http://localhost:3000 and stores data in the bundled
Postgres. Configure via the `environment:` block in `docker-compose.yml`.
Published images live at `ghcr.io/pavel1337/perimeter`.

## Versioning & releases

Versioning is automatic, driven by git tags (`vMAJOR.MINOR.PATCH`):

- Every push to `main` bumps the **patch** version and, once lint and tests
  pass, builds and pushes `ghcr.io/pavel1337/perimeter:<version>` and `:latest`,
  then creates the matching `v<version>` git tag.
- For a **minor** or **major** bump, push a tag yourself — the next push to
  `main` continues patch bumps from there:

  ```bash
  git tag v0.3.0 && git push origin v0.3.0   # minor
  git tag v1.0.0 && git push origin v1.0.0   # major
  ```

  (Pushing a tag doesn't trigger CI, so it won't double-build.)

## How it works

- **Web** (`internal/server`) — Fiber routes, HTML templates in `views/`.
- **Scanner** (`internal/scanner`) — job queue plus a worker pool. Producers queue scans; workers run them.
- **Storage** (`internal/storage`) — all database access, backed by the Ent ORM.
- **Scanners** (`scanner/`) — the port, SSL, and CSP logic.

## License

[AGPL-3.0](LICENSE).
