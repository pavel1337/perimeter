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

SSL Labs needs registration details (`FIRST_NAME`, `LAST_NAME`, `EMAIL`, `ORGANIZATION`). OIDC login is optional (`OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URL`).

## Build

```bash
go build -o perimeter      # binary
make generate              # regenerate Ent code after schema changes
go test ./...              # run tests
```

## How it works

- **Web** (`internal/server`) — Fiber routes, HTML templates in `views/`.
- **Scanner** (`internal/scanner`) — job queue plus a worker pool. Producers queue scans; workers run them.
- **Storage** (`internal/storage`) — all database access, backed by the Ent ORM.
- **Scanners** (`scanner/`) — the port, SSL, and CSP logic.

## License

[AGPL-3.0](LICENSE).
