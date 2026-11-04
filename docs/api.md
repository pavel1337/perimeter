# REST API

The REST API lives under `/api/v1` on the Perimeter host. It reads targets, their scan results, tags, the summary and the change feed, and it makes the same target and tag changes as the web UI. The [MCP server](mcp.md) uses the same code, so both make the same changes and write the same audit rows.

The OpenAPI description is at `/api/v1/openapi.yaml`. It needs no token.

The examples use `https://perimeter.example.com` and a `prm_...` placeholder token. Send `Content-Type: application/json` with request bodies. Responses are abbreviated where marked with `...`.

## Tokens and permissions

Create a token on the Account page. Choose:

- a name (1 to 100 characters);
- a scope, `read` or `write`;
- an expiry: 30 days, 90 days, 1 year, or never.

The raw token has the form `prm_` followed by 40 characters from `a` to `z` and `2` to `7`. It is shown once. Perimeter stores only its SHA-256 hash, so a lost token cannot be shown again: revoke it and create a new one. If your account has two-factor authentication on, creating a token needs a current code.

A request is allowed only when both the token scope and the role of the user who made the token allow it:

| Token scope | Role | Reads | Writes |
|-------------|------|-------|--------|
| `read` | admin, member, viewer | yes | no |
| `write` | admin, member | yes | yes |
| `write` | viewer | yes | no (403) |

Viewers can only create read tokens, so a viewer has a write token only if their role was lowered after the token was made. The role is read on every request, so a change applies at once. A role change does not revoke tokens.

Admin-only operations (users, invites, roles, importers, notifiers, tag creation and deletion, settings) are not part of the API.

A token stops working when it expires, when it is revoked (by its owner on the Account page, or by an admin on the Settings page), when an admin resets its owner's two-factor authentication, or when its owner is deleted. Expired and revoked tokens get the same `401` as unknown ones.

## Authentication

Send the token in the `Authorization` header. The `Bearer` scheme name is not case-sensitive:

```bash
curl -H "Authorization: Bearer prm_..." https://perimeter.example.com/api/v1/me
```

Session cookies are not accepted on `/api/v1`. A request without a valid bearer token gets `401`.

## Errors

Every error has the same body, with the matching HTTP status:

```json
{"error":{"code":"invalid_request","message":"tags: unknown tags: nope (tags are created by an admin in the UI)"}}
```

| Status | Code | Meaning |
|--------|------|---------|
| 400 | `invalid_request` | A parameter or body is wrong. The message names the field. |
| 401 | `unauthorized` | Missing, malformed, unknown, revoked or expired token. |
| 403 | `forbidden` | The token is read-only, or the user's role cannot change data. |
| 404 | `not_found` | No such target, or no such endpoint under `/api/v1`. |
| 409 | `conflict` | An `Idempotency-Key` was reused for a different request, or the first request with that key is still running. |
| 429 | `rate_limited` | Over the rate limit. See below. |
| 500 | `internal` | Unexpected error. The message says to check the server log, which has the details. |

## Pagination

`GET /api/v1/targets` and `GET /api/v1/targets/{id}/history` return pages:

- `limit` is the page size: 50 by default, at most 200. A larger value is capped, not refused. Zero or a negative value is a `400`.
- A page has `items`, `total` (the number of matches) and, when another page follows, `next_cursor`. Pass it back as `cursor` to get the next page. The cursor is opaque: do not build or parse it.

```bash
curl -H "Authorization: Bearer prm_..." "https://perimeter.example.com/api/v1/targets?limit=2"
```

```json
{"items":[{"id":1,"input":"a.example.com", ...},{"id":2,"input":"b.example.com", ...}],"total":5,"next_cursor":"Mg"}
```

`GET /api/v1/changes` is paged by time instead; see [Polling for changes](#polling-for-changes).

## Rate limit

Each token may make 120 requests per minute. Every request counts, including the MCP calls made with the same token. A request over the limit gets `429` with the `rate_limited` code and a `Retry-After` header, in whole seconds. Wait that long before you retry.

`GET /api/v1/openapi.yaml` is not limited.

## Idempotency

A write that is retried after a timeout must not change things twice. Optionally send an `Idempotency-Key` header with any `POST`, `PUT` or `DELETE` under `/api/v1`:

```bash
curl -X POST -H "Authorization: Bearer prm_..." -H "Idempotency-Key: onboard-2026-10-12-01" \
  -H "Content-Type: application/json" -d '{"targets":["example.com"]}' \
  https://perimeter.example.com/api/v1/targets
```

- The key is 1 to 255 printable ASCII characters. Anything else is a `400`.
- The first request with a key runs, and its answer is kept. A repeat with the same key, method, path and body gets the kept answer, with the header `Idempotent-Replayed: true`, and makes no change.
- A key reused with a different request gets `409`. So does a repeat that arrives while the first request is still running. Wait and send it again.
- Keys are scoped to the token, so two tokens may use the same key.
- A key is remembered for 24 hours from its first request. A retry after that is a new request.
- Answers with status 401, 403, 429 or 5xx are not kept, so a refused or failed request runs again when it is retried. Every other answer is kept and replayed, including 400 and 404.
- Keys live in the memory of one server process. A restart forgets them, and a second server process does not see them. The store holds at most 10,000 keys and 64 MiB of replies; the oldest are dropped first.

## Endpoints

### GET /api/v1/me

Who the token belongs to. Any token can call it.

```bash
curl -H "Authorization: Bearer prm_..." https://perimeter.example.com/api/v1/me
```

```json
{"email":"alice@example.com","name":"Alice","role":"member","token":{"name":"ci","scope":"write","prefix":"prm_k2x8q4wz","expires_at":"2027-01-10T09:00:00Z"}}
```

`expires_at` is left out for a token that never expires. The raw token is never returned.

### GET /api/v1/summary

Totals over the live targets, the certificates expiring soon, and the recent changes.

```bash
curl -H "Authorization: Bearer prm_..." https://perimeter.example.com/api/v1/summary
```

```json
{"totals":{"targets":42,"by_reachability":{"ok":38,"pending":1,"unreachable":2,"unresolved":1},"open_ports":57,"csp_issues":11,"expiring_certs":3,"expired_certs":1,"weak_ssl":4,"ssl_unscanned":2},"ssl_scanning":true,"expiring":[ ... ],"recent_changes":[ ... ]}
```

`expiring_certs` counts certificates that are not yet expired but expire within `CERT_EXPIRY_WINDOW` (30 days by default), and `expired_certs` those already expired. `weak_ssl` counts targets graded C or worse, including F, T and M. `ssl_unscanned` counts live targets with no SSL grade yet. `ssl_scanning` is `false` when the server has SSL scanning off (no SSL Labs credentials), and then the SSL and certificate totals are always empty. `expiring` holds target summaries, and `recent_changes` holds changes in the same shape as the change feed.

### GET /api/v1/targets

Lists live targets. Every parameter is optional, and they combine with AND.

| Parameter | Meaning |
|-----------|---------|
| `q` | The input contains this text, ignoring case. |
| `tag` | The target has this tag. |
| `state` | Reachability: `ok`, `unreachable`, `unresolved` or `pending`. Repeat it, or separate values with commas. |
| `ssl_below` | SSL grade worse than this one. `B` keeps `C` and everything below it, including `T` and `M`. Ungraded targets are not kept. |
| `ssl_grade` | SSL grade exactly this one. |
| `csp` | `issues` (has findings), `ok` (no findings) or `none` (never checked). |
| `port` | Some IP address of the target has this TCP port open, 1 to 65535. |
| `expiring_within_days` | The certificate expires within this many days from now, counting the whole last day. Expired certificates are included. |
| `deleted` | `true` lists soft-deleted targets instead, most recently deleted first, each with the reachability it had when deleted. Only `q`, `state`, `limit` and `cursor` may be combined with it; `state=ok` lists the targets that still answered when they were deleted. |
| `sort` | `target` (the default, by input), `csp`, `ports`, `ssl` (best grade first) or `expiry` (soonest first). |
| `order` | `asc` (the default) or `desc`. |
| `limit`, `cursor` | Paging, see above. |

```bash
curl -H "Authorization: Bearer prm_..." "https://perimeter.example.com/api/v1/targets?tag=prod&ssl_below=B&sort=ssl&limit=20"
```

```json
{"items":[{"id":12,"input":"shop.example.com","is_ip":false,"reachability":"ok","tags":["prod"],"ssl_grade":"C","cert_expiry":"2026-11-20T00:00:00Z","cert_days_left":39,"csp_findings":3,"open_ports":2,"created_at":"2026-03-01T10:00:00Z"}],"total":1}
```

Each item is a target summary. `ssl_grade`, `cert_expiry`, `cert_days_left` and `csp_findings` are left out until the target has been scanned for them. `deleted_at` appears only with `deleted=true`.

### POST /api/v1/targets

Starts tracking targets. Body: `{"targets": [...]}` with 1 to 1000 entries. Each entry is a hostname, an IP address or a URL, which is reduced to its host. Adding is additive and safe to repeat: targets already tracked are left as they are, and soft-deleted ones are restored with their history. New targets are scanned on the next cycles. Entries that are not valid hosts are listed in `invalid` and do not fail the request. The reply is `200`.

```bash
curl -X POST -H "Authorization: Bearer prm_..." -H "Content-Type: application/json" \
  -d '{"targets":["https://Shop.example.com/login","10.0.0.7","bad host!"]}' \
  https://perimeter.example.com/api/v1/targets
```

```json
{"added":["shop.example.com","10.0.0.7"],"existing":[],"restored":[],"invalid":["bad host!"],"targets":[{"id":12,"input":"shop.example.com","status":"added"},{"id":13,"input":"10.0.0.7","status":"added"}]}
```

`targets` lists the targets the call touched, each with a `status` of `added`, `existing` or `restored`.

### GET /api/v1/targets/{id}

One target with its newest scan of each kind. Returns `404` for an unknown or soft-deleted target.

```bash
curl -H "Authorization: Bearer prm_..." https://perimeter.example.com/api/v1/targets/12
```

```json
{"id":12,"input":"shop.example.com","is_ip":false,"reachability":"ok","tags":["prod"],"ssl_grade":"C","open_ports":2,"created_at":"2026-03-01T10:00:00Z","ips":[{"address":"203.0.113.10","open_ports":[80,443],"last_checked":"2026-10-12T09:00:00Z"}],"ssl":{"grade":"C","status":"READY","cert_subject":"shop.example.com","cert_issuer":"Example CA","cert_expiry":"2026-11-20T00:00:00Z","protocols":["TLS 1.2","TLS 1.3"],"first_seen":"...","last_checked":"..."},"csp":{"header":"default-src 'self'","findings":[ ... ],"first_seen":"...","last_checked":"..."}}
```

The target summary fields are followed by `ips`, and by `ssl` and `csp` when those have been scanned. `resolve_error` is present when the last lookup failed, and `resolved_at` is the time of the last lookup that succeeded. Names are looked up again every `RESOLVE_INTERVAL` (1h by default): a name that no longer resolves loses its IPs and becomes `unresolved`, and a moved name is linked to its new IPs. `ssl.status` is the SSL Labs status of the scan. `stale: true` on an IP, `ssl` or `csp` means its last check is more than twice its scan interval old: the scanner fell behind or the target wasn't scanned. The summary counts these under `totals.stale`. `cert_problems` says why a certificate is not trusted (self-signed, name mismatch, untrusted chain, expired, ...), the reason behind a T or M grade. A self-signed or name-mismatch certificate is not ours to renew, so it has no `cert_expiry` and is left out of the expiring and expired counts. `csp.status_code` and `csp.final_url` are the HTTP status and the URL the CSP probe ended on; CSP is only judged on 2xx responses, so a 401 or 404 page has no findings and does not count as a CSP issue. `csp.tls_problem` is set when the certificate failed verification and the probe read the response without verifying it; a `final_url` starting with `http://` means nothing answered TLS on port 443. `csp.redirect_host` is set when the target redirects to another site (a third-party sign-in page, for example): the probe stops there and the CSP is not judged. When the newest SSL check failed, `ssl.last_check_error` says why and `ssl.last_check_failed_at` when; the grade and certificate are then the last real result, and the check is retried within 30 minutes.

### GET /api/v1/targets/{id}/history

The scan history of one target, newest first, paged like the list.

```bash
curl -H "Authorization: Bearer prm_..." "https://perimeter.example.com/api/v1/targets/12/history?limit=2"
```

```json
{"items":[{"kind":"csp","first_seen":"2026-10-12T09:00:00Z","last_checked":"2026-10-12T09:00:00Z","summary":"CSP 2 findings","findings_count":2},{"kind":"ssl","first_seen":"2026-10-11T09:00:00Z","last_checked":"2026-10-11T09:00:00Z","summary":"grade C","grade":"C"}],"total":2}
```

`kind` is `ssl`, `csp` or `ports`. Port entries also have `ip` and `ports`. An entry whose scan failed has an `error`.

### PUT /api/v1/targets/{id}/tags

Replaces the tags of a target. Body: `{"tags": ["prod", "web"]}`. An empty list (`[]`) removes every tag. A missing `tags` key is a `400`, so `{}` does not clear anything. Every name must already exist, because admins create tags in the web UI. If any name is unknown the reply is `400` and nothing changes.

```bash
curl -X PUT -H "Authorization: Bearer prm_..." -H "Content-Type: application/json" \
  -d '{"tags":["prod","web"]}' https://perimeter.example.com/api/v1/targets/12/tags
```

The reply is the target summary, with the new tags.

### POST /api/v1/targets/{id}/tags

Adds tags to a target and keeps the ones it has. Body: `{"tags": ["prod"]}`. The reply is the target summary. The same rules as for `PUT` apply.

### DELETE /api/v1/targets/{id}/tags/{tag}

Removes one tag. Percent-encode a tag name that has spaces (`%20`). The reply is the target summary.

```bash
curl -X DELETE -H "Authorization: Bearer prm_..." https://perimeter.example.com/api/v1/targets/12/tags/web
```

### DELETE /api/v1/targets/{id}

Soft-deletes a target. It leaves the lists and is no longer scanned, but its history is kept and it can be restored. The reply is `204 No Content`.

```bash
curl -X DELETE -H "Authorization: Bearer prm_..." https://perimeter.example.com/api/v1/targets/12
```

### POST /api/v1/targets/{id}/restore

Brings back a soft-deleted target with its history. The reply is the target summary. Returns `404` when there is no such soft-deleted target.

```bash
curl -X POST -H "Authorization: Bearer prm_..." https://perimeter.example.com/api/v1/targets/12/restore
```

### POST /api/v1/targets/{id}/rescan

Queues an on-demand scan of one target. The reply is `202`:

```json
{"status":"queued"}
```

or, when the target was rescanned less than `RESCAN_COOLDOWN` ago (10 minutes by default), nothing is queued and the reply says when a rescan is allowed:

```json
{"status":"cooling_down","retry_at":"2026-10-12T09:10:00Z"}
```

That reply also sends a `Retry-After` header, in seconds. `404` is returned for an unknown or soft-deleted target.

```bash
curl -X POST -H "Authorization: Bearer prm_..." https://perimeter.example.com/api/v1/targets/12/rescan
```

### POST /api/v1/rescan

Queues on-demand scans of up to 500 targets. Body: `{"ids": [12, 15]}`. The reply is `202`:

```json
{"queued":[12],"cooling_down":[{"id":15,"retry_at":"2026-10-12T09:10:00Z"}],"not_found":[99999]}
```

Unknown and soft-deleted ids are listed in `not_found`, and the call still returns `202`. A queued scan runs the port scan and the CSP check, and the SSL Labs check when SSL scanning is configured. Scans run in the background, so the results appear later: read the target or the change feed afterwards.

```bash
curl -X POST -H "Authorization: Bearer prm_..." -H "Content-Type: application/json" \
  -d '{"ids":[12,15]}' https://perimeter.example.com/api/v1/rescan
```

### GET /api/v1/tags

Every tag, with the number of live targets that carry it. Not paged.

```bash
curl -H "Authorization: Bearer prm_..." https://perimeter.example.com/api/v1/tags
```

```json
{"items":[{"id":1,"name":"prod","color":"#6b7280","target_count":12}]}
```

### GET /api/v1/changes

The change feed. See the next section.

## Polling for changes

`GET /api/v1/changes` lists what changed after a time, oldest first. `since` is required and is an RFC 3339 time:

```bash
curl -H "Authorization: Bearer prm_..." "https://perimeter.example.com/api/v1/changes?since=2026-10-11T00:00:00Z"
```

```json
{"items":[{"at":"2026-10-11T08:15:00.123456789Z","target_id":12,"target":"shop.example.com","kind":"ssl_grade_changed","from":"B","to":"C","summary":"shop.example.com: SSL grade B to C"}],"truncated":false,"until":"2026-10-11T08:15:00.123456789Z"}
```

- A change is listed only when it is after `since`.
- `limit` is the number of changes per reply: 200 by default, at most 1000.
- `until` is the time of the last change in the reply, or `since` itself when there is none. It is written with nanoseconds, so passing it back does not repeat a change.
- When `truncated` is `true`, more changes follow. Call again at once with `since` set to `until`.
- When `truncated` is `false`, wait, then call again with `since` set to `until`.
- A reply never splits changes that share a time, so it can hold a few more than `limit`, or a few less.
- A target's first results count as changes: its first SSL grade (from none), its first CSP result (from `not checked`), and the ports open on its IP's first answered scan.

Change kinds: `target_added`, `target_deleted`, `ssl_grade_changed`, `cert_renewed`, `ports_opened`, `ports_closed`, `csp_changed`, `became_unreachable`, `became_reachable` and `dns_changed`. `dns_changed` is a name that moved to new IPs (none of the old ones kept), no longer resolves, or resolves again; IP changes that keep some old IPs, as CDNs rotate them, are only in the target history. `from` and `to` are set when the change has a before and an after value, and `ip` when it concerns one address.

## Audit log

Every successful write adds a row to the audit log, including a tag write that changes nothing: the action (`target.import`, `target.tags`, `target.delete`, `target.restore` or `target.rescan`), the target, the detail, the owner's email, the source (`api` for REST, `mcp` for MCP) and the token prefix. Rows are not changed or deleted by the API.

Admins read the log on the web UI, under Settings, with "All audit events". The API has no endpoint for it.

## OpenAPI

The full description, with every parameter and schema, is at `/api/v1/openapi.yaml`:

```bash
curl https://perimeter.example.com/api/v1/openapi.yaml
```
