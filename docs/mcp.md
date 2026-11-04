# MCP server

Perimeter serves a [Model Context Protocol](https://modelcontextprotocol.io) server at `/mcp`. An agent that speaks MCP can read the attack surface, follow changes, and, with a write token, track targets and start scans. It is a second front end to the same service as the [REST API](api.md): the same limits apply, and every write is recorded in the audit log with source `mcp`.

The examples use `https://perimeter.example.com` and a `prm_...` placeholder token.

## Tokens

Create a token on the Account page, as described in [Tokens and permissions](api.md#tokens-and-permissions). Use a read token unless the agent must change things. The `/mcp` endpoint takes only a bearer token in the `Authorization` header; a session cookie is not accepted.

The token scope and your role decide which tools are listed. The server builds its tool list for each request from the token and the current role:

- Read tools are listed for every token.
- Write tools are listed only for a `write` token whose owner is an admin or member. A read-only caller does not see them at all. The instructions sent at connection say which case applies and, for a read-only connection, why (read token or viewer role), so an agent can tell the user what to change.

## Tools

### Read tools

| Tool | What it does |
|------|--------------|
| `summary` | Totals by reachability, open ports, CSP issues, expiring and expired certificates, the weakest SSL grades, the soonest expiries, and recent changes. Call it first. |
| `list_targets` | Targets, one line each. Filters: `query`, `tag`, `state`, `ssl_below`, `port`, `csp`, `expiring_within_days`, `deleted`. Sort with `sort` and `desc`. |
| `get_target` | One target: its IP addresses and open ports, the newest SSL scan and the newest CSP evaluation. |
| `target_history` | Scan history of one target, newest first. |
| `find_issues` | Targets that need attention, grouped by category with a reason for each. Categories: `weak_ssl` (configuration grades worse than B), `untrusted_certs` (T or M grades, with the reason such as self-signed or name mismatch), `expiring_certs` (self-signed and name-mismatch certificates left out), `expired_certs`, `csp_issues`, `unreachable`, `unresolved`, `open_port` (needs `port`). |
| `changes_since` | Changes after a time, oldest first. `since` is an RFC 3339 time, a duration such as `24h`, or whole days such as `7d`. |
| `list_tags` | Every tag, with the number of live targets carrying it. |

The `target` argument of `get_target` and `target_history` is a target id such as `12`, or a name such as `example.com`.

### Write tools

These are listed only for write tokens of admins and members.

| Tool | What it does |
|------|--------------|
| `add_targets` | Starts tracking hosts, IP addresses or URLs (reduced to the host). Adding is additive and safe to repeat. Up to 1000 entries per call. |
| `set_tags` | Changes the tags of one target. `mode` is `add` (the default), `remove` or `replace` (sets exactly this list, `[]` removes all). The tags must already exist; admins create them in the web UI. |
| `delete_target` | Soft-deletes a target. Its history is kept. |
| `restore_target` | Brings a soft-deleted target back with its history. |
| `rescan` | Queues scans of up to 50 targets, given as names or ids. A target that was scanned recently is not queued, and the reply gives its `retry_at` time. |

Admin-only operations (users, invites, roles, importers, notifiers, tag creation and deletion, settings) are not available through MCP.

## Limits

- `list_targets`, `target_history` and `find_issues` return 25 items by default and at most 100 per call. Pass `offset` to read the next page; the reply names the next offset when more exist. `find_issues` applies `limit` and `offset` to each category.
- `changes_since` returns 25 changes by default and at most 100. `until` is the time of the last change, or `since` when there is none. When `truncated` is true, call again at once with `since` set to `until`; otherwise poll later from `until`.
- `rescan` takes at most 50 targets per call. The REST rescan endpoint takes up to 500.
- Every MCP call counts against the token's limit of 120 requests per minute, the same limit as the REST API. A call over the limit fails with HTTP 429 and a `Retry-After` header.

Results come from periodic scans, so they can be hours old. A `rescan` queues work that finishes later: check `get_target` or `changes_since` after it.

## Setup

### Claude Code

Replace the token with the one you created:

```bash
claude mcp add --transport http perimeter https://perimeter.example.com/mcp --header "Authorization: Bearer prm_..."
```

The token page shows this line with the token and host filled in.

### Claude Desktop

Claude Desktop connects to remote servers through the `mcp-remote` bridge, which needs Node.js for `npx`. Add this to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "perimeter": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://perimeter.example.com/mcp", "--header", "Authorization:${PERIMETER_AUTH}"],
      "env": {"PERIMETER_AUTH": "Bearer prm_..."}
    }
  }
}
```

The header value is passed through an environment variable, not as a space-separated argument, because Claude Desktop on Windows splits arguments at spaces. Restart Claude Desktop after editing the file. The Connectors screen is for servers that use OAuth, so it does not take a bearer token.

### Other clients

Any client that can send HTTP POST requests can use the endpoint:

- Send each JSON-RPC message as a POST to `/mcp` with `Content-Type: application/json`, `Accept: application/json, text/event-stream` and the `Authorization: Bearer prm_...` header. A request without the `Accept` header is refused with `400`.
- The server is stateless. It returns no `Mcp-Session-Id`, and each POST stands alone, so a client does not need to keep a session.
- Replies are plain JSON, not server-sent events.

```bash
curl -X POST https://perimeter.example.com/mcp \
  -H "Authorization: Bearer prm_..." \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"summary","arguments":{}}}'
```

The result has a text part for reading and the same data as structured content. A failed tool call is reported in the result, with the reason in the text.

## Example requests

Ask the agent things like:

- "Give me an overview of the attack surface." (`summary`)
- "Which targets have a weaker SSL grade than B?" (`list_targets` with `ssl_below`, or `find_issues`)
- "Which certificates expire in the next 14 days?" (`find_issues` with `expiring_within_days`)
- "What changed on example.com in the last 24 hours?" (`changes_since` with `since` set to `24h`)
- "Track these hosts: shop.example.com, 10.0.0.7." (`add_targets`, with a write token)
- "Rescan the targets tagged prod, then tell me when the results are in." (`list_targets`, then `rescan`, then `changes_since`)

## Safety

- Give an agent a read token unless it has to change targets. A read token cannot see or call the write tools.
- Use a write token only for the agent that needs it, and revoke it when the work is done. Revoking takes effect on the next call.
- Every write made through MCP is in the audit log, with the source `mcp` and the token prefix. Admins see the log under Settings.
- Deleting is soft: `delete_target` keeps the history, and `restore_target` undoes it.
- Each token has its own rate limit, so one busy agent cannot starve another token, but it can use up its own 120 requests per minute.
