# BLT Secure — Fleet Dashboard

> **Legacy — superseded by Buoy / BLT Connect (Ed25519 envelopes).** This
> channel is frozen: defect fixes only, no new features.

The hosted, multi-site console for BLT Secure (Phase 3). Runs on Cloudflare
Workers + D1; each client site running the plugin pushes a compact posture
snapshot here, and (v1) can be sent remote commands back.

This directory is **excluded from the plugin distribution** (`.distignore`
`/dashboard`) — it is operator infrastructure, not shipped to client sites.
The plugin's "zero runtime Composer dependency" rule applies only to the PHP
plugin; the Worker is a normal TS/Wrangler project.

This document is the contract the plugin (`Blt_Secure_Fleet`) reports against.

## Contract version 2 (breaking change from version 1)

There is no backward compatibility: a v1 plugin is rejected (`unsupported
schema`) and a v2 plugin will not act on an unsigned `/v1/commands` response.
Update the Worker and every enrolled site together. Changes from v1:

- Snapshot `schema` is **2**. `events` are counts of high-signal events
  **since the previous successful report** (deltas), not the plugin's running
  ring-buffer totals. The Worker drops a snapshot whose `reported_at` is not
  newer than the stored one, so a replay cannot double-count.
- The plugin only talks to an **https://** endpoint and uses
  `wp_safe_remote_*` with redirects disabled.
- `GET /v1/commands` requires an `X-BLT-Nonce` header (16-64 alphanumerics,
  fresh per request) and the response is **signed** (below). The plugin
  discards an unsigned or mis-signed list.
- Commands are re-delivered if not acknowledged within 15 minutes (delivery
  never means "done"), expire after 7 days, and at most 5 are handed out (and
  executed) per pull. The plugin persists the highest executed id and never
  runs an id at or below it.
- Operator routes verify the Cloudflare Access JWT and fail closed (see
  DEPLOY.md). `POST /admin/commands` needs `Content-Type: application/json`,
  a known command and an existing `site_id`; `POST /admin/sites/revoke`
  deletes a site and its token.

### Signed commands response

Response headers on `GET /v1/commands`:

| Header | Value |
| --- | --- |
| `X-BLT-Response-Timestamp` | Unix seconds |
| `X-BLT-Response-Nonce` | the request's `X-BLT-Nonce`, echoed |
| `X-BLT-Response-Signature` | `hex( hmac_sha256( "{ts}.{nonce}.{body}", response_key ) )` |

`response_key = hex( hmac_sha256( "blt-secure-fleet/v2/response-key", site_token ) )`
(the hex string itself is the HMAC key). The plugin checks the nonce matches
what it sent, the timestamp is within 5 minutes, and the signature, in
constant time.

Limitation (be honest about it): the site token is also the bearer secret, so
this proves the responder knows the token and defeats replay and blind
spoofing — it does not protect against a party that was already sent the token
over a broken transport, which is why https is mandatory. Closing that gap
(key-id separate from the signing secret) is what BLT Connect is for.

## Ingest contract (plugin → Worker)

`POST {endpoint}/v1/snapshot`

Headers:

| Header | Value |
| --- | --- |
| `Authorization` | `Bearer {site_token}` — per-site token issued at enrollment |
| `Content-Type` | `application/json` |
| `X-BLT-Timestamp` | Unix seconds when the body was signed |
| `X-BLT-Signature` | `hex( hmac_sha256( "{timestamp}.{body}", site_token ) )` |

The Worker MUST: look the token up in D1, recompute the HMAC over
`timestamp . "." . rawBody`, reject if it differs or the timestamp is older
than a few minutes (replay protection), then upsert the snapshot.

### Snapshot body (no secrets, no file contents)

```jsonc
{
  "schema": 2,
  "site": "https://example.com",     // home_url
  "name": "Example",                 // blogname
  "reported_at": 1700000000,
  "versions": { "plugin": "1.0.6", "wp": "6.5", "php": "8.2" },
  "health":   { "score": 92, "pass": 40, "warn": 3, "fail": 1 },
  "core":     { "status": "ok", "issues": 0 },
  "malware":  { "status": "ok", "findings": 0 },
  "baseline": { "status": "ok", "findings": 0 },
  "ioc":      { "status": "ok", "count": 1234 },
  "cloudflare": { "connected": true, "plan": "pro" },
  "events":   { "lockout": 2, "blocked_upload": 1 }  // high-signal counts SINCE the last successful report
}
```

## Command contract (Worker → plugin) — v1 remote actions

**Pull model** (chosen — it adds no inbound control surface to client sites).

1. The plugin polls `GET {endpoint}/v1/commands` hourly (opt-in), signed with
   the per-site token + HMAC (over an empty body) plus an `X-BLT-Nonce`. The
   Worker returns pending (or un-acked for 15 min) commands, signed, and marks
   them `delivered`:
   ```json
   { "commands": [ { "id": 12, "command": "scan_core", "params": {} } ] }
   ```
2. The plugin runs only whitelisted commands — `scan_core`, `scan_malware`,
   `scan_baseline`, `sync_ioc`, `health_scan`, `report` — by firing the local
   WP-Cron action each already owns. Unknown commands and any operator-supplied
   `params` are ignored, so the receiver can never run arbitrary code. Each
   executed command is recorded to the local event log (`fleet_command`).
3. The plugin acknowledges with `POST {endpoint}/v1/commands/ack`
   (`{ "ids": [12] }`, same signing); the Worker moves those rows to `done`,
   scoped to the acknowledging site.

Operators queue work with `POST /admin/commands` (`{ site_id, command }`),
behind Cloudflare Access (JWT verified).
