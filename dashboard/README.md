# BLT Secure — Fleet Dashboard

The hosted, multi-site console for BLT Secure (Phase 3). Runs on Cloudflare
Workers + D1; each client site running the plugin pushes a compact posture
snapshot here, and (v1) can be sent remote commands back.

This directory is **excluded from the plugin distribution** (`.distignore`
`/dashboard`) — it is operator infrastructure, not shipped to client sites.
The plugin's "zero runtime Composer dependency" rule applies only to the PHP
plugin; the Worker is a normal TS/Wrangler project.

Status: **plugin-side reporter first.** The Worker + D1 implementation lands
in a later step; this document is the contract the plugin
(`Blt_Secure_Fleet`) reports against so the two sides can be built
independently.

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
  "schema": 1,
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
  "events":   { "lockout": 2, "blocked_upload": 1 }  // recent high-signal type counts
}
```

## Command contract (Worker → plugin) — v1 remote actions

Deferred to the remote-actions step. Decision still open: **pull** (plugin
polls `GET {endpoint}/v1/commands` on cron and executes queued commands) vs
**push** (Worker calls an authenticated WP REST route on the site). Pull is
favored — it adds no inbound control surface to client sites — but the
choice is confirmed when that piece is built. Whichever is chosen, commands
are signed the same way and every executed command is recorded to the local
event log.
