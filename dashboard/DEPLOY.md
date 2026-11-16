# Fleet Dashboard — deploy runbook

> **Legacy — superseded by Buoy / BLT Connect.** Frozen: defect fixes only.

Cloudflare Worker + D1. No build step (plain ESM JS). Runtime dependencies:
none. Dev dependency: `wrangler`.

> This session builds the code only. The steps below are for an operator to
> run against the S-FX.com Cloudflare account.

## 0. Prerequisites
```bash
cd dashboard
npm install          # installs wrangler (dev dependency)
npx wrangler login   # authenticate to the S-FX.com account
```

## 1. Create the D1 database
```bash
npx wrangler d1 create blt-secure-fleet
```
Copy the printed `database_id` into `wrangler.toml` (`[[d1_databases]] database_id`).

## 2. Apply the schema
```bash
npx wrangler d1 execute blt-secure-fleet --file=schema.sql          # local
npx wrangler d1 execute blt-secure-fleet --remote --file=schema.sql # production
```

## 3. Test + deploy
```bash
npm test             # runs the auth + snapshot unit tests (node --test)
npx wrangler deploy
```

## 4. Put the operator routes behind Cloudflare Access
`/` and `/admin/*` expose fleet data and site enrollment — gate them:

1. Serve the Worker from a **custom domain / route** (`workers_dev = false` in
   `wrangler.toml` turns the public `*.workers.dev` hostname off — leave it off).
2. Zero Trust → Access → Applications → **Add self-hosted app** for the
   Worker's hostname, paths `/` and `/admin/*`. Policy: **Allow** your admin
   email(s).
3. Copy the app's **Application Audience (AUD) tag** and your team domain
   (`<team>.cloudflareaccess.com`) into `wrangler.toml`:
   `ACCESS_AUD` and `ACCESS_TEAM_DOMAIN`, then `npx wrangler deploy`.

The Worker verifies the signed `Cf-Access-Jwt-Assertion` header (RS256 against
the team JWKS, with `aud`, `iss` and `exp` checked) on every operator request.
A bare `Cf-Access-Authenticated-User-Email` header is **not** trusted — a client
can send it to any hostname that reaches the Worker without Access. If either
variable is empty the operator routes **refuse every request** (fail closed).

The `/v1/*` ingest routes are authenticated by the per-site token + HMAC and
must **not** be behind Access (client sites call them machine-to-machine).

## 5. Enroll a site
```bash
# Through Access, use a service token (or a browser session): the request needs
# a valid Access JWT. Cross-site browser requests are refused (Origin check).
curl -X POST https://<worker-host>/admin/sites \
  -H "CF-Access-Client-Id: <id>" -H "CF-Access-Client-Secret: <secret>"
# returns { id, token }
```
The `token` is shown once. Paste it into the site's BLT Secure → Advanced →
Fleet enrollment field, set the endpoint to `https://<worker-host>`, enable
fleet reporting, save, then "Send report now".

## Endpoints
| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/v1/snapshot` | site token + HMAC | ingest a posture snapshot |
| GET | `/v1/commands` | site token + HMAC | pull queued remote commands |
| POST | `/v1/commands/ack` | site token + HMAC | acknowledge executed commands (→ `done`) |
| GET | `/` | Cloudflare Access (JWT verified) | operator dashboard |
| POST | `/admin/sites` | Cloudflare Access (JWT verified) | enroll a site (one-time token) |
| POST | `/admin/commands` | Cloudflare Access | queue a command for a site (`application/json`, known command, existing `site_id`) |
| POST | `/admin/sites/revoke` | Cloudflare Access | delete a site and its token (`{ "site_id": n }`) |

## Notes / next steps
- Only `sha256(token)` is stored; the raw token lives only on the client site.
- The plugin's remote-command **receiver** pulls `/v1/commands` hourly (opt-in
  via Advanced → "Accept remote commands"), executes only a fixed whitelist of
  scan/sync actions, then POSTs `/v1/commands/ack` to close them. Queue work
  with `POST /admin/commands` (`{ site_id, command }`) where `command` is one
  of `scan_core`, `scan_malware`, `scan_baseline`, `sync_ioc`, `health_scan`,
  `report`.
- Snapshots are validated + field-whitelisted (`src/snapshot.js`) before they
  touch D1.
