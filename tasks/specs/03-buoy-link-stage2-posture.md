# 03 — Buoy link, stage 2: security posture in the inventory (no new commands)

## Goal
Buoy shows, per connected site, the same posture a site owner sees in BLT Secure: Health score,
scan statuses, 2FA coverage, Cloudflare connection/plan, recent high-signal event counts — and
alerts when it degrades. Delivered through the existing `inventory.read`, so **no change to the
`[HARD]` command vocabulary**.

## Contract
New local filter `blt_secure_posture` (null in → array out), applied by the agent beside
`blt_secure_findings`. Payload (all values bounded and typed; no secrets, paths or file contents):
```jsonc
{ "schema": 1,
  "plugin_version": "1.2.0",
  "health":   { "score": 92, "pass": 40, "warn": 3, "fail": 1, "scanned_at": 1700000000 },
  "scans":    { "core":    {"status":"ok|issues|error|none","count":0,"at":1700000000},
                "malware": {"status":"…","count":0,"at":…,"partial":false},
                "baseline":{"status":"…","count":0,"at":…} },
  "two_factor": { "policy":"optional|required_admins|required_all", "admins":4, "admins_enrolled":3 },
  "login":    { "slug_hidden":true, "lockout":true, "xmlrpc_disabled":true },
  "cloudflare": { "connected":true, "plan":"pro", "cards_deployed":["waf_managed","rate_limit"], "stale":false },
  "events_24h": { "lockout":2, "blocked_upload":1 },
  "failing_checks": ["php_supported","no_installer_files"]   // ≤20 check ids, ids only
}
```
Reuse the pure assembly already in `Blt_Secure_Fleet::assemble_snapshot()` — move it into
`Blt_Secure_Buoy_Bridge::posture()` (keep the Fleet method delegating until spec 06 deletes it).

## BLT Secure steps
1. `Blt_Secure_Buoy_Bridge::posture()` pure builder + `provide_posture()` filter callback;
   golden-JSON test; a test that no value exceeds its bound and no key outside the schema appears.
2. Count 2FA coverage with one bounded `WP_User_Query` (`role__in` admin roles, `count_total`,
   `fields` = ID, meta check) — cron/REST only, never page load.

## Buoy steps (separate PR in /Buoy)
1. `agent/blt-connect/src/Commands/Inventory.php`: `$posture = apply_filters('blt_secure_posture', null);
   if (is_array($posture)) { $out['blt_secure_posture'] = $posture; }` — same pattern as findings.
   Bump the plugin version → a signed release is cut on merge; say so in the PR.
2. Migration `0003_site_security_posture.sql` (**additive only**): `site_security_posture(site_id PK,
   received_at, plugin_version, health_score, health_fail, scans_json, two_factor_json, cloudflare_json,
   events_json, failing_checks_json)`.
3. `services/inventory.ts`: strict validation/clamping (hostile input, §2 D-7), upsert; notify Teams
   when health score drops ≥15 points or a scan goes `none→issues`; never alert twice for one state.
4. `routes/admin.ts` + dashboard: a Security column in the site list and a posture card on the site
   page (text-only rendering; the dashboard CSP stays).
5. THREATMODEL row: posture is site-reported and advisory; it never gates a command.

## Done when
A connected site's posture appears in Buoy within one inventory cycle; a malicious payload with
oversized/mistyped fields is clamped or dropped; sites without BLT Secure are unaffected.
