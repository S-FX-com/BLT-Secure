# 14 — Persistent, tamper-evident audit log

Today's event log is a 100-entry option ring buffer with a read-modify-write race: a lockout flood evicts the
forensic events that matter. 

## Build
- Table `{prefix}blt_secure_audit` (`dbDelta`): `id`, `ts`, `type`, `severity`, `actor_id`, `actor_login`, `ip`
  (as resolved by the resolver), `ua_hash`, `context` (JSON, ≤2 KB), `prev_hash`, `hash`. Hash-chain
  `hash = sha256(prev_hash || canonical row)` so deletion or edit is detectable; a Health check verifies the chain
  (bounded, from the last verified id).
- Writes go through one `Blt_Secure_Audit::record()`; `Blt_Secure_Alerting` calls it for every event **before**
  `do_action( 'blt_secure_alert' )`. Insert with `$wpdb->insert`; if the table is missing, create it lazily in cron
  /admin only — never on a front-end request.
- Retention (default 90 days, configurable) pruned by a daily cron in batches; a row-count cap as a backstop.
- Viewer: the Timeline tab merges audit rows with Cloudflare edge events (existing merge helper), paginated.
- Export: a signed JSON download (nonce + `manage_options`); optional webhook forwarding (reuse the alert-channel
  dispatcher, deferred via cron, never inline).
- **Buoy link**: expose `blt_secure_audit_summary` (counts by type, last chain-verify result) for the posture
  payload (spec 03). Buoy never receives raw rows.
- Uninstall: drop the table only when "delete data on uninstall" is on.

## Done when
10,000 lockout events do not evict a prior `activity_admin_granted`; editing a row breaks the chain check; no
request on the front end creates or writes to the table except the login-failure path (one indexed insert).
