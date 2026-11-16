# 06 — Retire the legacy fleet reporter and `dashboard/`

`Blt_Secure_Fleet` (bearer token + HMAC keyed with the same token, unauthenticated commands
response, inline network I/O) and the `dashboard/` Worker are superseded by Buoy/BLT Connect.
They were fixed for the worst defects in the review pass but remain a second, weaker channel.

## Preconditions (do not start before)
- Spec 03 is live: posture reaches Buoy through the agent.
- Any site still enrolled in the legacy dashboard has been migrated. Check the Worker's D1
  `sites` table for recent `last_seen_at`.
- Shane confirms the legacy Worker and D1 can be deleted.

## Steps
1. Release N: mark Fleet deprecated in the UI ("Replaced by Buoy"), keep it working.
2. Release N+1: remove the module, `dashboard/`, the Advanced-tab section, `blt_secure_fleet_*`
   options/cron/transients (add them to `uninstall.php` cleanup in N so they are purged), the
   `.distignore` entry and the dashboard job in CI.
3. Update `tasks/todo.md` Phase 3 items to "superseded".

## Done when
No code path in the plugin POSTs to a dashboard endpoint; uninstall leaves no `blt_secure_fleet*` rows.
