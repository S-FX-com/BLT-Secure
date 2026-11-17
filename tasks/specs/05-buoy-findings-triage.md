# 05 — Buoy findings triage (route + dashboard)   ✅ APPROVED 2026-11-16 — items 1–4 BUILT

## Status
**Approved by Shane on 2026-11-16 and built** in Buoy (items 1–4): `GET /api/admin/findings`,
`POST /api/admin/findings/:id/triage`, the Findings dashboard view and the site-row badge. Recorded as
Buoy `DECISIONS.md` D-2026-11-16-02; runbook RB-9; threat-model section updated. Delivered in Buoy PR #9
(same branch as the auto-resolve change).
**Item 5 (auto-resolving critical findings) was NOT approved and is NOT built** — the recommendation stays "no".
**Still your decision:** whether BLT Secure should now *send* `critical` (`blt_secure_buoy_allow_critical`,
default off). Triage exists, but a regex heuristic being able to hold a client's updates is a separate risk call.
One addition beyond the original text: ingest no longer re-opens a finding a person marked `triaged` or
`false_positive`, otherwise a false-positive on a finding the site keeps reporting came straight back as open.

## Why
In Buoy nothing can move a `malware_findings` row out of `open` except the new auto-resolve for
non-critical rows. There is no list route, no triage route and no dashboard view. A `critical`
row blocks that site's automated updates (§11.4 `[HARD]`) until someone edits D1 by hand.
Until this exists BLT Secure caps severity at `high` (spec 02). This spec is the prerequisite for
ever passing `critical` through.

## Build (Buoy)
1. `GET /api/admin/findings?site_id=&status=&severity=` — scoped by the staff member's client
   assignments (default-deny, like every list route).
2. `POST /api/admin/findings/:id/triage` `{ status: "triaged"|"resolved"|"false_positive", note }`.
   Roles owner/operator. Clearing a **critical** finding requires step-up (§6.3, fresh auth ≤300 s)
   and writes a critical audit event `malware.triaged` with actor and note. Never auto-lift.
3. Dashboard "Findings" view + a badge on the site row; text-only rendering.
4. After triage of the last open critical: nothing else to do — `updatesBlocked()` already reads
   `status='open'`.
5. Optional, **needs explicit approval**: let a critical auto-resolve after N consecutive complete
   clean inventories *and* a human acknowledgement. Recommended answer: no.

## Done when
A staff member can list and triage findings for their clients only; clearing a critical one needs a
fresh sign-in and lands in the audit chain; tests cover scoping, step-up and audit.
