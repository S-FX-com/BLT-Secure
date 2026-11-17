# 02 — Buoy link, stage 1: findings (code is written; wire it up and verify)

## Architecture (decided — do not relitigate)
**BLT Connect (Buoy's WordPress agent) is the ONLY transport between a site and Buoy.** It speaks
Ed25519-signed envelopes with a fixed command vocabulary and no code-execution path. BLT Secure
adds **no network code, no credentials and no inbound route** for Buoy: it answers local PHP
filters that the agent applies while serving an already-authenticated `inventory.read`.
"Connected" means the site is enrolled in Buoy through BLT Connect; until then nothing calls BLT
Secure's filters.

Rejected: pointing `Blt_Secure_Fleet`'s bearer-token/HMAC channel at Buoy. It would add a second,
weaker auth scheme to a control plane designed around one strong one.

## What exists
- BLT Secure: `includes/class-buoy-bridge.php` (`Blt_Secure_Buoy_Bridge`), `tests/test-buoy-bridge.php`.
  Provides the `blt_secure_findings` filter: `{severity, signature, path}` only, ≤199 findings most
  severe first, `blt_secure:truncated` sentinel when more existed or any scanner's result is
  missing/partial, whitelisted findings excluded, `critical` capped to `high` unless
  `blt_secure_buoy_allow_critical` is true.
- Buoy: `ingestMalwareFindings(..., {authoritative:true})` from `inventory.read` resolves open
  **non-critical** `blt_secure` findings missing from a **complete** list. Critical is never
  auto-resolved (DECISIONS D-2026-11-16-01). Tests in `apps/control-plane/test/findings.spec.ts`.
- The agent already calls `apply_filters( 'blt_secure_findings', null )` in `Inventory::read`
  and slices to 200. **No agent change, no protocol change, no migration.**

## Left to do
1. Register the bridge from the core singleton, not from a module that may be disabled:
   `require_once includes/class-buoy-bridge.php` in `blt-secure.php`; in `Blt_Secure::init()`,
   `( new Blt_Secure_Buoy_Bridge( $this->whitelist ) )->boot();`. Boot is one `add_filter`.
2. Smoke on a staging site running both plugins, in **both** poll and push transport: create a
   test file with `eval(base64_decode($_POST['x']));` in `wp-content/uploads/`, scan, wait for
   `inventory.read` (or trigger it from Buoy), confirm the finding appears in D1
   `malware_findings` with `source='blt_secure'`; ignore it in BLT Secure, wait for the next
   inventory, confirm it becomes `resolved`.
3. Confirm with BLT Secure deactivated that the key is simply absent (Buoy leaves open findings
   untouched — it cannot know).
4. Add a "Connected to Buoy" status row to the Advanced tab: detect `class_exists('\BLTConnect\Bootstrap')`
   and show "BLT Connect installed / not installed". Do **not** try to read enrollment state until
   the agent exposes a read-only status filter (propose `blt_connect_status` in a Buoy PR).

## Done when
A finding created on a site shows in Buoy within one inventory cycle; ignoring or fixing it
resolves it; a site with 400 low findings never hides one high finding; critical never blocks
updates because of a regex heuristic.
