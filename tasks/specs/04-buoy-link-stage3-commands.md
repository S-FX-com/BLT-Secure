# 04 — Buoy link, stage 3: `secure.*` commands   ⛔ NEEDS SHANE'S WRITTEN APPROVAL

Buoy's command vocabulary is `[HARD]` (spec §6.2): `commands.ts`, the literal `match` in
`Dispatch.php`, the shared protocol vectors and both test suites. Adding a command needs
Shane's written approval and a dated `DECISIONS.md` entry. **Do not start this spec until that
is on file.** The proposal below is what to ask for — exact names and tiers.

## Proposed commands
| Command | Tier | Approval | Writes | Params | Behaviour |
|---|---|---|---|---|---|
| `secure.scan` | 1 | actor | yes | `{ scan: "core"\|"malware"\|"baseline"\|"ioc"\|"health" }` | Literal enum → literal WP-Cron hook (`blt_secure_core_scan` …). Schedules **one** single event (de-duplicated) and returns `{queued:true}`; never runs the scan inside the 60 s command window. |
| `secure.configure` | 3 | actor + step-up | yes | `{ changes: { "<section>.<key>": bool\|int\|enum } }` | Validated against a literal allowlist schema inside BLT Secure and applied through `Blt_Secure_Options` + each module's own sanitizer. Returns `{written[], rejected[]}`. |

Optional `secure.read` (tier 0) only if posture riding the inventory proves insufficient.

## Allowlist for `secure.configure` (literal, in BLT Secure — not in the agent)
Booleans/enums only: `login.lockout_enabled`, `login.max_attempts` (1–20), `privacy.block_enumeration`,
`xmlrpc.disabled`, `headers.hsts|xfo|nosniff|referrer`, `file_guard.block_file_managers`,
`file_guard.disable_file_edit`, `two_factor.policy`.
**Never**: any credential or token, `login.slug` (lock-out generator), Cloudflare deploy actions,
anything that takes free text or a URL.

## Hard constraints (from the Buoy doctrine and our own lessons)
- Scan trigger = literal `match` to literal hook names. **Do not port `Blt_Secure_Fleet::execute()`'s
  `do_action($hook)`** — the forbidden-construct gate (`scripts/forbidden-check.php`) exists to refuse that shape.
- Do **not** widen `settings.write` to `blt_secure_settings` (scalar-only rule). And remember
  `tasks/lessons.md`: programmatic writes to `blt_secure_settings` go through the Settings API
  sanitizer; unknown sections are silently dropped — go through `Blt_Secure_Options::update_section()`.
- Not granted by default at enrollment (`DEFAULT_GRANTS`): grant per site explicitly.

## Touch list
Buoy: `packages/protocol/src/commands.ts`, `agent/blt-connect/src/Commands/Dispatch.php` (+ new
`Secure.php`), `packages/protocol/vectors/*` (`npm run vectors`), `agent/tests/run-tests.php`,
`apps/control-plane/test/signing.spec.ts`, THREATMODEL command table, DECISIONS entry, agent version
bump. BLT Secure: `Blt_Secure_Buoy_Bridge::queue_scan()` / `apply_configuration()` behind two
local filters the agent calls.

## Done when
Every `[HARD]` gate is green on both sides, the forbidden-check passes, a negative test proves an
unknown scan name / non-allowlisted key is refused, and a scan queued from Buoy runs on the next
WP-Cron tick.
