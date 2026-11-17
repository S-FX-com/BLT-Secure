# Build specs — how to use these

Each file here is a self-contained brief for one feature: hand it to an agent (or pick it up
yourself) and it should be enough without this conversation. They follow `CLAUDE.md`: PHP 7.4+,
zero runtime Composer deps, shared-hosting safe, no heavy work on page load, every output
escaped, nonces + `manage_options` on every form/AJAX, Cloudflare optional.

**Order matters.** Specs 01 and 02 unblock everything else (CI would have caught several
of the bugs fixed in the review pass; the Buoy findings path is the foundation of the link).

| # | Spec | Repo | Needs your decision first? |
|---|---|---|---|
| 01 | CI, PHP 7.4 compatibility gate, signed releases | BLT-Secure | no |
| 02 | Buoy link, stage 1 — findings (DONE in code; wiring + verification left) | both | no |
| 03 | Buoy link, stage 2 — posture in inventory | both | no (no new commands) |
| 04 | Buoy link, stage 3 — `secure.*` commands | both | **YES — `[HARD]` command vocabulary** |
| 05 | Buoy findings triage (route + dashboard) | Buoy | **YES — touches §11.4 `[HARD]` surface** |
| 06 | Retire the legacy fleet reporter and `dashboard/` | BLT-Secure | yes (after 03) |
| 07 | Turnstile on login / register / lost-password / comments | BLT-Secure | no |
| 08 | Cloudflare: consolidated WordPress-attack rule, Bot Fight Mode, notifications | BLT-Secure | no |
| 09 | Cloudflare: zone audit (SSL/TLS, DNS, DNSSEC, email auth, cache, origin lock) + two-token split | BLT-Secure | token model |
| 10 | Vulnerability intelligence (installed versions vs a feed) | BLT-Secure (+Buoy roll-up) | feed licence |
| 11 | wp.org checksum verification + stat-only file-change monitor | BLT-Secure | no |
| 12 | Resumable chunked scanning + quarantine instead of delete | BLT-Secure | no |
| 13 | Enforced 2FA with grace period, admin reset, trusted device, passkeys | BLT-Secure | no |
| 14 | Persistent tamper-evident audit log | BLT-Secure | no |
| 15 | Sessions: list/destroy, idle limit, re-auth for sensitive actions; credential hygiene | BLT-Secure | no |
| 16 | Database injection scanner | BLT-Secure | no |

Every spec ends with **Done when** (acceptance criteria) and **Tests**. When a spec is
finished, move its checklist into `tasks/todo.md` as a completed phase and append any gotcha
to `tasks/lessons.md`.

**Agent guardrails that apply to every spec**
- `includes/blt-family/` and `includes/lib/` are vendored — never edit them here.
- Run `vendor/bin/phpunit`, `vendor/bin/phpcs`, `php -l` on every changed file before committing.
  The dev box may run PHP 8.x: until spec 01 lands, re-read your diff for 8.0+ syntax
  (`match`, `str_contains`, `readonly`, nullsafe `?->`, union types, named arguments).
- Cloudflare work: never call a live account while developing; verify plan gating and token
  scopes against current developers.cloudflare.com docs and cite the URL in the PR.
- Buoy: a merge to `main` **deploys production and applies D1 migrations**; a version bump under
  `agent/` cuts a signed release. Keep migrations additive and say so in the PR.
