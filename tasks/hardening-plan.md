# BLT Secure — hardening plan and Buoy link (2026-11-16)

Companion to `tasks/todo.md` (checklists), `tasks/lessons.md` (gotchas) and `tasks/specs/` (build briefs).
Branch `sfx/intelligent-lovelace-tt5eki` in both repos; one PR each.

## 1. What was done

A line-by-line review of the whole plugin (four code slices + a Cloudflare-capabilities study) found **real
defects, several serious**. Each high-severity finding was confirmed against WordPress core source, current
Cloudflare docs, or a reproduction before it was fixed. Tests went from **247 to 585**; `phpcs` is clean; the
legacy Worker went from 16 to 40 tests; Buoy is green (108 TS tests, 83 agent tests, forbidden-construct gate).

Most important findings, in plain language:

| # | Finding | Impact |
|---|---|---|
| 1 | **The login lockout never blocked anything.** A `WP_Error` at `authenticate` priority 1 is discarded by core once credentials are non-empty. | Brute-force protection was cosmetic; alerts fired while a correct guess still logged in. |
| 2 | Hidden login URL still reachable via `?action=POSTPASS`, `//wp-login.php`, `/wp-login.php/x`. | The headline "hide wp-login" feature was bypassable with one character. |
| 3 | 2FA had no per-user throttle; recovery codes were never shown; a `system.multicall` skipped 2FA. | Brute-forceable second factor; lost phone = locked-out account. |
| 4 | Upload guard rejected ~half of random 2 MB files (zips, photos). | Randomly broke legitimate uploads. |
| 5 | Baseline monitor silently re-baselined an infected plugin if the attacker also bumped `Version:`. | Tamper detection could be defeated by editing one header. |
| 6 | A 2.2 MB padded webshell, a few hundred SVGs in uploads, or a symlinked directory hid malware from the scanner; signatures were trivially evadable. | False sense of "clean". |
| 7 | Cloudflare cards that **cannot succeed on the Free plan** (rate limit period, leaked credentials), partial deploys that left untracked live rules, Access apps/lists shared by name across sites (one site's Remove deleted another's), an Access app that could deny everyone with no way out. | Broken or dangerous edge deployments. |
| 8 | The fleet reporter's HMAC was keyed with the bearer token it travels with; saving the Advanced tab silently disabled the daily report; alert delivery blocked the failing request. | Weak channel, dead scheduling, slow logins. |
| 9 | **The Buoy link was dead.** Buoy's agent asks BLT Secure for `blt_secure_findings`; BLT Secure never answered. | Nothing flowed to Buoy. |

All fixed except the items in §3. Commits on the branch: login/2FA (`61c54d0`), Cloudflare (`9e0d09f`),
scanners (`06104b4`), bridge + specs (`8cc0e4c`), fleet/credentials/updater (`ed4a91a`), bridge wiring (`1b05057`),
CI + 7.4 gate (`38f0a9f`), whitelist hardening (`dca06db`).

## 2. Decisions that need you

1. **Buoy `[HARD]` §6.2 — new commands** (`secure.scan` tier 1, `secure.configure` tier 3 + step-up). Spec 04. Needs
   your written approval and a DECISIONS entry. Everything else in the link works without it.
2. **Buoy findings triage** (spec 05). Nothing in Buoy can clear an open `critical` finding except hand-edited SQL.
   Until triage exists, BLT Secure sends `high` at most. Approve building the triage route + dashboard view?
3. **TOR folded into the ASN challenge rule** (2 custom rules instead of 3) so the whole plugin fits the Free plan's
   5 rules. The cost: ASN and TOR can no longer be toggled separately. Alternative: keep 3 rules and accept that a
   Free zone cannot hold every card.
4. **Host-scoped IP-list names** stop sites in one account overwriting each other's list, but Free allows **one**
   custom list per account — a second site on a Free account cannot create its own. Agencies are normally paid.
5. **Retire the legacy fleet reporter and `dashboard/`** (spec 06) once Stage 2 lands?
6. **Cloudflare token model** (spec 09): split into an *enforce* token and a read-only *audit* token? And may Buoy
   hold any Cloudflare token? (`DECISIONS D-2026-08-27-03` says no, on purpose.)
7. Small policy calls: make core's "username not registered" login error generic? Require `list_users` for
   `/wp/v2/users` for logged-in subscribers (could break the editor's author picker)? Should `fleet_command` leave the
   shared event buffer?
8. **Release key.** Buoy's README says the agent's release public key is still a placeholder that fails closed
   (no self-update) until the key ceremony is run — worth doing before signed BLT Secure releases (spec 01) reuse it.

## 3. Deliberately not fixed (and why)

- Grace-period enforcement of "required 2FA", passkeys, trusted device → spec 13 (feature).
- Resumable cron-chunked scanning and quarantine → spec 12 (features; the time budget, lock and `partial` flag shipped).
- Cron-chunked baseline for >20,000-file trees → surfaced as an "unmonitored" finding instead.
- Rate limiting on the legacy Worker's `/v1/*`; `fleet_command` still shares the 200-event buffer (race remains) → spec 14.
- Cloudflare list/detection pagination (no documented pagination), double-slash paths in edge expressions,
  `verify_token` behaviour for account-owned tokens (a fallback covers it).
- **Vendored `includes/blt-family/` findings — port to the other BLT repos** (this repo must not diverge):
  F1 (medium) `class-blt-family-crypto.php` falls back to `b64:` base64 "obfuscation" when no AEAD backend exists and
  `decrypt()` returns any unrecognised value as plaintext — violates "never store a secret in plaintext"; refuse to
  store and drop the passthrough. F2 `class-blt-family-admin.php` runs `sanitize_text_field` on secrets (strips
  `<…>`/`%xx`, corrupts valid values) — use `trim( wp_unslash() )` + a format check. F3 no salt-rotation canary (card
  says "Configured" while every field is "Not set"), envelopes carry no per-field AAD. F4 `?force-check` is honoured
  on unauthenticated requests (bypasses the 24 h floor).
- **Never exercised on a real site/zone:** the Free-zone smoke test was always unchecked in `todo.md` and still is;
  the Access `PUT`-with-inline-policies call is untested against real Cloudflare; the PHP 7.4 and 8.4 CI legs have
  not run yet. See the manual smoke list in `todo.md` Phase 6.

## 4. Cloudflare plan

Study results are folded into the specs; the headline facts (all with doc URLs in the specs and lessons):

- **Free-plan budget is the design constraint**: 5 custom rules, 1 rate-limit rule (10 s / 10 s), 1 custom list /
  10,000 items account-wide, no custom leaked-credential detection. After this pass the whole plugin is exactly 5
  rules; new coverage must **consolidate** (spec 08a), not add.
- Ranked by value per effort: (1) plan-aware degradation — **done**; (2) one consolidated WordPress-attack rule
  (spec 08a); (3) Turnstile (spec 07); (4) zone SSL/TLS audit (spec 09); (5) origin lock via secret header
  (spec 09); (6) opt-in Bot Fight Mode — never in "Deploy all" (spec 08b); (7) notifications (runbook);
  (8) cache-bypass audit; (9) DNS/DNSSEC/email-auth audit; (10) Page Shield inventory.
- Skip: API Shield (docs contradict each other; WordPress publishes no OpenAPI schema), Zero Trust beyond the Access
  app already deployed, Workers VPC/Browser Rendering, Email Routing.
- Token model: split enforce vs audit (spec 09). *Zone WAF Edit* is coarse; never put Turnstile-write,
  Notifications-write, DNS-write or Registrar permissions in a per-site token.
- Open doc conflicts to confirm on a throwaway zone: `firewallEventsAdaptive` availability on Free, Edit-vs-Write
  permission names in the token UI, Access free-seat limit, which `ssl` modes each plan offers.

## 5. The Buoy link — design and status

**BLT Connect (Buoy's agent) is the only transport.** BLT Secure exposes local read-only filters; the agent applies
them while serving an already-authenticated `inventory.read`. BLT Secure adds no network code, credentials or inbound
route for Buoy, and "connected" simply means the site is enrolled in Buoy. The legacy bearer/HMAC fleet channel is
**not** repointed at Buoy: it would add a weaker auth scheme to a control plane built around Ed25519.

```
 BLT Secure scanners ──► Blt_Secure_Buoy_Bridge ──filter──► BLT Connect (inventory.read) ──signed──► Buoy
   (local options)        blt_secure_findings                (agent, fixed dispatch)                  ingestMalwareFindings
```

| Stage | What | Needs approval? | Status |
|---|---|---|---|
| 1 | Findings: `{severity,signature,path}`, ≤199 + truncation sentinel, whitelist-aware, `critical`→`high`; Buoy auto-resolves non-critical findings missing from a **complete** list | no | **Done**, verified end to end; staging smoke left (spec 02) |
| 2 | Posture (health score, scan states, 2FA coverage, CF connection, event counts) via a second filter on the same `inventory.read`; additive migration; dashboard card | no (no new commands) | Spec 03 |
| 3 | `secure.scan`, `secure.configure` commands | **yes — `[HARD]`** | Spec 04 |
| — | Findings triage route + view in Buoy | yes (touches §11.4 surface) | Spec 05 |
| — | Retire legacy fleet/`dashboard/` | yes | Spec 06 |

Safeguards baked in: critical is never auto-resolved and never sent by default; a truncated or incomplete scan list
resolves nothing; no snippets, descriptions or secrets leave the site; the bridge is one `add_filter`, registered in
the core singleton so a disabled module cannot remove it. Buoy side: no protocol, vocabulary or migration change.
A merge to Buoy `main` deploys production — the PR says so.

## 6. Order of work

1. Merge the two PRs after the manual smoke list passes; run the Free-zone and Buoy staging smokes.
2. Spec 01 (release integrity) — it protects every later release.
3. Decide §2.1/§2.2, then specs 03 → 05 → 04 → 06.
4. Specs 07–09 (Turnstile, Cloudflare), then 10–11 (vulnerability intelligence, wp.org checksums), then 12–16.
