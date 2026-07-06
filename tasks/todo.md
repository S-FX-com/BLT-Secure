# BLT Secure — Task Board

## Phase 1 — Hardening Baseline

### Local hardening

- [ ] **Login slug rename** — `wp-login.php` hidden behind a custom slug.
  - AC: `GET /{slug}` serves the login form; `GET /wp-login.php` and unauthenticated `/wp-admin/*` return 404 (except `admin-ajax.php` / `admin-post.php`); password-reset email links use the new slug; `postpass`, `logout`, `rp`, `confirm_action`, interim-login flows all work; `BLT_SECURE_DISABLE_SLUG` constant restores default; feature disabled on multisite; off by default.
- [ ] **Login lockout** — N failed attempts → temporary block.
  - AC: 5 failures (default) from one IP or against one username → generic error, no timing/count leak; success clears counters; thresholds/window configurable; alert event fired on lockout; IP resolved via CF-aware resolver.
- [ ] **TOTP 2FA** — optional per-user, policy-enforceable.
  - AC: enrollment via QR (client-side render) + manual code; completes only after a valid code; codes verify at ±1 window with replay guard; 8 single-use recovery codes shown once, stored hashed; interstitial rate-limited; policies optional / required for admins / required for all; un-enrolled users under a "required" policy are nagged, not locked out.
- [ ] **File editing disabled** — `file_mod_allowed` filter when `DISALLOW_FILE_EDIT` not already set. AC: theme/plugin editors gone from wp-admin; constant state shown read-only in UI.
- [ ] **File-manager plugin blocker** — filterable slug list.
  - AC: install blocked at `upgrader_pre_install`; activation links stripped; already-active blocked plugin is auto-deactivated with an admin notice; every block fires an alert event.
- [ ] **Security headers** — HSTS, X-Frame-Options, nosniff, Referrer-Policy, starter CSP.
  - AC: headers on front-end + login, never CSP on wp-admin; HSTS only over SSL, `includeSubDomains`/`preload` behind separate checkboxes; pre-existing same-name headers are not duplicated; CSP defaults to Report-Only.
- [ ] **Hide WP version + block user enumeration.**
  - AC: no generator tag; `?ver={core}` stripped from enqueues only when equal to core version; `?author=N` → 404 for visitors incl. the canonical-redirect leak; REST `/wp/v2/users*` → 401 for logged-out.
- [ ] **XML-RPC kill switch** — default off.
  - AC: when off, `xmlrpc.php` answers with a fault before parsing; pingback methods and `X-Pingback` header gone; toggle re-enables cleanly; UI warns about Jetpack/mobile apps.

### Cloudflare edge (token-gated)

- [ ] **Token setup** — verify, zone discovery, encrypted storage.
  - AC: token verified via `/user/tokens/verify`; zone auto-discovered from `home_url`; account_id read from zone object; token stored encrypted (autoload=no); salt rotation detected → re-prompt notice, no silent failures.
- [ ] **Managed WAF deploy** — CF Managed Ruleset (wordpress emphasis) + OWASP.
  - AC: idempotent (ref-reconciled); paranoia + sensitivity controls redeploy via PATCH; free-plan zones get the Free Managed Ruleset with honest card copy.
- [ ] **Custom rules pack** — ASN challenge, TOR challenge, sensitive-path block.
  - AC: three rules with `blt-secure-*` refs; removable individually as a pack; other tenants' rules untouched.
- [ ] **Rate limiting** — login + xmlrpc + custom slug, 5/60s → 600s block.
  - AC: single rule (free-plan budget); local slug change marks deployment stale in UI.
- [ ] **Leaked credentials** — detection on `log`/`pwd` fields + challenge rule.
  - AC: zone check enabled + custom detection + companion rule; degraded gracefully by plan.
- [ ] **Cloudflare Access app** — wp-admin + login slug, admin-email allow policy, admin-ajax bypass.
  - AC: 403 scope probe renders card disabled with exact token-fix instructions; app + policies removable.

### Manual smoke checklist (run on wp-env or a staging site before tagging a release)

- [ ] Activate plugin: no notices/fatals with WP_DEBUG on.
- [ ] Rename login slug → old URL 404s, new URL logs in, reset-password email link works.
- [ ] 5 bad passwords → locked out; correct password after window works.
- [ ] Enroll 2FA with a real authenticator app; log in with code; burn a recovery code.
- [ ] `curl -sI` front page and login: expected headers present, none duplicated.
- [ ] `curl -s -X POST /xmlrpc.php` → fault response.
- [ ] Try installing wp-file-manager → blocked with notice.
- [ ] Configure a real free-plan CF zone token → verify, deploy all five cards, confirm rules in CF dash, remove all five, confirm gone.
- [ ] Deactivate → CF rules untouched, notice shown. Uninstall with cleanup opted in → options/meta gone.

## Phase 2 — Detection & Monitoring (not started)

- [ ] File integrity monitor (baseline hash core/theme/plugin, scheduled diff, alert on change)
- [ ] YARA-based scanner via Pressidium ruleset + signature-base (pure-PHP subset fallback for shared hosting)
- [ ] IOC blocklist sync (ThreatFox, Spamhaus DROP) → push to CF IP List / custom rule
- [ ] CF firewall event ingestion → unified timeline
- [ ] Suspicious wp-admin activity log (new admins, plugin installs, cron changes)
- [ ] Malicious upload detection (CF signal + local pass on /uploads)
- [ ] Wire feeds/feeds.json loader (pluggable feed sources)

## Phase 3 — Fleet Management (not started)

- [ ] Central dashboard (CF Workers + D1)
- [ ] Worker/KV credential store backend (swap for Blt_Secure_Encrypted_Option_Store)
- [ ] Slack/email alerting channels behind Blt_Secure_Alerting
- [ ] Scheduled feed updates w/ changelog
- [ ] Client-facing status page / trust badge
