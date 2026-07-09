# BLT Secure — Task Board

## Phase 1 — Hardening Baseline

### Local hardening

- [x] **Login slug rename** — `wp-login.php` hidden behind a custom slug.
  - AC: `GET /{slug}` serves the login form; `GET /wp-login.php` and unauthenticated `/wp-admin/*` return 404 (except `admin-ajax.php` / `admin-post.php`); password-reset email links use the new slug; `postpass`, `logout`, `rp`, `confirm_action`, interim-login flows all work; `BLT_SECURE_DISABLE_SLUG` constant restores default; feature disabled on multisite; off by default.
- [x] **Login lockout** — N failed attempts → temporary block.
  - AC: 5 failures (default) from one IP or against one username → generic error, no timing/count leak; success clears counters; thresholds/window configurable; alert event fired on lockout; IP resolved via CF-aware resolver.
- [x] **TOTP 2FA** — optional per-user, policy-enforceable.
  - AC: enrollment via QR (client-side render) + manual code; completes only after a valid code; codes verify at ±1 window with replay guard; 8 single-use recovery codes shown once, stored hashed; interstitial rate-limited; policies optional / required for admins / required for all; un-enrolled users under a "required" policy are nagged, not locked out.
- [x] **File editing disabled** — `file_mod_allowed` filter when `DISALLOW_FILE_EDIT` not already set. AC: theme/plugin editors gone from wp-admin; constant state shown read-only in UI.
- [x] **File-manager plugin blocker** — filterable slug list.
  - AC: install blocked at `upgrader_pre_install`; activation links stripped; already-active blocked plugin is auto-deactivated with an admin notice; every block fires an alert event.
- [x] **Security headers** — HSTS, X-Frame-Options, nosniff, Referrer-Policy, starter CSP.
  - AC: headers on front-end + login, never CSP on wp-admin; HSTS only over SSL, `includeSubDomains`/`preload` behind separate checkboxes; pre-existing same-name headers are not duplicated; CSP defaults to Report-Only.
- [x] **Hide WP version + block user enumeration.**
  - AC: no generator tag; `?ver={core}` stripped from enqueues only when equal to core version; `?author=N` → 404 for visitors incl. the canonical-redirect leak; REST `/wp/v2/users*` → 401 for logged-out.
- [x] **XML-RPC kill switch** — default off.
  - AC: when off, `xmlrpc.php` answers with a fault before parsing; pingback methods and `X-Pingback` header gone; toggle re-enables cleanly; UI warns about Jetpack/mobile apps.

### Cloudflare edge (token-gated)

- [x] **Token setup** — verify, zone discovery, encrypted storage.
  - AC: token verified via `/user/tokens/verify`; zone auto-discovered from `home_url`; account_id read from zone object; token stored encrypted (autoload=no); salt rotation detected → re-prompt notice, no silent failures.
- [x] **Managed WAF deploy** — CF Managed Ruleset (wordpress emphasis) + OWASP.
  - AC: idempotent (ref-reconciled); paranoia + sensitivity controls redeploy via PATCH; free-plan zones get the Free Managed Ruleset with honest card copy.
- [x] **Custom rules pack** — ASN challenge, TOR challenge, sensitive-path block.
  - AC: three rules with `blt-secure-*` refs; removable individually as a pack; other tenants' rules untouched.
- [x] **Rate limiting** — login + xmlrpc + custom slug, 5/60s → 600s block.
  - AC: single rule (free-plan budget); local slug change marks deployment stale in UI.
- [x] **Leaked credentials** — detection on `log`/`pwd` fields + challenge rule.
  - AC: zone check enabled + custom detection + companion rule; degraded gracefully by plan.
- [x] **Cloudflare Access app** — wp-admin + login slug, admin-email allow policy, admin-ajax bypass.
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
- [ ] Deactivate → CF rules untouched, notice shown. Uninstall with cleanup opted in → options/meta gone (including PUC's `external_updates-blt-secure` option and cron hook).
- [ ] **Updates end-to-end:** install a CI-built release zip on staging, add a GitHub token (Advanced tab), force a check (Dashboard → Updates → "Check again"), confirm the update row shows the newer version + changelog, run the update, confirm the plugin folder is still `blt-secure/` and the plugin stays active.
- [ ] Public-repo updates: with no token configured, no "updates cannot be checked" notice appears; a real newer release is still detected and installs. (No-token warning only returns if `blt_secure_updates_repo_public` is filtered to false.)
- [ ] Health Check: open the Health Check tab → "Run checks now" → score + grouped pass/warn/fail results render; confirm the daily `blt_secure_health_scan` cron event is scheduled; confirm a fresh page load with no scan does NOT make the self-HTTP request (results come from the stored option).
- [ ] Settings restyle: on Hardening/Login/Advanced, toggles flip and save correctly (each section saves without wiping another); the read-only `DISALLOW_FILE_EDIT` toggle is disabled but reflects the constant; selects/number fields still persist; keyboard focus ring shows on toggles.
- [ ] Core scanner: open the Scanner tab → "Scan core files now" → verified-count/version render and the flagged-files list appears if any core file is modified/missing (temporarily edit a core file to confirm it is caught, then restore); confirm the `core_integrity` check appears under Files & Permissions on the Health Check tab; confirm the daily `blt_secure_core_scan` cron event is scheduled.
- [ ] Malware scanner: drop a harmless test file containing `eval(base64_decode($_POST['x']));` into wp-content/uploads → "Scan for malware now" → it is flagged (plus the executable-PHP-in-uploads finding); confirm a normal site scans clean with no false positives; confirm the `malware_scan` check appears on the Health Check tab and the weekly `blt_secure_malware_scan` cron is scheduled; delete the test file afterwards.
- [ ] Activity log: create a test admin user → confirm an `activity_admin_granted` event appears on the Advanced tab; activate a plugin and switch theme → confirm those are logged with the acting user; change the site URL → confirm `activity_option_changed`; confirm front-end requests do not record transient option writes.
- [ ] Release workflow dry run: temporarily add a `test/release-dry-run` branch trigger with `draft: true` on the release step, push, download + unzip-verify the draft asset, then remove the test trigger. (workflow_dispatch only appears once the workflow file is on main.)

## Phase 2 — Detection & Monitoring (in progress)

- [x] **Health Check** — on-demand + daily WP-Cron security self-assessment (~50 checks) with a pass/warn/fail score.
  - AC: checks framework (`includes/health/`) is read-only and side-effect free; scan runs only on cron/AJAX, never on a front-end page load; results stored in the non-autoloaded `blt_secure_health_results` option; score = passed / (passed + failed), warnings/skips excluded; a check that throws is downgraded to SKIP; "Health Check" tab shows score gauge, tallies, and grouped results; catalogue is extendable via the `blt_secure_health_checks` filter (the core/malware scanners below append their own checks here).
- [x] **Core integrity scanner** — verifies WordPress core against the official wp.org md5 checksums (the "core scanner").
  - AC: fetches checksums via core's `get_core_checksums()` (direct api.wordpress.org fallback); flags `modified`/`missing`/`unknown` files under wp-admin, wp-includes, and root wp-*.php only (wp-content excluded so deleted default themes/plugins are not false positives); pure diff helpers (`classify`, `unknown_files`, `in_scope`) unit-tested; runs on a daily `blt_secure_core_scan` WP-Cron worker and on demand; latest result stored in the non-autoloaded `blt_secure_core_scan_results` option; issue list capped at 200; a Scanner tab lists flagged files; a `core_integrity` summary check feeds the Health score via `blt_secure_health_checks`; an alert fires when issues are found.
- [ ] Plugin/theme baseline integrity (hash-baseline installed plugins/themes, diff on schedule, re-baseline on update) — extends the scanner beyond core, where no wp.org checksums exist.
- [x] **Malware scanner** — pure-PHP signature scan of wp-content (the "malware scanner").
  - AC: walks uploads/plugins/themes/mu-plugins, matches PHP-family files against a bundled, feed-updatable signature set (`includes/scanner/signatures/malware-signatures.json`, extendable via `blt_secure_malware_signatures`/`blt_secure_malware_hashes` filters); high-signal rules only (superglobal-fed exec/eval, decoder-fed eval, split-string eval, webshell markers, obfuscation) validated for low false positives; flags executable PHP in uploads and known-bad hashes too; skips the plugin's own dir, node_modules/.git, and files >2 MB; findings capped at 200 and file walk at 30k; pure helpers (`scan_content`, `valid_rules`, `is_php_file`) unit-tested; weekly `blt_secure_malware_scan` cron + on-demand AJAX; results in the non-autoloaded `blt_secure_malware_results` option; a `malware_scan` summary check feeds the Health score; findings raise an alert; results shown in the Scanner tab.
- [ ] YARA engine acceleration when ext-yara is present (optional, layered behind the same scanner interface).
- [ ] IOC blocklist sync (ThreatFox, Spamhaus DROP) → push to CF IP List / custom rule
- [ ] CF firewall event ingestion → unified timeline
- [x] **Suspicious wp-admin activity log** — records high-signal backend changes as security events.
  - AC: `Blt_Secure_Activity` module hooks admin-grant (`set_user_role`), user deletion, plugin activate/deactivate, theme switch, plugin/theme/core install-or-update (`upgrader_process_complete`), and changes to watched options (siteurl/home/admin_email/users_can_register/default_role/template/stylesheet); each event is attributed to the acting user and forwarded to `Blt_Secure_Alerting::notify()` (shown on the Advanced tab, available to Phase 3 channels via `blt_secure_alert`); the high-frequency `updated_option` listener is admin-only so front-end transient writes are never observed; pure helpers (`is_admin_grant`, `is_watched_option`) unit-tested.
- [x] **Malicious upload detection (local)** — `Blt_Secure_Upload_Guard` rejects uploads at `wp_handle_upload_prefilter` that are PHP by extension (including double-extension `.php.jpg`) or carry a PHP open tag anywhere in the first 8 MB (disguised polyglot); FP-safe (no signature scan of binary media); blocked uploads raise a `blocked_upload` alert. Pure helpers (`dangerous_extension`, `has_php_open_tag`, `danger_reason`) unit-tested. *(CF-signal side remains under the Cloudflare track.)*
- [x] **feeds/feeds.json loader** — `Blt_Secure_Feeds` parses/validates the feed catalogue into normalized, filterable descriptors (`all`/`enabled`/`by_format`/`get`), rejecting entries with a bad id, non-http(s) url, or unsupported format; extendable via the `blt_secure_feeds` filter; no network I/O (consumers fetch). Pure helpers (`valid_format`, `normalize_feed`) unit-tested. Foundation for the YARA-signature and IOC consumers below.

## Phase 3 — Fleet Management (not started)

- [ ] Central dashboard (CF Workers + D1)
- [ ] Worker/KV credential store backend (swap for Blt_Secure_Encrypted_Option_Store)
- [ ] Slack/email alerting channels behind Blt_Secure_Alerting
- [ ] Scheduled feed updates w/ changelog
- [ ] Client-facing status page / trust badge
