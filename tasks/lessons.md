# Lessons / Gotchas Log

Append-only. Things learned the hard way (or anticipated hard) while building BLT Secure.

## Seeded at design time (2026-07)

- **Login slug rename is the #1 lockout generator** in this plugin class. Mitigations shipped from day one: `BLT_SECURE_DISABLE_SLUG` wp-config constant, off-by-default, post-save notice + email with the new URL, hard bail on multisite. Flows that must survive the hidden slug: `postpass`, `logout`, `rp`/`resetpass`, `confirm_action`, `interim-login`.
- **Plugins that hardcode `wp-login.php`** (some SSO/membership plugins) will 404 behind the slug. The `site_url` filter covers everything using `wp_login_url()`; hardcoders need the `blt_secure_login_slug_bypass` filter. Document, don't chase.
- **Lockout behind Cloudflare without header trust = disaster.** Every failed login appears to come from CF edge IPs — one attacker locks out the world (or nobody). Only honor `CF-Connecting-IP` when `REMOTE_ADDR` is inside Cloudflare's published CIDR ranges. Never trust `X-Forwarded-For` — trivially spoofable, and GoDaddy's proxy layer varies.
- **Header duplication:** hosts and Cloudflare may already send HSTS/XFO. Check `headers_list()` before sending; first writer wins. HSTS never over plain HTTP; `preload` is effectively irreversible — separate explicit checkbox.
- **CSP breaks page builders** even at permissive settings. Report-Only default, never sent on wp-admin, never part of any one-click "secure everything" action.
- **Salt rotation silently kills salt-derived encryption.** Other plugins ship "rotate salts" buttons. Store an `encrypt('ok')` canary; on decrypt failure wipe credentials and show a re-enter-token notice instead of letting CF calls fail mysteriously.
- **Cloudflare plan variance:** managed rulesets need Pro+; free plan gets exactly one rate-limit rule; Access needs Zero Trust enabled (free ≤50 seats). Every deploy card must render a truthful degraded state, keyed off the plan read from the zone object.
- **Never PUT a whole ruleset entrypoint** — other tools' rules live in the same phase entrypoints. Per-rule POST/PATCH/DELETE only, with `ref` as the idempotency anchor. This also lets a fresh install re-adopt rules after a site migration instead of duplicating them.
- **Access in front of `/wp-admin` breaks anonymous `admin-ajax.php`** (front-end forms, some themes). Auto-create a bypass policy for `admin-ajax.php`; explain the residual risk in card copy.
- **RFC 6238 test vectors are 8-digit SHA-1** with ASCII secret `12345678901234567890` — don't "fix" tests to 6 digits and wonder why they fail.
- **rest_endpoints unset() for /wp/v2/users is fragile** across WP versions; `rest_pre_dispatch` route match is the stable interception point. oEmbed author leak deliberately out of Phase 1 scope.
- **GoDaddy PHP builds:** sodium has been bundled since PHP 7.2 so it's the safe primary; OpenSSL AEAD ciphers occasionally missing → if no AEAD available, refuse to store secrets rather than downgrade to CBC.
- **WP-Cron may effectively never fire** on low-traffic client sites. Anything cron-refreshed (CF IP ranges) must work forever from its shipped static fallback.

## Programmatic writes to `blt_secure_settings` go through the Settings API sanitizer

`register_setting()` attaches `sanitize_settings()` to the option via WP core's
`sanitize_option` filter, and that filter fires on EVERY `update_option()` for
that name — including our own programmatic writes (admin-ajax runs `admin_init`
first, so the callback is always registered). `sanitize_settings()` only keeps
sections owned by a module id, `advanced`, or a registered default — anything
else is silently dropped, and `Blt_Secure_Options::update_section()` masks the
loss within the same request by caching the pre-sanitize array. Symptom: the
value "saves" (and survives until the request ends) but is gone on the next
page load, and no test catches it because the test bootstrap's `update_option`
shim has no sanitize machinery. Rule: state that isn't a module settings
section belongs in its own option (like `blt_secure_cf_state`), not in
`blt_secure_settings`.

## `.blt-card` on the Cloudflare tab is a JS contract, not just a style

`admin/js/admin.js` drives the edge-protection cards with
`document.querySelectorAll( '.blt-card' )`, and "Deploy all" queues **every**
match, reading the feature from `data-feature`. When the shared BLT design
system arrived, the settings sections on the Hardening / Login / Advanced tabs
were converted from `.blt-section` to the shared `.blt-card` component — safe,
because those tabs have no `#blt-cf-deploy-all` button and no `.blt-deploy` /
`.blt-remove` children, so no listener binds and no queue runs. Adding a
`.blt-card` **to the Cloudflare tab** is a different matter: a card with no
`data-feature` joins the deploy-all queue, POSTs `feature=""`, and comes back
as a failed card. That is why the token block on that tab is a bare
`.blt-field` row instead of a card. Either keep new Cloudflare-tab containers
off `.blt-card`, or narrow the selector to `.blt-card[data-feature]` first.

## The shared BLT family store is a read-only last rung

Both fallbacks added here are reads, never writes:
`Blt_Secure_Cloudflare_Api::resolve_token()` is the single place the CF token
is resolved (the fallback must NOT go inside
`Blt_Secure_Encrypted_Option_Store::get()`, which also holds the Slack
webhook, the fleet token and the GitHub token — single-consumer secrets that
must never resolve from a shared row), and `Blt_Secure_Cloudflare_State::zone()`
gap-fills `account_id` / `host` in the array it returns only. Nothing borrowed
is ever handed to `set_zone()`: a shared `account_id` in stored state would let
the IOC deployer PUT list items into someone else's Cloudflare account.

## Review pass 2026-11-16 — authentication

- **A `WP_Error` returned at `authenticate` priority 1 is thrown away.** Core's `wp_authenticate_username_password` (priority 20) returns early only for a `WP_User`; with non-empty credentials it re-authenticates and a correct password wins. The old lockout therefore never blocked a login. Enforce at `wp_authenticate_user` (runs before the hash check) **and** at `authenticate` priority 99. Check the lock before the 2FA interstitial (priority 50), which also bypasses a priority-99 guard.
- **Lockout keyed on username alone is a remote admin-lockout** once it really blocks. Key on client IP (IPv6 reduced to /64) and the (IP, username) pair; a per-username counter may alert but must not block.
- **`$_REQUEST` at `plugins_loaded` is not what `wp-login.php` will see.** Compare raw GET+POST values: `sanitize_key`/`wp_unslash` can turn `POSTPASS` into an allowed action while core falls through to the login form.
- **`wp_parse_url('//wp-login.php')` returns no path** (it is parsed as a host). Decide on the executing script (`SCRIPT_FILENAME`), not the URI.
- **A hook added inside a POST handler that ends in a redirect is gone on the next request** (recovery codes were never shown). Register display hooks in `boot()`.
- **`did_action()` is request-wide** — under `system.multicall` an application-password success for one user exempted another user from 2FA. Track the user ID per `authenticate()` run.
- **`Plugin_Upgrader::install()` passes only `type` and `action` in `hook_extra`**; fresh installs must be checked in `upgrader_source_selection`.
- **`<?=` or `<?` + whitespace appears by chance in high-entropy data** (about once per 2 MB): a naive "PHP open tag anywhere" check rejects zips and photos. Anchor on `<?php\s` or an executable `<?=`.
- **`wp-login.php` calls `wp_signon()` with empty credentials on every visit**, and core's cookie handler answers with the logged-in user — a 2FA filter must ignore empty credentials.
- **The `site_url` filter leaks a hidden slug** through the password-protected-post form, and core redirects `/login` to `wp_login_url()` on a 404.

## Review pass 2026-11-16 — scanners

- **A security gate must not trust a field the attacker controls.** The plugin `Version:` header was the "this is a legitimate update" signal for the baseline monitor; changing it re-baselined an infected plugin silently. Trust an upgrader event or wp.org checksums.
- **`realpath()` on the final path component defeats symlink handling.** Resolve the parent directory and treat the last component as the object; deleting a symlink must unlink the link, never the target.
- **Caps must count what the user can still act on** (post-whitelist) and must not let the noisiest root starve the rest — 250 SVGs in uploads hid a webshell in `plugins/`.
- **`preg_match()` returning `false` is not "no match".** PCRE auto-optimisations hide catastrophic backtracking on long probes; test short "almost matches".
- **Mime-only `AddType` and host-generated `AddHandler …-php74 .php` lines are legitimate.** Only a non-PHP extension mapped to a PHP handler is suspicious.
- **A check that offers a fix must not make that fix create a scanner finding** — the uploads `index.php` fix produced a high-severity finding.
- **`has_action()` is not "the output is hidden".** Judge the real filter output.
- **`update_option()` returns false for both "unchanged" and "failed"** — verify large writes by reading back; split big arrays across rows (`max_allowed_packet`).
- **Whitelist/ignore must act only on findings a scanner stored**, and derive scanner and label from the stored finding.

## Review pass 2026-11-16 — Cloudflare

- **Persist per-rule progress during a deploy, and make Remove key off the live entrypoint's `blt-secure-*` refs**, never stored ids alone: a failure on rule 3 of 5 left two live, untracked rules the UI could not remove.
- **Access apps, IP lists and leaked-credential detections are account-wide and have no `ref`.** Scope their names by host, record created-vs-adopted, delete only what this plugin created. One site's Remove deleted another's app.
- **Create an Access app with its policy inline.** An app with no policy denies everyone, and the UI had no way out.
- **`self_hosted_domains` is past its sunset (2025-11-21); use `destinations`.**
- **Cloudflare returns code 10000 ("Authentication error") with HTTP 403 for missing token scope** — test 403 before the 10000 code, and plan refusals before the generic 403.
- **Choose the WAF tier from the zone plan, never from an error**; retire the other tier's refs on a transition.
- **Free plan facts that shape the whole plugin** (https://developers.cloudflare.com/waf/): 5 custom rules; 1 rate-limiting rule with a 10 s period and 10 s block; custom leaked-credential detections are Enterprise-only (WordPress is already a default location; `password_leaked` only on Free); 1 custom list, 10,000 items **account-wide**. Budget the whole plugin: 2 (pack) + 1 (country) + 1 (leaked creds) + 1 (IOC) = 5.
- **IP-list items must be IPv4 /8–/32 and IPv6 /12–/128, and the list `PUT` is asynchronous** — poll the bulk operation before reporting success; a failed or empty feed must never replace the list.
- **A feed line of `0.0.0.0/0` would block the whole site at the edge.** Reject reserved/private/too-broad ranges and never block the site's own IP, the admin's IP, or Cloudflare's ranges.
- **Form fields in a custom detection need `url_decode(http.request.body.form["x"][0])`**; `lookup_json_string` on a map is wrong.
- **`is_admin()` is true for anonymous `admin-ajax.php` and `admin-post.php`** — gate the admin stack (and the CF classes it requires) on our own action prefix.
- **A "request came from a Cloudflare IP" origin check is spoofable by other Cloudflare customers**; use a secret header added by a Transform Rule.

## Review pass 2026-11-16 — admin, fleet, updater

- **A settings-form sanitizer must keep keys the form does not render.** A disabled input or a conditionally hidden field posts nothing; render a hidden carrier. (Saving the Advanced tab silently turned the fleet schedule off for good.) A dead setting with no UI cannot be repaired by preserving it once a bug has stored a bad value — stop reading it.
- **Never do network or mail I/O inside the alert hook.** Claim the throttle, `wp_schedule_single_event`, `spawn_cron()`. Log the event before firing the action or the snapshot misses it.
- **`wp_clear_scheduled_hook()` skips events that carry args**; use `wp_unschedule_hook()`.
- **PUC's `REQUIRE_RELEASE_ASSETS` still falls through to the latest-tag source zip** — filter `request_info_result` and guard `upgrader_pre_download`. PUC stores its state with `update_site_option`, so uninstall needs `delete_site_option`.
- **Enumerate credential keys or contract-test them**, or a salt rotation leaves stale rows that later wipe a re-entered token. The rotation flag must be persistent: the request that detects it is often cron or a heartbeat.
- **Do not trust `Cf-Access-Authenticated-User-Email`** — verify the `Cf-Access-Jwt-Assertion` JWT (RS256, `aud`, `iss`, `exp`) and fail closed when unconfigured.
- **A signature keyed with the same secret that travels as the bearer adds nothing.** Derive the signing key; better, use BLT Connect.
- **Contract tests earn their keep:** every emitted high-signal slug is alerted or deliberately routine; every `Blt_Secure_*` option constant is purged by `uninstall.php` (it caught three options added by other agents the same day).

## Widening what a monitor covers is an upgrade hazard

- **A baseline written under a narrower scope must not be compared directly against a wider scan.** Widening the hashed file set (JS, JSON, config, bigger files) made every unchanged new-scope file look "added" on the first scan after upgrade — false drift on nearly every plugin, and a flood of findings into Buoy. Stamp the scope in the stored entry, compare legacy entries over what they could see, upgrade a clean one in place (new files recorded as first-seen), never upgrade a dirty one over evidence. Test with a baseline fixture written by the *previous* release, not one the new code produced.
- **A capped loop must not skip the bookkeeping later passes depend on.** Breaking out of the checksum loop at the issue cap meant the "known files" set was incomplete, so the next pass flagged genuine core files. Stop the expensive work, keep collecting the cheap state.
- **A progress write that replaces a record must carry forward what the previous record owned**, and every failure path must restore it — otherwise a failed redeploy orphans the live object it was updating.

## Measuring a detector's false-positive rate

- **Measure the pattern that actually shipped, over enough samples, and compute the expected rate.** The "0 of 60 random buffers" result for the upload guard was luck: a bare `<?=` plus one of `$`, backtick, `(`, `@` still flagged **1.33%** of random 8 MB buffers (4/300) — about one large JPEG or ZIP in 75 — and a different regex than the one in the code had been simulated. Estimate per-position probability × positions before trusting a small sample: a few-byte marker over megabytes of high-entropy data is a coin flip waiting to happen. Require structure (an expression, a boundary, a terminator) so chance bytes cannot satisfy it.
- **A test that draws from `random_bytes()` can fail on any run** however low the real rate is, and CI multiplies the draws (7 jobs × several buffers). Use a fixed corpus (a SHA-256 stream) so the test always passes or always fails, and pin both sides: chance bytes are not a hit, real payloads still are.

## Tooling

- **Composer scripts refuse to run as root** ("Do not run Composer as root"): call `vendor/bin/phpunit` / `vendor/bin/phpcs` directly, and register the WPCS paths with `phpcs --config-set installed_paths`.
- **PHPCompatibility cannot gate PHP 8 syntax here.** 9.x has no sniff for `match`, `?->`, union types, `fdiv()` or `get_debug_type()` (verified with a probe: it reported nothing); 10.x needs PHP_CodeSniffer 4, which WPCS does not support. `tests/test-php74-compat.php` reads the token stream instead. **Always prove a gate fails on a known-bad input** — a gate that checks nothing looks identical to a gate that passes.
- **Review agents' findings are hypotheses.** Several were confirmed by a reproduction (the upload regex flagged 11/20 random 2 MB blobs), one of mine was a shell-quoting artefact. Reproduce before fixing.

## Buoy link

- **BLT Connect is the only transport between a site and Buoy.** BLT Secure exposes local, read-only filters the agent applies during an authenticated `inventory.read`; it adds no network code, credentials or routes. Do not point `Blt_Secure_Fleet`'s bearer/HMAC channel at Buoy.
- **Buoy's `critical` severity opens an incident, marks backups suspect and blocks automated updates until a person triages it — and Buoy has no triage UI yet.** The bridge caps severity at `high` (`blt_secure_buoy_allow_critical` to lift it) so a regex heuristic cannot freeze updates on a client site.
- **A findings list is only "complete" if nothing was cut and every scanner ran.** The bridge sends ≤199 findings plus a `blt_secure:truncated` sentinel (also when any scan result is missing, errored or partial); Buoy resolves absent findings only from a complete list.
- **A change to Buoy that adds a command touches the `[HARD]` vocabulary** (`commands.ts`, the literal `Dispatch.php` match, vectors, both test suites, a DECISIONS entry with Shane's written approval). Prefer riding existing payloads.
