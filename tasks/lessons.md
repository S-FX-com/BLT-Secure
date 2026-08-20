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
