# 07 — Turnstile on login, register, lost-password and comments

## Why
Today the only friction against credential stuffing is lockout, 2FA and an edge rate-limit rule. Turnstile
is free on every plan and removes most scripted traffic before it reaches a password check.
Docs: https://developers.cloudflare.com/turnstile/ (plans: /turnstile/plans/ — Free: 20 widgets/account,
10 hostnames/widget).

## Design
- **Credentials**: site key (public) + secret key. Secret goes through `Blt_Secure_Crypto` (encrypted option
  store; add `turnstile_secret` to `known_keys()` — see the salt-rotation lesson). Do **not** give the per-site
  Cloudflare token the "Turnstile Sites Write" permission; widgets are created in the dashboard (or by an
  operator tool) and the keys pasted in. One widget can cover up to 10 hostnames.
- **Module** `Blt_Secure_Turnstile` (new, `includes/modules/class-turnstile.php`), off by default, per-form toggles.
- **Render**: `login_form`, `register_form`, `lostpassword_form`, `comment_form_after_fields` /
  `comment_form_logged_in_after`. Load `https://challenges.cloudflare.com/turnstile/v0/api.js` only on pages that
  render a protected form (never site-wide). `async defer`, explicit `action` per form.
- **Verify** server-side on `authenticate` (priority 5, before password checks — a failed challenge must not
  cost a hash), `registration_errors`, `lostpassword_post`, `preprocess_comment`:
  `POST https://challenges.cloudflare.com/turnstile/v0/siteverify` with `secret`, `response`, `remoteip` (from
  `Blt_Secure_Ip_Resolver`), `idempotency_key`; `wp_safe_remote_post`, `redirection => 0`, 8 s timeout.
  Check `success`, `hostname` equals the site host, and `action`. Tokens are single-use and expire in 300 s
  (https://developers.cloudflare.com/turnstile/get-started/server-side-validation/).
- **Failure policy** (decide, document, test): missing/invalid token → fail **closed** (generic error, counts
  toward lockout). siteverify network error/5xx → fail **open** for login (a Cloudflare outage must not lock
  admins out; lockout + 2FA remain) and log a `turnstile_unavailable` event. Never fail open on a *missing* token.
- No-JS: there is no documented no-JS mode. Show an explicit "enable JavaScript" message; offer the existing
  backup-key URL path for recovery. XML-RPC/REST/application-password auth is not challenged (it has no UI);
  leave it to the XML-RPC switch and lockout.
- **CSP**: when the headers module is enabled, add `challenges.cloudflare.com` to `script-src` and `frame-src`
  (https://developers.cloudflare.com/turnstile/reference/content-security-policy/). Never cache pages that
  carry the widget.
- Coexist with 2FA: the challenge runs before the password step; 2FA interstitial is unchanged.
- BLT family: `cloudflare` group is shared; Turnstile keys are **not** shared (per-site widget).

## Done when
A scripted login without a token is rejected before any password check; a real browser logs in; a siteverify
timeout does not block an admin; secret is encrypted at rest and never echoed; admin UI shows key status only.

## Tests
Pure `build_siteverify_request()` / `interpret_response()` (success, wrong hostname, wrong action, expired,
duplicate, network error) with golden fixtures; failure-policy matrix; the secret round-trips through the
credential store.
