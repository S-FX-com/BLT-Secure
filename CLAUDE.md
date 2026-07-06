# BLT Secure — Repo Conventions

WordPress hardening plugin. PHP 7.4+ compatible, WordPress 6.0+. Text domain: `blt-secure`. Prefix everything: classes `Blt_Secure_*`, functions/hooks/options `blt_secure_*`.

## Hard constraints

- **Zero runtime Composer dependencies.** Target hosts include GoDaddy shared hosting (no shell, restricted PHP builds, WP-Cron only). `composer.json` is dev tooling only and is excluded from distribution via `.distignore`.
- **wp.org-ready:** every output escaped (`esc_html__`, `esc_attr`, `esc_url`), every input sanitized, nonces + `current_user_can( 'manage_options' )` on all forms/AJAX, i18n on all user-facing strings, no minified-only JS.
- **No heavy work on page load.** Scans/syncs go through WP-Cron. Any hook into the core lifecycle gets a "what does this cost per request?" pass.
- **Cloudflare is optional.** Local hardening must work with no token configured. CF code never loads on front-end requests.

## Architecture

- Modules implement `Blt_Secure_Module` (includes/interface-blt-module.php) and are booted by the `Blt_Secure` singleton on `plugins_loaded` priority 1. Module list is filterable via `blt_secure_modules`.
- Settings live in ONE autoloaded option `blt_secure_settings` (array, sections per module). State that changes at a different cadence (CF deployment IDs, event log, encrypted token) lives in separate `autoload = no` options.
- Secrets (CF token, TOTP secrets) go through `Blt_Secure_Crypto` (sodium secretbox, openssl AES-GCM fallback, key derived from WP salts). Never store a secret in plaintext; never fall back to unauthenticated ciphers.
- Cloudflare rules are created with `"ref": "blt-secure-*"` — that ref is the idempotency anchor. Never PUT a whole ruleset entrypoint (it clobbers other tools' rules); only POST/PATCH/DELETE individual rules.

## Commands

```bash
composer install   # dev deps (phpcs, wpcs, phpunit)
composer lint      # php -l every file
composer phpcs     # WordPress-Extra standard
composer test      # unit tests — no WP install required (tests/bootstrap.php shims)
```

Always run `composer lint` and `composer test` before committing. PHPCS before pushing.

## Testing philosophy

Pure logic (TOTP math, base32, crypto envelopes, CIDR matching, CF rule payloads) is isolated in classes with no WP dependencies and unit-tested against known vectors (RFC 6238 Appendix B, golden JSON payloads). WP-coupled behavior is smoke-tested manually per the checklist in `tasks/todo.md`.

## Files

- `tasks/todo.md` — phase checklists with acceptance criteria. Keep current.
- `tasks/lessons.md` — gotchas discovered during development. Append, don't rewrite history.
- `feeds/feeds.json` — Phase 2 pluggable feed config (schema documented in the file).
