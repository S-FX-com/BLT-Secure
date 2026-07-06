# BLT Secure

WordPress hardening plugin with Cloudflare edge enforcement. Part of the S-FX **BLT** plugin family (alongside BLT Image Optimizer).

**Core thesis:** don't build another PHP-level WAF. Harden WordPress locally, push heavy enforcement to Cloudflare's edge via API, and pull detection signatures from open threat-intel feeds instead of proprietary research.

```
┌─────────────────────────────────────────────┐
│              Cloudflare (Edge)              │
│  Managed WAF · OWASP · Rate Limiting        │
│  Custom Rules · Leaked Creds · Access       │
└──────────────────┬──────────────────────────┘
                   │ Cloudflare API (scoped zone token)
┌──────────────────▼──────────────────────────┐
│        BLT Secure (WordPress plugin)        │
│  Login hardening · TOTP 2FA · Headers       │
│  Privacy · XML-RPC control · File guard     │
│  Cloudflare deployer (idempotent, tagged)   │
└─────────────────────────────────────────────┘
```

## Features (Phase 1)

### Local hardening — no Cloudflare required
- **Login slug rename** — hide `wp-login.php` behind a custom URL (early request interception, not rewrite rules). Escape hatch: `define( 'BLT_SECURE_DISABLE_SLUG', true );` in `wp-config.php`.
- **Login lockout** — transient-based, keyed by IP *and* username, with Cloudflare-aware client IP detection (`CF-Connecting-IP` trusted only when the request actually comes from Cloudflare's published ranges).
- **TOTP 2FA** — pure-PHP RFC 6238, QR enrollment rendered client-side (secret never leaves the site), single-use recovery codes, per-role enforcement policies.
- **Security headers** — HSTS (SSL-only), X-Frame-Options, nosniff, Referrer-Policy, starter CSP with report-only default. Skips headers already sent by the host/CDN.
- **Privacy** — hide WP version, block `?author=N` and unauthenticated REST `/wp/v2/users` enumeration.
- **XML-RPC kill switch** — off by default, one toggle for Jetpack/mobile-app users.
- **File guard** — disable wp-admin file editing; block installation/activation of file-manager plugins (filterable slug list).

### Cloudflare edge (activates with a scoped API token)
| Feature | Cloudflare phase / API |
|---|---|
| Managed WAF (WordPress) + OWASP Core Ruleset w/ paranoia+sensitivity controls | `http_request_firewall_managed` |
| Custom rules: bad-ASN challenge, TOR challenge, sensitive-path block | `http_request_firewall_custom` |
| Rate limiting on login + xmlrpc | `http_ratelimit` |
| Leaked-credentials detection on the login form | leaked-credential-checks + custom rule |
| Cloudflare Access app for `/wp-admin` | Access apps (account-scoped) |

Every rule is created with a `blt-secure-*` ref and `[BLT Secure]` description — deploys are **idempotent** (re-adopt existing rules by ref, never duplicate) and **removable** per feature from the UI. The plugin never replaces whole rulesets, so rules from other tools are untouched.

## Cloudflare token recipe

Create a **custom API token** at dash.cloudflare.com → My Profile → API Tokens:

- **Zone → Zone: Read** (zone discovery)
- **Zone → Zone WAF: Edit** (managed/custom/rate-limit rules, leaked-credential settings)
- **Account → Access: Apps and Policies: Edit** — *only* if you want the Cloudflare Access feature
- Scope to the specific zone (and account, for Access)

The token is stored encrypted (libsodium, key derived from your WP salts) in a non-autoloaded option. If your salts rotate, the plugin detects it and asks for the token again instead of failing silently.

## Updates & releases

Installed sites update straight from this private repo via the bundled [plugin-update-checker](https://github.com/YahnisElsts/plugin-update-checker) (MIT, vendored at `includes/lib/`). Each site needs a GitHub token that can read this repo:

- **Per-site UI:** BLT Secure → Advanced → *GitHub access token* — a fine-grained PAT with read-only **Contents** permission on `sfxdotcom/BLT-Secure` (or a classic PAT with `repo` scope). Stored encrypted like the Cloudflare token.
- **Fleet automation:** `define( 'BLT_SECURE_GITHUB_TOKEN', '…' );` in wp-config.php — the constant takes precedence over the stored token.

Without a token, update checks against the private repo silently find nothing; the plugin shows a warning on the Plugins/Updates screens instead of letting sites quietly fall behind.

**Release flow (automated):** every merge to `main` runs `.github/workflows/release.yml`, which bumps the version (patch by default — put `#minor` or `#major` in the merge commit message to bump higher, or use the manual *Release* workflow dispatch), commits the bump with `[skip ci]`, tags `vX.Y.Z`, builds the distribution zip per `.distignore` (stable `blt-secure/` top-level folder, verified to include PUC's internals and exclude dev files), and publishes a GitHub release with the zip attached. The update checker only accepts that zip asset (`blt-secure-X.Y.Z.zip`) — never source archives.

If branch protection is ever enabled on `main`, grant the GitHub Actions app a ruleset bypass (or switch the workflow to a PAT secret) so the bot's version-bump push isn't rejected.

## Development

No runtime Composer dependencies (target hosts include shared hosting without shell access). Dev tooling:

```bash
composer install            # phpcs + WPCS, phpunit (dev only)
composer lint               # PHP syntax check all files
composer phpcs              # WordPress coding standards
composer test               # unit tests (no WP install needed)
```

Repo conventions live in [CLAUDE.md](CLAUDE.md). Phase roadmap and acceptance criteria: [tasks/todo.md](tasks/todo.md).

## License

GPL v2 or later. Bundled `qrcode.js` is MIT-licensed (license header retained).
