=== BLT Secure ===
Contributors: sfxdotcom
Tags: security, hardening, cloudflare, two-factor, login
Requires at least: 6.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.0.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress hardening with Cloudflare edge enforcement — login protection, TOTP 2FA, security headers, and one-click WAF deployment.

== Description ==

BLT Secure is a thin, fast hardening layer for WordPress. Instead of inspecting every request in PHP the way traditional security plugins do, it hardens WordPress locally and pushes heavy enforcement to Cloudflare's edge via the Cloudflare API.

**Local hardening (works on any site, no Cloudflare required):**

* Rename the login URL and block direct access to wp-login.php
* Lock out repeated failed login attempts (per IP and per username)
* Optional TOTP two-factor authentication with recovery codes — works with any authenticator app
* Disable the wp-admin file editor and block file-manager plugin installs
* Security headers: HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and a starter Content-Security-Policy with report-only mode
* Hide the WordPress version and block user enumeration (`?author=N` and the REST users endpoint)
* Disable XML-RPC (default) with a one-click toggle for sites that need it

**Cloudflare edge enforcement (lights up when you add a scoped API token):**

* One-click deploy of Cloudflare Managed WAF rules (WordPress ruleset) and the OWASP Core Ruleset
* Curated custom rules: challenge known-bad ASNs and TOR exits, block wp-config/.env/.git probes
* Rate limiting on wp-login.php and xmlrpc.php
* Leaked-credentials detection on the login form
* Cloudflare Access (Zero Trust) in front of wp-admin

All Cloudflare rules are tagged and tracked so deploys are idempotent and fully removable from the plugin UI.

== External services ==

When you configure a Cloudflare API token, the plugin communicates with the Cloudflare API (`api.cloudflare.com`) to verify the token and deploy/remove firewall configuration for your zone. The plugin also periodically fetches Cloudflare's published IP ranges from `api.cloudflare.com/client/v4/ips` (no token or personal data involved) to safely detect visitor IPs behind the Cloudflare proxy. No site content or visitor data is sent to Cloudflare by this plugin. See the Cloudflare privacy policy: https://www.cloudflare.com/privacypolicy/

== Installation ==

1. Upload the `blt-secure` folder to `/wp-content/plugins/`, or install via the Plugins screen.
2. Activate the plugin.
3. Visit **BLT Secure** in the admin menu to configure hardening options.
4. (Optional) Add a zone-scoped Cloudflare API token under the Cloudflare tab to enable edge enforcement.

== Frequently Asked Questions ==

= Does it require Cloudflare? =

No. All local hardening works standalone. Cloudflare features activate only when a token is configured.

= I renamed my login URL and locked myself out. =

Add `define( 'BLT_SECURE_DISABLE_SLUG', true );` to `wp-config.php` to restore `wp-login.php`, log in, and fix the setting.

= What Cloudflare token permissions are needed? =

A custom token with Zone:Read and Zone WAF:Edit for your zone. Add Account → Access: Apps and Policies:Edit only if you want the Cloudflare Access feature.

== Changelog ==

= 0.1.0 =
* Initial release: login hardening, TOTP 2FA, security headers, privacy hardening, XML-RPC control, file guard, and Cloudflare one-click WAF/rate-limit/Access deployment.
