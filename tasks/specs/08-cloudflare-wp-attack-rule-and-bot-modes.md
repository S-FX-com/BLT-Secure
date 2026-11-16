# 08 — Cloudflare: consolidated WordPress-attack rule, Bot Fight Mode, notifications

**Budget reality** (https://developers.cloudflare.com/waf/custom-rules/): Free has 5 custom rules. After the
review pass the whole plugin is exactly 5 on Free (pack 2 + country 1 + leaked-creds 1 + IOC 1). New coverage
must **consolidate**, not add. `preflight_budget()` already refuses a deploy that would exceed the plan.

## 8a — One consolidated WordPress-attack rule (S)
Fold into the existing `blt-secure-custom-paths` rule (same ref → PATCH, no new rule):
- dotfiles/config: `/.env`, `/.git`, `/.htaccess`, `/wp-config.`
- backups/logs: path ends with `.sql`, `.bak`, `debug.log` (scope `.zip` to the site root, or challenge it — it breaks real downloads)
- PHP in uploads: `starts_with(path, "/wp-content/uploads/") and ends_with(path, ".php")`
- xmlrpc: only when the local XML-RPC kill switch is on
- REST user enumeration: `starts_with(path, "/wp-json/wp/v2/users")` and `query contains "rest_route=/wp/v2/users"`
- author enumeration: `query contains "author="` → **challenge**, not block, on Free/Pro (regex needs Business;
  `contains` would also match `coauthor=`).
Use `starts_with`/`lower`/`ends_with` only (no plan restriction:
https://developers.cloudflare.com/ruleset-engine/rules-language/functions/). Prefix the site's `home_url` path
for subdirectory installs. Golden-test every expression.

## 8b — Bot Fight Mode / Super Bot Fight Mode — opt-in toggle only (S)
`PUT /zones/{id}/bot_management` (token: *Bot Management Write*;
https://developers.cloudflare.com/api/resources/bot_management/methods/update/). Free = Bot Fight Mode,
Pro+ = Super Bot Fight Mode; the body differs per plan — read the plan first.
**Never part of "Deploy all".** Card copy must warn: Bot Fight Mode cannot be bypassed by WAF skip rules and may
challenge Jetpack, WooCommerce/payment webhooks, WP-Cron loopbacks and mobile-app API traffic; "Definitely
automated" must stay Allow for Tunnel users. Provide a one-click revert (store the previous setting).

## 8c — Notifications (S, operator-level)
HTTP DDoS alerts exist on every plan (https://developers.cloudflare.com/ddos-protection/reference/alerts/);
Security Events alerts need Business+ and fire on spikes only
(https://developers.cloudflare.com/waf/reference/alerts/). `POST /accounts/{id}/alerting/v3/policies` needs
*Notifications Edit* — an account permission that should **not** live in a per-site plugin token. Prefer
documenting this as an operator runbook (or a Buoy operator task, see spec 09 §Token model) over plugin code.
Verify the `alert_type` strings against the API reference before use.

## Done when
Free zone still deploys all cards within 5 custom rules; the new expressions are golden-tested; BFM is
opt-in with a working revert; no card changes ref names (existing deployments PATCH in place).
