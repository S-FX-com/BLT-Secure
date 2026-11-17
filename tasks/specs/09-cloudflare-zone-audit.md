# 09 — Cloudflare zone audit (read-only first) and token model

## Audit checks (surface in the Health tab; each is read-only; opt-in fix only for the low-risk ones)
| Check | API | Notes |
|---|---|---|
| SSL/TLS mode, min TLS version, TLS 1.3, Always Use HTTPS, Automatic HTTPS Rewrites, edge HSTS | `GET /zones/{id}/settings/<id>` | *Zone Settings Read*. One-click fix **only** for Always Use HTTPS and Automatic HTTPS Rewrites. "Full (strict)" only after a successful origin-certificate probe (strict + bad cert = 526). Flexible + WordPress HTTPS redirect = loop — warn. HSTS preload is effectively irreversible. |
| DNSSEC status | `GET /zones/{id}/dnssec` | *DNS Read*. Status check only — enabling needs a DS record at the registrar; a wrong one is an outage, so keep enable manual. |
| Exposed origin / dangling records | `GET /zones/{id}/dns_records` | *DNS Read*. Flag grey-cloud A/AAAA on the web host (origin IP exposure). |
| SPF / DKIM / DMARC | `dns_get_record()` | No token needed; works on shared hosting. |
| Cache bypass correctness | Cache Rules read | A "Cache Everything" rule must never cover `/wp-login.php`, `/wp-admin/*`, or requests with `wp-`, `wordpress`, `comment_`, `woocommerce_` cookies (https://developers.cloudflare.com/automatic-platform-optimization/reference/query-parameters/). Confirm the token permission name for rulesets/cache in the token UI before coding. |
| Page Shield script inventory | Page Shield read (*Client-side security Read*) | Script monitoring is on every plan; CSP management is Advanced-only. Read-only list of third-party scripts. |
| Origin lock | Transform rule + plugin check | A "request came from a Cloudflare IP" check is spoofable by other Cloudflare customers. Use a secret request header added by a Request Header Transform Rule (*Transform Rules Edit*) that the plugin verifies; Authenticated Origin Pulls and Tunnel are not possible on shared hosting. |

## Token model (decision needed)
Today one token carries Zone Read + Zone WAF Edit + Analytics Read (+ Account Filter Lists Edit, Access: Apps and
Policies Edit). *Zone WAF Edit* is coarse — it covers every ruleset phase. Recommended split:
1. **Enforce token** (per zone): Zone Read, Zone WAF Edit, Analytics Read, + per feature: Account Filter Lists
   Edit, Access Apps and Policies Edit, Bot Management Edit, Transform Rules Edit.
2. **Audit token** (read-only): Zone Settings Read, SSL and Certificates Read, DNS Read, Zone WAF Read,
   Client-side security Read, Analytics Read. A leak cannot change anything.
Never put Turnstile-write, Notifications-write, DNS-write or Registrar permissions in a per-site token.
Confirm the Edit-vs-Write permission names in the token UI (the permissions table lists both:
https://developers.cloudflare.com/fundamentals/api/reference/permissions/).

**Buoy tension:** `DECISIONS D-2026-08-27-03` keeps a Cloudflare token out of the Worker on purpose. A
Buoy-side audit would reverse that. Until Shane approves a per-account read-only audit token (wrapped in D1 under
the master KEK, with a DECISIONS entry), Buoy only rolls up what the plugin already reports (spec 03).

## Done when
Health tab lists each audit with plain-language remediation; nothing is changed without a click; audit works
with the read-only token; the two-token setup is documented in `README.md`.
