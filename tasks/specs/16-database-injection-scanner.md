# 16 — Database injection scanner

File scanners miss the common SEO-spam / skimmer injections that live in the database.

## Build
Cron-only, batched (`LIMIT`/offset or ID-range cursor, ~500 rows per tick, time-boxed, resumable like spec 12a):
- `wp_posts.post_content` / `post_excerpt`: `<script src=` to a host not in an allowlist (site host + a filterable
  list of common CDNs), `<iframe` with `display:none` / 0×0, `eval(`, `atob(`, `fromCharCode` runs,
  `document.write(unescape`, hidden spam links (`display:none`/off-screen CSS containing `<a href`).
- `wp_options` (excluding transients and a known-safe name allowlist): long base64/hex values, `eval`, widget
  text/custom-HTML options containing the same JS patterns, `siteurl`/`home` drift (already watched).
- `wp_usermeta` capabilities containing `administrator` for users registered after the baseline (cross-check with
  spec 15).
- Output findings `{type:'db_injection', table, id, field}` — **no content snippets** beyond ≤120 chars of a
  redacted match; never write to the database; link to the edit screen. Honour the scan whitelist by fingerprint
  over (table, id, content hash). Feed into the Buoy bridge as severity ≤ medium (heuristic).
- Use `$wpdb->prepare` and `$wpdb->esc_like`; no user input in SQL.

## Done when
A post with an injected hidden iframe and an option with an injected `<script src>` are flagged on a 50k-post
site within the tick budget without a request exceeding 30 s; a site with a normal Google Tag Manager snippet is
not flagged (allowlist).
