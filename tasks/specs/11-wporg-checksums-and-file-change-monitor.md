# 11 — wp.org checksum verification + stat-only file-change monitor

## 11a — wp.org plugin checksums (replaces trust-on-first-use)
The baseline monitor hashes whatever is on disk the first time it sees an extension, so a site that is already
infected baselines the infection. For plugins hosted on wordpress.org, verify against
`https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json` (verify the endpoint shape when
building). Cron/AJAX only, ≤5 fetches per scan (the existing budget), cache results per slug+version,
**fail soft** (404 = not on wp.org → keep baseline-only; network error = skip, no finding). Mismatch → the
existing `drift` finding kind with `source: wporg`. Non-wp.org and premium plugins keep the baseline path;
mark their baseline `trust: first_seen` (already stored). Themes: same idea if a checksum endpoint exists.

## 11b — Stat-only file-change monitor
Hashing is too slow for shared hosting on every tick. Instead keep `path → (size, mtime)` for `wp-content`
(excluding caches/uploads media) and the ABSPATH root, one non-autoloaded option per top-level directory,
refreshed by a cron tick that does `stat()` only and respects a time budget (resume from a saved cursor).
Alert on: a new `*.php`/`.htaccess`/`.user.ini`/drop-in (`db.php`, `object-cache.php`, `advanced-cache.php`),
PHP with an mtime newer than the last scan under uploads, and mtime moving backwards (timestomping).
Content-hash only the changed set, then run it through the malware scanner. Honour the scan whitelist;
reuse `Blt_Secure_Scan_Whitelist::fingerprint('filemon', …)`.

## Done when
A modified file in a wp.org plugin is flagged even on a site that was infected before BLT Secure was
installed; a dropped `db.php` raises a finding within one tick; a 30k-file site finishes across ticks without
hitting `max_execution_time`.
