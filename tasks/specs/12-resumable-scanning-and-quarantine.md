# 12 — Resumable chunked scanning + quarantine instead of delete

## 12a — Resumable scanning
The malware scan now has a time budget, an atomic lock and a `partial` flag, but a partial result is simply
partial. Make the walk resumable: persist a cursor (current root, directory index, files done) in a non-autoloaded
option, process N files / M seconds per WP-Cron tick, schedule the next tick with `wp_schedule_single_event`, and
assemble `blt_secure_malware_results` only when the cursor completes (keep the previous complete result visible
meanwhile, marked "scan in progress"). Findings accumulate in a staging option. A stale lock (>10 min) is broken.
Health shows "scan in progress" not "no scan". Same machinery for the baseline hasher.

## 12b — Quarantine
"Delete file" is irreversible and runs on heuristics that can false-positive. Replace the default with
**Quarantine**: move to `wp-content/blt-quarantine/<timestamp>/<hash>.q` (rename extension, deny-all
`.htaccess` + `index.html`, never web-served), record original path + sha256 + user + time in a non-autoloaded
option, offer **Restore** (refuse if the target path was re-created) and **Purge** (after 30 days or on click).
Keep the existing safeguards: containment, symlink handling (unlink the link, never the target), refusal for the
active theme's `functions.php`/`index.php`/`style.css` and an active plugin's main file, fingerprint lookup — never
trust a request path. Keep a separate, explicitly-confirmed "Delete permanently".

## Done when
A 30k-file site completes a scan with no request exceeding 30 s; quarantine → restore round-trips byte-identical;
the quarantine directory is not reachable over HTTP (test with the deny rules and an `index.html`).
