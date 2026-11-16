# 01 — CI, PHP 7.4 compatibility gate, signed releases

## Why
- BLT-Secure has no pull-request CI. `release.yml` is the only workflow and it ships every push
  to `main` to every client site after only `php -l blt-secure.php`.
- `phpcs.xml.dist` has no PHP-compatibility sniff. The plugin promises PHP 7.4+, development
  runs on 8.x, so 8.0+ syntax would pass every local gate and fatal on a client site.
- `release.yml` pushes the version-bump commit *before* it builds and verifies the zip, so a
  build failure leaves `main` bumped with no release. The tag is lightweight, so `--follow-tags`
  pushes nothing and the release action tags `main` HEAD, which may be newer than the built tree.
- `#minor` / `#major` are substring matches across the whole push (`#minority` bumps minor).
- Actions are not SHA-pinned and run with `contents: write`.
- The updater trusts TLS + GitHub account integrity only; nothing verifies the downloaded zip.
  Buoy's agent already does this properly (Ed25519-signed zips).

## Status
Steps 1 and 2 are **done**: `.github/workflows/ci.yml` runs lint + the suite on PHP 7.4–8.4 (phpcs once), and
the 7.4 gate is `tests/test-php74-compat.php` — PHPCompatibility was tried and cannot see PHP 8 (9.x has no PHP 8
sniffs; 10.x needs PHP_CodeSniffer 4, which WPCS does not support), so do not add it. Remaining: steps 3 and 4.

## Steps
1. **(done) `.github/workflows/ci.yml`** on `pull_request` and `push`: matrix PHP `7.4, 8.0, 8.1, 8.2, 8.3, 8.4`
   → `composer install`, `composer lint`, `composer phpcs`, `composer test`; plus a Node job
   running `cd dashboard && node --test` while `dashboard/` exists. Set `sodium` and `openssl` extensions.
2. **(done, different tool) PHP 7.4 gate** — `tests/test-php74-compat.php` (token-level, no dependencies).
3. **Release workflow.** Make `release.yml` depend on CI success (`workflow_run` or a reusable
   workflow). Order: determine bump → build zip → verify zip → **then** commit/tag/push. Use an
   annotated tag created by the workflow itself at the built commit. Parse bump level from the
   squash-merge title / head commit only, with word boundaries (`(^|\s)#minor(\s|$)`). Pin every
   third-party action to a full commit SHA (look the SHAs up at implementation time).
   Add `dashboard`, `build`, `node_modules` to the verify step's "must not ship" list.
4. **Signed releases.** Mirror Buoy's scheme (`DECISIONS D-2026-08-27-02`): CI signs
   `blt-secure-<v>.zip` with an Ed25519 key held as a GitHub Actions secret, publishes
   `blt-secure-<v>.zip.sig` next to it. The plugin embeds the public key and verifies the detached
   signature in `upgrader_pre_download` (before any byte is installed) with
   `sodium_crypto_sign_verify_detached`. Missing/invalid signature, or no sodium → refuse the
   update with an admin notice (fail closed). Pass `REQUIRE_RELEASE_ASSETS` to the update checker so
   it never falls back to GitHub's source zip.
   Key ceremony is the same as Buoy's: generate offline, store the private half only as a CI secret,
   embed the public half; a placeholder key must fail closed.
5. Document the ceremony in `tasks/lessons.md`.

## Done when
- A PR that adds `match`/`fdiv()`/union types fails CI (the compat test) and on the 7.4 job.
- A PR with a failing test cannot produce a release.
- A release zip without a valid `.sig` is refused by a site; a tampered zip is refused.
- A build failure leaves `main` un-bumped.

## Tests
`tests/test-updater.php`: signature verify accepts a fixture-signed zip, rejects a flipped byte,
rejects a missing sig, rejects when sodium is unavailable (shim), rejects the placeholder key.
