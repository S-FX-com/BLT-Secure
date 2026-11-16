# 13 — Enforced 2FA with grace period, admin reset, trusted device, passkeys

## Why
`required_admins` / `required_all` only show a nag today — an un-enrolled admin still logs in with a password
alone, and the Health check passes on the policy name. A lost phone with no admin reset means a locked-out account.

## Build
1. **Enforcement**: after a configurable grace period (default 7 days from the policy being enabled, stored per
   user on first login under the policy), an un-enrolled in-scope user is redirected to enrollment on login and
   cannot reach other admin screens until enrolled. Never lock out the *only* administrator: if no other
   administrator can reset them, fall back to nag + alert.
2. **Admin reset** (`edit_users` + `manage_options`, nonce, audit event `twofa_reset`, notifies the user by email).
3. **Trusted device**: optional 30-day cookie bound to user id + a per-user random secret + a UA hash, stored
   hashed in user meta, revoked on password change / 2FA disable / "log out everywhere".
4. **Secret decrypt failure** must not delete recovery hashes or silently drop 2FA: show a re-enrol prompt and alert.
5. **Passkeys / WebAuthn** as a phishing-resistant factor: registration + assertion ceremony with a small,
   self-contained verifier (no Composer dependency): CBOR + COSE (ES256/RS256) + authenticator-data parsing,
   RP-ID = site host, challenge in a short-lived transient, signature counter check. Largest item — build and
   fuzz the parser against the W3C test vectors before wiring any UI. Keep TOTP as the fallback.
6. Make the Health `two_factor` check report **enforced** vs **nag only**.

## Done when
Under `required_admins`, an un-enrolled admin cannot continue past the grace period; a reset admin can re-enrol;
a trusted-device cookie skips the prompt and dies on password change; passkey login works in current Chrome,
Safari and Firefox and falls back to TOTP.
