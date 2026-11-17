# 15 — Sessions and credential hygiene

## Sessions
List the current user's / any user's sessions (`WP_Session_Tokens`) with IP, UA, login time; "Log out
everywhere else"; force-logout all sessions of a user on role change to administrator, on password reset and on
2FA disable; idle timeout (default off; 30 min–12 h) enforced on `auth_cookie_valid` / `heartbeat` without
extra DB writes beyond one throttled meta; concurrent-session cap (default off). **Re-authentication** (password,
or TOTP when enrolled) within the last 10 minutes before: installing/activating/deleting plugins and themes,
creating an administrator, changing the admin email, disabling 2FA. Use a signed, time-boxed nonce-like token in
user meta; never a client-trusted flag.

## Credential hygiene
- Optional **breached-password check** on set/change using the HIBP k-anonymity range API (send only the first 5
  hex chars of the SHA-1; `wp_safe_remote_get`, 4 s timeout, **fail open**, cron/admin context only, never on login).
  https://haveibeenpwned.com/API/v3#PwnedPasswords
- Password policy (min length, reject top-N list bundled as a small file) for roles ≥ editor.
- **Application passwords**: setting to disable for non-administrators, list/revoke from the BLT screen, alert on
  creation for administrators; do not break the 2FA application-password exemption (it is per-user now).
- Detect and alert on a **new administrator** created outside wp-admin (compare against a stored admin snapshot in
  cron) — the activity log already records `user_register`/`add_user_role`; this adds the cron cross-check.

## Done when
A stolen auth cookie cannot install a plugin without a fresh password/TOTP; "log out everywhere" invalidates
other sessions; a breached password is rejected at change time, and an HIBP outage never blocks a change.
