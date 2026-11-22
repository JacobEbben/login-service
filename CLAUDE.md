# CLAUDE.md — Login Service

The central OpenID Connect provider for the AH Dashboard and File Share, with its own users (no Google). Flask +
Waitress, one process. README.md has the operator view.

## Commands (Docker only)

```bash
docker run --rm -v "$PWD:/src:ro" -w /src -e PYTHONDONTWRITEBYTECODE=1 python:3.12-slim sh ci/check.sh python  # 64 pytest + ruff + mypy
docker run --rm -v "$PWD:/src:ro" -w /src node:22-slim sh ci/check.sh js        # tsc + node tests
docker run --rm -v "$PWD:/src:ro" -w /src python:3.12-slim sh ci/check.sh lock
docker build -t login-service:ci . && bash deploy/smoke-image.sh login-service:ci
```

## Layout (`login_service/`)

- `app.py`: `create_app`, `Services` (`settings, db, users, oidc, keys, limiter, login_limiter`), `end_user()`
  (all sign-ins + tokens + back-channel), cleanup thread.
- `config.py` (`Settings`, `validate`: ISSUER required, https in production), `db.py` (SQLite, `?` params only).
- `users.py`: accounts keyed by **username** (`USERNAME_RE`, lower case; no e-mail addresses anywhere), invitations/resets (token hashes), passwords (scrypt, `password_problem`), TOTP
  (`totp_check` stores the accepted step), sessions (`begin`/`end`/`end_all`/`current`).
- `totp.py` (RFC 6238, tested with its vectors), `keys.py` (`KeyRing`: RS256 signing + JWKS + rotation;
  `SecretBox`: 2FA secrets encrypted with a key from SECRET_KEY), `oidc.py` (`Provider`: clients, authorize
  checks, codes, token exchange, userinfo, back-channel logout tokens).
- `routes/web.py` (login, 2FA, forced admin 2FA setup, invitations, logout; `attempt_allowed` = the lockout),
  `routes/account.py`, `routes/admin.py`, `routes/oidc.py`.
- `admin.py`: CLI `create-admin` / `reset` (prints one-time links). Static: Knight copy + `app.css`, JS
  (`common.js`, `i18n.js` en+nl). Templates are server-rendered; JS only does texts, theme, copy, confirm.

## Invariants

- **Redirects**: `redirect_uri` must EXACTLY equal a registered one; errors before that check are shown here,
  never redirected. After sign-in only our own paths (`web.safe_next`). Post-logout only to the client's
  registered `logout_uris`. RP logout needs a click (CSRF form), never a bare GET.
- **Claims**: scopes `openid profile` only; the ID token carries `sub`, `preferred_username`, `name` (no email).
  Apps must link accounts on `sub`.
- **Admin user table**: one column per action, the button (`.tbtn`) fills its fixed-width cell, so labels like
  Block/Unblock never change the layout.
- **Codes/tokens**: PKCE S256 + nonce required; codes single-use (read+delete in one transaction), 60 s, bound
  to client + redirect_uri + session (signed out since → refused). Only hashes of codes, tokens, client
  secrets and invitation tokens are stored. No refresh tokens.
- **Logout notices** (`oidc.end_sessions` + `deliver`): queued in `backchannel_outbox` and retried with back-off
  (cleanup job, every minute) up to 10 times; fresh token per attempt; production refuses internal addresses.
  Block/reset/delete/sign-out-everywhere notify EVERY app with a back-channel address by `sub` (no `sid`). The admin
  panel shows waiting/failed notices and apps without a back-channel address. Access tokens carry their `sid`
  and are revoked with it.
- **Lockouts**: `attempt_allowed()` before EVERY password or code check (also re-checks in account settings);
  failures counted before the check; the account lock only blocks clients with recent failures. The server-wide
  cap is split into a bucket for clients with recent failures and a 4x larger one for clean clients (one attacker
  can't lock everyone out); authenticator codes (cheap) have no global cap. Turning 2FA on needs the password and
  ends other sign-ins; half-finished sign-ins carry a credentials fingerprint (`web._version`) and die with a reset.
  Last-admin checks run in the same transaction as the change.
- **Admin password** (`adminpw.py`): `/admin/login` (404 without `ADMIN_PASSWORD_HASH`), a session of its own
  (`pw_sessions` row + cookie keys, keyed fingerprint of the hash, 30 min idle / 4 h), NOT a user: admin panel only,
  logged as "(admin password)". Same lockout as signing in (`attempt_allowed('*admin-password*')`). A user sign-in
  replaces it. Hash refused unless scrypt/pbkdf2; the CLI demands ≥ 16 characters.
- **Admins**: with REQUIRE_ADMIN_2FA the admin panel requires a session with `amr` containing `otp`; admins
  can't turn 2FA off; the last active admin can't be demoted/blocked/deleted.
- **SECRET_KEY** is required in production (`config.validate`, ≥ 32 chars, from the vault; never generated
  into the volume there) and never changes after go-live (it decrypts the 2FA secrets). Signing keys live in the data
  volume (`keys/`), mode 0600; rotation = rename + restart.
- **CSP form-action** = 'self' + registered apps' origins (browsers apply it to the redirect after the login
  POST). No inline scripts/styles/handlers, no `innerHTML` (tests grep).
- Every UI string in en AND nl (`i18n.js`); `msg_`/`done_`/`onetime_` keys are used via a prefix.
- Never open or print `.env` or real secrets; test values stay obviously fake. Never commit (the user does).
