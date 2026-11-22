# Login Service

The central sign-in for the AH Dashboard and File Share (and future apps), on its own domain
(`login.example.nl`). It is an **OpenID Connect provider** with its own user management:
no Google, no third parties.

- **Accounts** have a **username** (3-32 characters: a-z, 0-9, `. _ -`), no e-mail address. They are made by an
  admin; there is no self sign-up. A new user gets a one-time
  **invitation link** to choose a password (≥ 12 characters, scrypt-hashed).
- **Two-factor authentication** with an authenticator app (TOTP: Google Authenticator,
  Microsoft Authenticator, 1Password, Aegis, …), switched on by each user in their **account
  settings** (QR code or key). **Required for admins** (`REQUIRE_ADMIN_2FA`, default on): an
  admin sets it up at the first sign-in, and the admin panel only opens in a session that
  signed in with the code.
- **Lost password or authenticator**: the admin makes a reset link (clears password and 2FA, ends
  every sign-in). No e-mail is needed.
- **Admin password** (`ADMIN_PASSWORD_HASH`, optional): `/admin/login` opens the admin panel to create the first
  accounts; see "First accounts".
- **Admin panel**: users (create + invite, reset, block, make admin, delete) and apps (register,
  redirect URIs, new client secret, remove). The last admin can't be demoted, blocked or deleted.
- **Apps** sign people in with the authorization-code flow: PKCE (S256) and a nonce required,
  exact redirect URIs, one-time codes (60 s), RS256-signed ID tokens (`/jwks.json`), back-channel
  logout when a sign-in ends here (sign out, blocked, reset).

Python 3.12, Flask, Waitress, `cryptography`, `segno` (QR codes); Knight design (Light/Dark), Dutch and English.

## First accounts

There is no default password and no setup page that works without a secret. Two ways:

**The admin password** (like AH Dashboard and File Share). Create its hash, put it in the vault (or `.env`,
single-quoted) and restart:

```bash
docker compose run --rm login-service python -m login_service.admin password    # at least 16 characters
```

Then sign in at `/admin/login`, create the accounts (each gets an invitation link) and make one an admin. The
admin-password session is not a user: it can only use the admin panel, can't sign in to apps, and ends after 30
minutes idle or 4 hours. It is a single factor (admins with an account must use 2FA), so **remove
`ADMIN_PASSWORD_HASH` once your admin accounts exist**, or keep it only as a long, safely stored emergency key.

**The command line**, on the server:

```bash
docker exec -it login-service python -m login_service.admin create-admin yourname "Your Name"
```

It prints a one-time link (48 h). Choose a password there, sign in, and set up the
authenticator app. `… admin reset yourname` makes a new link if you lose access.

## Connecting an app

1. In **Admin → Apps → Add an app**: a client id (e.g. `file-share`), a name, the exact
   redirect URI (`https://share.example.nl/auth/callback`), optionally post-logout URIs and a
   back-channel logout URI. The **client secret is shown once**: put it in that app's vault.
2. In the app: issuer `https://login.example.nl` (discovery at
   `/.well-known/openid-configuration`), the client id and secret.

What an app gets in the ID token: `sub` (stable, random user id: link accounts on this, not on
the username), `preferred_username` and `name` (scope `profile`), `auth_time`, `amr` (`["pwd"]` or
`["pwd","otp"]`), `sid`, `nonce`. Apps keep their own permissions (who is admin *there*).

## Security

- Strict CSP (`default-src 'none'`, Trusted Types, `frame-ancestors 'none'`; `form-action`
  lists only the registered apps' origins), HSTS, COOP/COEP/CORP, `no-store` on pages and tokens.
- `__Host-` session cookie (Secure, HttpOnly, SameSite=Lax), a new session at every sign-in,
  sign-out ends it on the server, rights re-checked on every request.
- Guessing: every password or code attempt is counted before the check (atomically), per client
  and per account (the account lock only blocks clients that already failed, so nobody can lock a
  person out); a server-wide cap; the same answer for unknown accounts, with the same hashing time.
- Codes from the authenticator work once (the accepted time step is stored). 2FA secrets are
  stored encrypted with a key derived from `SECRET_KEY`.
- Invitation tokens, client secrets, authorization codes and access tokens are stored as SHA-256
  only, and shown once.
- Changing the password, or turning 2FA off, needs the current password (and code).

## Run locally

```bash
cp .env.example .env    # ISSUER=http://127.0.0.1:8081, APP_ENV=development, COOKIE_SECURE=false
docker compose up -d --build
docker compose exec login-service python -m login_service.admin create-admin yourname
```

## Checks (Docker only)

```bash
docker run --rm -v "$PWD:/src:ro" -w /src -e PYTHONDONTWRITEBYTECODE=1 python:3.12-slim sh ci/check.sh python  # pytest, ruff, mypy
docker run --rm -v "$PWD:/src:ro" -w /src node:22-slim sh ci/check.sh js
docker run --rm -v "$PWD:/src:ro" -w /src python:3.12-slim sh ci/check.sh lock
docker build -t login-service:ci . && bash deploy/smoke-image.sh login-service:ci
```

## Deploy with vps-platform

Checked against vps-platform's own validation and render (the generated compose file runs this image healthy:
read-only, no capabilities, user `app`, 256 MB). Step by step:

1. **DNS**: `login.example.nl` → the server.
2. **Repository**: push this folder to GitHub (`login-service`). `release.yml` builds, tests, smoke-tests,
   scans and pushes `ghcr.io/<owner>/login-service`. **Make that GHCR package public** (Package settings →
   visibility): vps-platform pulls without a registry login. The image holds no secrets.
3. **Secrets** (from the image, or locally with `docker compose run --rm login-service …`):
   ```bash
   docker run --rm ghcr.io/<owner>/login-service python -m login_service.admin secret-key     # SECRET_KEY
   docker run --rm -it ghcr.io/<owner>/login-service python -m login_service.admin password   # ADMIN_PASSWORD_HASH
   ```
   `SECRET_KEY` is **required** in production (it also encrypts the 2FA secrets; the app refuses to start
   without it) and must **never change** afterwards. Keep a copy in your password manager.
4. **vps-platform** (in `../vps-platform`):
   ```bash
   ./vpsctl app add login-service        # the values from deploy/vps-app.yml
   ./vpsctl vault-edit login-service     # SECRET_KEY and ADMIN_PASSWORD_HASH (one line each)
   ./vpsctl app apply login-service
   ./vpsctl github login-service         # prints the gh commands: run them in this repository
   gh variable set DEPLOY_ENABLED --body true
   ```
   Every push to `main` now deploys: backup of the data volume, old container stopped, new one started,
   health check (`/healthz`, also through Caddy), automatic rollback.
5. **First accounts**: `https://login.example.nl/admin/login` with the admin password → create your account
   (invitation link) → make it admin → sign in, set up the authenticator app. Then remove
   `ADMIN_PASSWORD_HASH` from the vault (`vault-edit` + `app apply`), or keep it as a long emergency key.
6. **Apps**: Admin → Apps → add each app with the addresses its admin panel lists (File Share: Admin →
   "Login service"). File Share reaches the login service over its public HTTPS address (server to server).

**Key rotation**: move `/app/data/keys/signing-key.pem` to e.g. `2026-11.pem` and restart; a new key
signs from then on, the old one stays published so existing tokens verify. Remove it a day later.

## Not (yet) included

Passkeys, recovery codes, self-service password reset by e-mail, a privacy statement and terms
page. See CLAUDE.md before adding any of them.
