# Login Service

An OpenID Connect provider with its own accounts: usernames, invitation links, TOTP two-factor authentication
(required for admins), and an admin panel for users and apps. Apps sign in with the code flow + PKCE and get
RS256-signed ID tokens and back-channel logout.

## Run

```bash
cp .env.example .env
docker compose up -d --build
docker compose exec login-service python -m login_service.admin create-admin yourname   # invitation link
```

**Apps**: Admin → Apps → add the app's redirect URI (and optional logout URIs); the client secret is shown once.
Apps should link accounts on `sub`.

**Production**: behind HTTPS with `APP_ENV=production`, `ISSUER=https://<domain>`, and a `SECRET_KEY`
(`python -m login_service.admin secret-key`) that **never changes**. Keep the `/app/data` volume.
`.github/workflows/release.yml` builds, tests and deploys on push to `main`.

## Checks

```bash
docker run --rm -v "$PWD:/src:ro" -w /src -e PYTHONDONTWRITEBYTECODE=1 python:3.12-slim sh ci/check.sh python
docker run --rm -v "$PWD:/src:ro" -w /src node:22-slim sh ci/check.sh js
docker run --rm -v "$PWD:/src:ro" -w /src python:3.12-slim sh ci/check.sh lock
```

Details: `CLAUDE.md`. Licence: MIT (`LICENSE`); fonts: SIL OFL (`login_service/static/knight/fonts/OFL.txt`).
