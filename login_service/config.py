"""Settings, from the environment (production) or directly (tests). See .env.example."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass


def unquote(value: str) -> str:
    """Strip ONE matching pair of quotes, like Docker Compose does for env files."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    app_env: str = "production"
    issuer: str = ""                          # https://login.example.nl: the OIDC issuer and public address
    data_dir: str = "/app/data"               # database + signing key + generated secret key (a volume)
    secret_key: str = ""                      # Flask session signing + 2FA secret encryption; generated when empty
    cookie_secure: bool = True                # HTTPS only (__Host- cookie); false for local http
    session_hours: int = 12                   # the single sign-on session (absolute)
    require_admin_2fa: bool = True            # admins must set up an authenticator app before they get in
    admin_password_hash: str = ""             # werkzeug hash (python -m login_service.admin password); '' = off
    admin_session_minutes: int = 30           # admin-password session: idle limit ...
    admin_session_max_hours: int = 4          # ... and absolute limit
    invite_hours: int = 48                    # invitation / reset links
    max_failures: int = 5                     # wrong passwords or codes per client ...
    account_max_failures: int = 10            # ... and per account, within ...
    lockout_seconds: int = 900                # ... this window
    login_attempts_per_minute: int = 30       # server-wide cap on password checks (0: off)
    code_seconds: int = 60                    # authorization codes
    id_token_seconds: int = 300
    access_token_seconds: int = 600
    privacy_contact: str = ""
    background_jobs: bool = True              # tests switch off cleanup and back-channel threads

    @property
    def testing(self) -> bool:
        return self.app_env == "testing"


def _int(env: Mapping[str, str], key: str, default: int, low: int, high: int) -> int:
    raw = unquote(env.get(key, "").strip())
    if not raw:
        return default
    value = int(raw)
    if not low <= value <= high:
        raise ValueError(f"{key} must be between {low} and {high}")
    return value


def from_env(env: Mapping[str, str] = os.environ) -> Settings:
    def get(key: str, default: str = "") -> str:
        return unquote(env.get(key, default).strip())

    return Settings(
        app_env=get("APP_ENV", "production") or "production",
        issuer=get("ISSUER").rstrip("/"),
        data_dir=get("DATA_DIR", "/app/data") or "/app/data",
        secret_key=get("SECRET_KEY"),
        cookie_secure=_bool(get("COOKIE_SECURE", "true")),
        session_hours=_int(env, "SESSION_HOURS", 12, 1, 24 * 30),
        require_admin_2fa=_bool(get("REQUIRE_ADMIN_2FA", "true")),
        admin_password_hash=get("ADMIN_PASSWORD_HASH"),
        admin_session_minutes=_int(env, "ADMIN_SESSION_MINUTES", 30, 1, 240),
        admin_session_max_hours=_int(env, "ADMIN_SESSION_MAX_HOURS", 4, 1, 24),
        invite_hours=_int(env, "INVITE_HOURS", 48, 1, 24 * 14),
        privacy_contact=get("PRIVACY_CONTACT"),
    )


def validate(s: Settings) -> None:
    """Refuse settings that would be unsafe in production."""
    if s.testing:
        return
    if s.admin_password_hash and not s.admin_password_hash.startswith(("scrypt:", "pbkdf2:")):
        raise ValueError("ADMIN_PASSWORD_HASH must be a hash from `python -m login_service.admin password`")
    if not s.issuer:
        raise ValueError("ISSUER is required (e.g. https://login.example.nl)")
    if not s.issuer.startswith(("https://", "http://127.0.0.1", "http://localhost")):
        raise ValueError("ISSUER must be https://…")
    if "?" in s.issuer or "#" in s.issuer:
        raise ValueError("ISSUER must not contain a query or fragment")
    if s.app_env == "production" and (not s.cookie_secure or not s.issuer.startswith("https://")):
        raise ValueError("production needs COOKIE_SECURE=true and an https ISSUER")
    if s.app_env == "production" and len(s.secret_key) < 32:
        # It also encrypts the 2FA secrets: generated into the data volume it would sit next to the
        # database in every backup. In production it must come from the vault.
        raise ValueError("production needs SECRET_KEY (>= 32 characters, from the vault): "
                         "python -m login_service.admin secret-key")
