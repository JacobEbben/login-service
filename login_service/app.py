"""The composition root: ``create_app`` builds the services and registers the routes."""

from __future__ import annotations

import logging
import os
import secrets
import threading
from dataclasses import dataclass
from datetime import timedelta

from flask import Flask, current_app

from . import errors
from .adminpw import AdminPassword
from .config import Settings, from_env, validate
from .db import Database
from .keys import KeyRing, SecretBox
from .oidc import Provider
from .security import LoginLimiter, RateLimiter, register_headers
from .users import Users

log = logging.getLogger("login_service")


@dataclass
class Services:
    settings: Settings
    db: Database
    users: Users
    oidc: Provider
    keys: KeyRing
    limiter: RateLimiter
    login_limiter: LoginLimiter
    adminpw: AdminPassword           # the admin-password session (ADMIN_PASSWORD_HASH)

    def sign_out_sessions(self, sids: list[str], user_id: str) -> None:
        """After sign-ins ended here: revoke their tokens and tell the apps they were used
        for (back-channel logout, queued and retried until delivered)."""
        self.oidc.end_sessions(sids, user_id, everywhere=False)
        self.oidc.notify_now(background=self.settings.background_jobs)

    def end_user(self, user_id: str) -> None:
        """Every sign-in of a user ends (blocked, reset, deleted, sign out everywhere): here,
        and in EVERY app with a back-channel address (by user, not by sign-in)."""
        sids = self.users.end_all(user_id)
        self.oidc.end_sessions(sids, user_id, everywhere=True)
        self.oidc.notify_now(background=self.settings.background_jobs)


def services(app: Flask | None = None) -> Services:
    return (app or current_app).extensions["services"]


def _secret_key(settings: Settings) -> str:
    """SECRET_KEY, or one generated once into the data volume (never in the image).
    In production set it in the vault: it also encrypts the 2FA secrets."""
    if settings.secret_key:
        return settings.secret_key
    if settings.testing:
        return "testing-only-secret-key-not-for-production"
    path = os.path.join(settings.data_dir, "secret.key")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, encoding="ascii") as f:
            return f.read().strip()
    with os.fdopen(fd, "w", encoding="ascii") as f:
        key = secrets.token_urlsafe(48)
        f.write(key)
    return key


def create_app(settings: Settings | None = None) -> Flask:
    settings = settings or from_env()
    validate(settings)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    os.makedirs(settings.data_dir, mode=0o700, exist_ok=True)

    app = Flask(__name__)
    secure = settings.cookie_secure
    secret_key = _secret_key(settings)
    app.config.update(
        SECRET_KEY=secret_key,
        SESSION_COOKIE_NAME="__Host-ls_session" if secure else "ls_session",   # named in the privacy text
        SESSION_COOKIE_SECURE=secure,
        SESSION_COOKIE_HTTPONLY=True,
        # Lax: the apps send the browser here with a top-level GET (/authorize) and it must
        # carry the sign-in. Every state change is a POST with a CSRF token.
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=settings.session_hours),
        MAX_CONTENT_LENGTH=64 * 1024,
        TEMPLATES_AUTO_RELOAD=False,
    )
    db = Database("" if settings.testing else os.path.join(settings.data_dir, "login.db"))
    keys = KeyRing(os.path.join(settings.data_dir, "keys"))
    settings_fn = lambda: app.extensions["services"].settings  # noqa: E731 - tests replace the settings
    s = Services(settings=settings, db=db, users=Users(db, settings_fn, SecretBox(secret_key)),
                 oidc=Provider(db, keys, settings_fn), keys=keys, limiter=RateLimiter(), login_limiter=LoginLimiter(),
                 adminpw=AdminPassword(db, settings_fn, secret_key.encode()))
    app.extensions["services"] = s

    from .routes import account, admin, oidc, web
    app.register_blueprint(web.bp)
    app.register_blueprint(account.bp, url_prefix="/account")
    app.register_blueprint(admin.bp, url_prefix="/admin")
    app.register_blueprint(oidc.bp)
    errors.register(app)
    register_headers(app, hsts=secure, form_targets=lambda: services(app).oidc.form_targets())

    @app.context_processor
    def _defaults() -> dict:
        from .security import csrf_token
        return {"csrf": csrf_token(), "user": s.users.current(), "pw_admin": s.adminpw.active(), "script": "page.js"}

    if settings.background_jobs and not settings.testing:
        _start_cleanup(s)
    return app


def _start_cleanup(s: Services) -> None:
    stop = threading.Event()

    def run() -> None:
        rounds = 0
        while True:
            try:
                s.oidc.deliver()                  # retry logout notices every minute
                if rounds % 10 == 0:
                    s.users.prune()
                    s.adminpw.prune()
                    s.oidc.prune()
                    s.db.checkpoint()
            except Exception:
                errors.log_error("cleanup failed")
            rounds += 1
            if stop.wait(60):
                return

    threading.Thread(target=run, name="cleanup", daemon=True).start()
