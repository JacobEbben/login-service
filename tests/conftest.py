"""Test helpers: an app on a temporary data folder, accounts, sign-ins and a registered app."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import sys
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from login_service import create_app, totp
from login_service.app import services
from login_service.config import Settings

ISSUER = "https://login.test"
APP_REDIRECT = "https://share.test/auth/callback"
APP_LOGOUT = "https://share.test/"
PASSWORD = "correct horse battery staple"     # test-only


def make_settings(tmp_path, **kw) -> Settings:
    base = Settings(app_env="testing", issuer=ISSUER, data_dir=str(tmp_path), cookie_secure=False, background_jobs=False)
    return replace(base, **kw)


@pytest.fixture
def app(tmp_path):
    return create_app(make_settings(tmp_path))


@pytest.fixture
def client(app):
    return app.test_client()


def csrf_of(page: bytes) -> str:
    m = re.search(rb'name="csrf" value="([^"]+)"', page)
    assert m, "no CSRF field on the page"
    return m.group(1).decode()


def make_user(app, username="alice", admin=False, with_2fa=False) -> dict:
    s = services(app)
    uid, token = s.users.create(username, "Alice", admin=admin)
    s.users.accept_invite(token, PASSWORD)
    secret = None
    if with_2fa:
        secret = totp.new_secret()
        assert s.users.enable_2fa(uid, secret, totp.code_at(secret, int(time.time() // 30) - 1))
    return {"id": uid, "username": username, "secret": secret}


def next_code(secret: str) -> str:
    """A code for a step not used before (each step works once)."""
    return totp.code_at(secret, int(time.time() // 30))


def sign_in(client, username="alice", password=PASSWORD, secret=None, next_url=None):
    page = client.get("/login" + (f"?next={next_url}" if next_url else "")).data
    r = client.post("/login", data={"csrf": csrf_of(page), "username": username, "password": password,
                                    "next": next_url or "/account/"})
    if secret and r.status_code == 302 and r.headers["Location"].endswith("/login/2fa"):
        page = client.get("/login/2fa").data
        r = client.post("/login/2fa", data={"csrf": csrf_of(page), "code": next_code(secret)})
    return r


def register_app(app, client_id="file-share", backchannel="") -> str:
    return services(app).oidc.save_client(client_id, "File Share", [APP_REDIRECT], [APP_LOGOUT], backchannel)


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorize(client, challenge, client_id="file-share", redirect_uri=APP_REDIRECT, **extra):
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri, "scope": "openid profile",
              "state": "st-123", "nonce": "nonce-456", "code_challenge": challenge, "code_challenge_method": "S256"}
    params.update(extra)
    return client.get("/authorize", query_string={k: v for k, v in params.items() if v is not None})


def code_from(location: str) -> dict[str, str]:
    q = parse_qs(urlsplit(location).query)
    return {k: v[0] for k, v in q.items()}
