"""The admin password: creating the first accounts, and its limits."""

from __future__ import annotations

import re
import time
from dataclasses import replace

import pytest
from conftest import csrf_of, make_user, sign_in
from werkzeug.security import generate_password_hash

from login_service.app import services

PW = "a long admin password for tests"     # test-only


@pytest.fixture
def pw_app(app):
    s = services(app)
    s.settings = replace(s.settings, admin_password_hash=generate_password_hash(PW, method="pbkdf2:sha256:1000"))
    return app


def _login(client, password=PW):
    return client.post("/admin/login", data={"csrf": csrf_of(client.get("/admin/login").data), "password": password})


def test_off_without_a_hash(app, client):
    assert client.get("/admin/login").status_code == 404
    assert client.get("/admin/").status_code == 404


def test_password_admin_creates_the_first_accounts(pw_app):
    c = pw_app.test_client()
    assert c.get("/admin/").headers["Location"].endswith("/admin/login")
    assert _login(c, "wrong password!!").status_code == 401
    assert _login(c).headers["Location"].endswith("/admin/")
    page = c.get("/admin/").data
    assert b"pwAdminBadge" in page
    r = c.post("/admin/users", data={"csrf": csrf_of(page), "username": "firstuser", "name": "First"})
    assert re.search(rb'value="https://login\.test/invite/[^"]+"', r.data)
    uid = services(pw_app).users.by_username("firstuser")["id"]
    c.post(f"/admin/users/{uid}/admin", data={"csrf": csrf_of(page)})
    assert services(pw_app).users.get(uid)["is_admin"] == 1
    # It is not a user: no account page, no sign-in to apps.
    assert c.get("/account/").headers["Location"].startswith("/login")


def test_limits_and_lockout(pw_app):
    c = pw_app.test_client()
    _login(c)
    with c.session_transaction() as sess:
        sess["pw_at"] = sess["pw_seen"] = time.time() - 31 * 60          # idle > 30 minutes
    assert c.get("/admin/").status_code == 302
    _login(c)
    s = services(pw_app)
    s.settings = replace(s.settings, admin_password_hash=generate_password_hash("another long password!!", method="pbkdf2:sha256:1000"))
    assert c.get("/admin/").status_code == 302                             # password changed: session gone
    s.settings = replace(s.settings, admin_password_hash=generate_password_hash(PW, method="pbkdf2:sha256:1000"))
    g = pw_app.test_client()
    for _ in range(5):
        assert _login(g, "wrong password!!").status_code == 401
    assert _login(g).status_code == 429


def test_sign_out_ends_it_server_side(pw_app):
    c = pw_app.test_client()
    _login(c)
    with c.session_transaction() as sess:
        copied = dict(sess)
    c.post("/logout", data={"csrf": copied["csrf"]})
    thief = pw_app.test_client()
    with thief.session_transaction() as sess:
        sess.update(copied)
    assert thief.get("/admin/").status_code == 302


def test_normal_users_still_get_no_panel(pw_app):
    make_user(pw_app)
    c = pw_app.test_client()
    sign_in(c)
    assert c.get("/admin/").status_code == 404


def test_hash_must_not_be_a_plain_password(tmp_path):
    from conftest import make_settings

    from login_service.config import validate
    with pytest.raises(ValueError):
        validate(replace(make_settings(tmp_path), app_env="production", admin_password_hash="hunter2hunter2hunter2"))


def test_production_requires_a_secret_key(tmp_path):
    from conftest import make_settings

    from login_service.config import validate
    prod = replace(make_settings(tmp_path), app_env="production", cookie_secure=True, issuer="https://login.example.nl")
    for bad in ("", "too-short"):
        with pytest.raises(ValueError, match="SECRET_KEY"):
            validate(replace(prod, secret_key=bad))
    validate(replace(prod, secret_key="x" * 40))


def test_secret_key_command(capsys):
    from login_service.admin import main
    assert main(["secret-key"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("SECRET_KEY: ") and len(out.split()[1]) >= 60
