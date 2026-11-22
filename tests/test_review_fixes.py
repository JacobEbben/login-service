"""Regression tests for the second security review (login service side)."""

from __future__ import annotations

import base64
import json
import threading
import time
from dataclasses import replace

from conftest import (
    APP_LOGOUT,
    APP_REDIRECT,
    PASSWORD,
    authorize,
    code_from,
    csrf_of,
    make_user,
    next_code,
    pkce,
    sign_in,
)

from login_service import totp
from login_service.app import services
from login_service.oidc import valid_uri


def _claims(token: str) -> dict:
    body = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


# 1. One attacker can't use up everyone's sign-in attempts.
def test_attacker_cannot_lock_out_clean_clients(app):
    s = services(app)
    s.settings = replace(s.settings, login_attempts_per_minute=3, max_failures=100)
    make_user(app)
    attacker = app.test_client()
    for _ in range(10):
        sign_in(attacker, password="wrong password!!")
    assert b"msg_locked" in sign_in(attacker, password="wrong password!!").data   # attacker hits the cap
    clean = app.test_client()
    clean.environ_base["REMOTE_ADDR"] = "10.9.8.7"
    assert sign_in(clean).status_code == 302                                    # the real user still gets in


# 2/3. Blocking notifies every app by user (no sid), and failed notices are retried.
def test_block_notifies_every_app_and_retries(app, monkeypatch):
    s = services(app)
    s.oidc.save_client("file-share", "File Share", [APP_REDIRECT], [APP_LOGOUT], "https://share.test/bc")
    u = make_user(app)
    attempts = []

    def flaky(uri, token):
        attempts.append(token)
        return "HTTP 503" if len(attempts) == 1 else None
    monkeypatch.setattr(s.oidc, "_post", flaky)
    s.end_user(u["id"])                         # no live session here: still notified
    assert len(attempts) == 1
    claims = _claims(attempts[0])
    assert claims["sub"] == u["id"] and "sid" not in claims
    row = s.db.one("SELECT attempts, next_try FROM backchannel_outbox")
    assert row["attempts"] == 1 and row["next_try"] > time.time()
    assert s.oidc.outbox_status()["file-share"]["pending"] == 1
    s.db.execute("UPDATE backchannel_outbox SET next_try = 0")
    assert s.oidc.deliver() == 1 and len(attempts) == 2
    assert s.db.one("SELECT COUNT(*) AS n FROM backchannel_outbox")["n"] == 0


def test_no_backchannel_is_flagged_in_the_panel(app):
    s = services(app)
    s.oidc.save_client("file-share", "File Share", [APP_REDIRECT], [], "")
    u = make_user(app, username="admin", admin=True, with_2fa=True)
    c = app.test_client()
    sign_in(c, username="admin", secret=u["secret"])
    assert b"bcMissing" in c.get("/admin/").data


# 9. A half-finished sign-in can't be completed after a reset; setup never replaces a secret.
def test_pending_sign_in_dies_with_a_reset(app):
    u = make_user(app, with_2fa=True)
    c = app.test_client()
    sign_in(c)                                                  # password ok, waiting for the code
    services(app).users.reset(u["id"])
    page = c.get("/login/2fa")
    assert "error=expired" in page.headers["Location"]


def test_forced_setup_never_replaces_an_existing_secret(app):
    s = services(app)
    u = make_user(app, username="admin", admin=True)
    c = app.test_client()
    sign_in(c, username="admin")                                # pending setup
    secret = totp.new_secret()
    assert s.users.enable_2fa(u["id"], secret, next_code(secret))   # someone else finished first
    assert "error=expired" in c.get("/login/setup-2fa").headers["Location"]


# 10. Access tokens die with the sign-in.
def test_access_tokens_end_on_sign_out(app):
    s = services(app)
    secret = s.oidc.save_client("file-share", "File Share", [APP_REDIRECT], [], "")
    make_user(app)
    c = app.test_client()
    sign_in(c)
    verifier, challenge = pkce()
    q = code_from(authorize(c, challenge).headers["Location"])
    auth = base64.b64encode(f"file-share:{secret}".encode()).decode()
    tok = c.post("/token", data={"grant_type": "authorization_code", "code": q["code"], "redirect_uri": APP_REDIRECT,
                                 "code_verifier": verifier}, headers={"Authorization": "Basic " + auth}).get_json()
    bearer = {"Authorization": "Bearer " + tok["access_token"]}
    assert c.get("/userinfo", headers=bearer).status_code == 200
    c.post("/logout", data={"csrf": csrf_of(c.get("/account/").data)})
    assert c.get("/userinfo", headers=bearer).status_code == 401


# 11. Registered addresses: plain host names only (they also go into the CSP).
def test_registered_addresses_have_plain_hosts():
    for bad in ["https://*/cb", "https://*.example.com/cb", "https://a.test;script-src *", "https://a.test,https://b",
                "https://ex ample.test/", "https://a.test:99999/", "https://ëxample.test/"]:
        assert not valid_uri(bad, False), bad
    assert valid_uri("https://share.example.nl/auth/callback", False)
    assert valid_uri("https://share.example.nl:8443/cb?x=1", False)


# 12. Two admins demoting each other at once can't leave none.
def test_last_admin_race(app):
    s = services(app)
    a = make_user(app, username="admin1", admin=True)
    b = make_user(app, username="admin2", admin=True)
    start = threading.Barrier(2)

    def demote(uid):
        start.wait()
        s.users.set_admin(uid, False)
    ts = [threading.Thread(target=demote, args=(x["id"],)) for x in (a, b)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert s.users.admin_count() == 1


# 14. Production: no logout notices to internal addresses.
def test_internal_addresses_refused_in_production(app):
    s = services(app)
    s.settings = replace(s.settings, app_env="production")
    for uri in ["https://127.0.0.1/bc", "https://10.0.0.5/bc", "https://169.254.169.254/latest", "https://localhost/bc"]:
        assert s.oidc._post(uri, "x") == "refused: internal address", uri


def test_password_needed_for_2fa_also_ends_other_sessions(app):
    make_user(app)
    other = app.test_client()
    sign_in(other)
    c = app.test_client()
    sign_in(c)
    page = c.get("/account/").data
    c.post("/account/2fa/start", data={"csrf": csrf_of(page)})
    with c.session_transaction() as sess:
        secret = sess["totp_setup"]
    r = c.post("/account/2fa/enable", data={"csrf": csrf_of(page), "current": PASSWORD, "code": next_code(secret)})
    assert "twofaOn" in r.headers["Location"]
    assert other.get("/account/").status_code == 302
