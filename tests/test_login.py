"""Signing in, 2FA, invitations, account settings."""

from __future__ import annotations

import base64
import time

from conftest import PASSWORD, csrf_of, make_user, next_code, sign_in

from login_service import totp
from login_service.app import services

# ---- TOTP itself -----------------------------------------------------------------------------

def test_totp_rfc6238_vectors():
    # RFC 6238 appendix B uses the ASCII seed "12345678901234567890"; apps take it base32-encoded.
    # Computed here rather than written out, so no key-shaped string sits in the repository.
    secret = base64.b32encode(b"12345678901234567890").decode()
    for t, eight in [(59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (2000000000, "69279037")]:
        assert totp.code_at(secret, t // 30) == eight[-6:]


def test_totp_drift_and_single_use():
    s = totp.new_secret()
    now = 1_000_000_000
    step = now // 30
    assert totp.verify(s, totp.code_at(s, step), now=now) == step
    assert totp.verify(s, totp.code_at(s, step - 1), now=now) == step - 1      # 30 s of clock drift
    assert totp.verify(s, totp.code_at(s, step - 3), now=now) is None
    assert totp.verify(s, totp.code_at(s, step), last_step=step, now=now) is None   # used already
    for junk in [None, "", "12345", "1234567", "abcdef", "١٢٣٤٥٦", 123456]:
        assert totp.verify(s, junk, now=now) is None


# ---- signing in ------------------------------------------------------------------------------

def test_password_sign_in_and_generic_errors(app, client):
    make_user(app)
    r = sign_in(client, password="wrong password!!")
    assert r.status_code == 401 and b"msg_badLogin" in r.data
    r2 = sign_in(app.test_client(), username="nobody")
    assert r2.status_code == 401 and b"msg_badLogin" in r2.data          # same answer: no account probing
    r = sign_in(client)
    assert r.status_code == 302 and r.headers["Location"] == "/account/"
    assert client.get("/account/").status_code == 200


def test_invited_account_without_password_cannot_sign_in(app, client):
    services(app).users.create("newuser")
    assert sign_in(client, username="newuser", password="").status_code == 401


def test_lockout(app, client):
    make_user(app)
    for _ in range(5):
        assert sign_in(client, password="wrong password!!").status_code == 401
    assert sign_in(client).status_code == 429                               # even the right one, for a while
    clean = app.test_client()
    clean.environ_base["REMOTE_ADDR"] = "10.1.2.3"
    assert sign_in(clean).status_code == 302                                # a clean client still gets its try


def test_2fa_sign_in(app, client):
    u = make_user(app, with_2fa=True)
    r = sign_in(client)                                                     # password only
    assert r.headers["Location"].endswith("/login/2fa")
    assert client.get("/account/").status_code == 302                       # not signed in yet
    page = client.get("/login/2fa").data
    assert client.post("/login/2fa", data={"csrf": csrf_of(page), "code": "000000"}).status_code == 401
    code = next_code(u["secret"])
    assert client.post("/login/2fa", data={"csrf": csrf_of(page), "code": code}).status_code == 302
    assert client.get("/account/").status_code == 200
    other = app.test_client()                                               # the same code can't be used again
    sign_in(other)
    page = other.get("/login/2fa").data
    assert other.post("/login/2fa", data={"csrf": csrf_of(page), "code": code}).status_code == 401


def test_2fa_step_expires(app, client):
    make_user(app, with_2fa=True)
    sign_in(client)
    with client.session_transaction() as sess:
        p = sess["pending"]
        p["at"] = time.time() - 600
        sess["pending"] = p
    assert "error=expired" in client.get("/login/2fa").headers["Location"]


def test_admin_must_set_up_2fa_and_admin_panel_needs_it(app, client):
    make_user(app, username="admin", admin=True)
    r = sign_in(client, username="admin")
    assert r.headers["Location"].endswith("/login/setup-2fa")
    page = client.get("/login/setup-2fa").data
    assert b"data:image/svg+xml" in page                                    # the QR code
    with client.session_transaction() as sess:
        secret = sess["totp_setup"]
    assert client.post("/login/setup-2fa", data={"csrf": csrf_of(page), "code": "000000"}).status_code == 400
    r = client.post("/login/setup-2fa", data={"csrf": csrf_of(page), "code": next_code(secret)})
    assert r.status_code == 302 and client.get("/admin/").status_code == 200
    # An admin session that signed in without the code (e.g. 2FA made optional and back) doesn't open the panel.
    s = services(app)
    s.db.execute("UPDATE sessions SET amr = 'pwd'")
    assert client.get("/admin/").status_code == 404


def test_next_is_never_an_open_redirect(app, client):
    make_user(app)
    for bad in ["https://evil.test/", "//evil.test/", "/\\evil.test", "/authorize?x=1\r\nSet-Cookie: a=b", "javascript:alert(1)"]:
        r = sign_in(app.test_client(), next_url=bad)
        assert r.headers["Location"] == "/account/", bad


def test_sign_in_replaces_the_session(app, client):
    make_user(app)
    with client.session_transaction() as sess:
        sess["sid"] = "attacker-fixed"
        sess["csrf"] = "attacker-known"
    sign_in(client)
    with client.session_transaction() as sess:
        assert sess["sid"] != "attacker-fixed" and sess["csrf"] != "attacker-known"


def test_logout_needs_csrf_and_ends_the_server_session(app, client):
    make_user(app)
    sign_in(client)
    with client.session_transaction() as sess:
        copied = dict(sess)
    assert client.post("/logout", data={"csrf": "x"}).status_code == 400
    client.post("/logout", data={"csrf": copied["csrf"]})
    thief = app.test_client()
    with thief.session_transaction() as sess:
        sess.update(copied)
    assert thief.get("/account/").status_code == 302


# ---- invitations -----------------------------------------------------------------------------

def test_invitation_sets_a_password_once(app, client):
    s = services(app)
    _, token = s.users.create("newuser")
    page = client.get(f"/invite/{token}").data
    r = client.post(f"/invite/{token}", data={"csrf": csrf_of(page), "password": "short", "password2": "short"})
    assert r.status_code == 400 and b"msg_pwTooShort" in r.data
    r = client.post(f"/invite/{token}", data={"csrf": csrf_of(page), "password": PASSWORD, "password2": PASSWORD + "x"})
    assert b"msg_pwMismatch" in r.data
    r = client.post(f"/invite/{token}", data={"csrf": csrf_of(page), "password": PASSWORD, "password2": PASSWORD})
    assert "passwordSet" in r.headers["Location"]
    assert client.get(f"/invite/{token}").status_code == 404                 # used up
    assert sign_in(app.test_client(), username="newuser").status_code == 302
    row = s.db.one("SELECT password_hash, invite_hash FROM users WHERE username = 'newuser'")
    assert PASSWORD not in row["password_hash"] and row["invite_hash"] == ""


def test_expired_or_unknown_invitation(app, client):
    s = services(app)
    uid, token = s.users.create("newuser")
    s.db.execute("UPDATE users SET invite_expires = 1")
    assert client.get(f"/invite/{token}").status_code == 404
    assert client.get("/invite/" + "x" * 43).status_code == 404


# ---- account settings ------------------------------------------------------------------------

def test_user_turns_2fa_on_and_off(app, client):
    make_user(app)
    sign_in(client)
    page = client.get("/account/").data
    client.post("/account/2fa/start", data={"csrf": csrf_of(page)})
    page = client.get("/account/").data
    assert b"data:image/svg+xml" in page
    with client.session_transaction() as sess:
        secret = sess["totp_setup"]
    assert client.post("/account/2fa/enable", data={"csrf": csrf_of(page), "code": next_code(secret)}).status_code == 401  # no password
    assert client.post("/account/2fa/enable", data={"csrf": csrf_of(page), "current": PASSWORD, "code": "111111"}).status_code == 400
    r = client.post("/account/2fa/enable", data={"csrf": csrf_of(page), "current": PASSWORD,
                                                  "code": totp.code_at(secret, int(time.time() // 30) + 1)})
    assert "twofaOn" in r.headers["Location"]
    assert sign_in(app.test_client()).headers["Location"].endswith("/login/2fa")   # now asked for
    row = services(app).db.one("SELECT totp_secret FROM users")
    assert secret not in row["totp_secret"]                                  # stored encrypted
    # Turning it off needs the password AND a fresh code.
    page = client.get("/account/").data
    assert client.post("/account/2fa/disable", data={"csrf": csrf_of(page), "current": "wrong", "code": "1"}).status_code == 401
    services(app).db.execute("UPDATE users SET totp_last_step = 0")   # (in real life: wait for the next code)
    step = int(time.time() // 30)
    r = client.post("/account/2fa/disable", data={"csrf": csrf_of(page), "current": PASSWORD, "code": totp.code_at(secret, step)})
    assert "twofaOff" in r.headers["Location"]


def test_admin_cannot_turn_2fa_off(app, client):
    u = make_user(app, username="admin", admin=True, with_2fa=True)
    sign_in(client, username="admin", secret=u["secret"])
    page = client.get("/account/").data
    r = client.post("/account/2fa/disable", data={"csrf": csrf_of(page), "current": PASSWORD, "code": "123456"})
    assert r.status_code == 400 and b"msg_twofaRequired" in r.data


def test_password_change_needs_the_current_one_and_ends_other_sessions(app, client):
    make_user(app)
    other = app.test_client()
    sign_in(other)
    sign_in(client)
    page = client.get("/account/").data
    new = "another long passphrase"
    r = client.post("/account/password", data={"csrf": csrf_of(page), "current": "wrong", "new": new, "new2": new})
    assert r.status_code == 401
    r = client.post("/account/password", data={"csrf": csrf_of(page), "current": PASSWORD, "new": new, "new2": new})
    assert "passwordChanged" in r.headers["Location"]
    assert client.get("/account/").status_code == 200 and other.get("/account/").status_code == 302
    assert sign_in(app.test_client(), password=new).status_code == 302


def test_sign_out_everywhere(app, client):
    make_user(app)
    other = app.test_client()
    sign_in(other)
    sign_in(client)
    client.post("/account/sign-out-everywhere", data={"csrf": csrf_of(client.get("/account/").data)})
    assert other.get("/account/").status_code == 302 and client.get("/account/").status_code == 302
