"""Admin panel, headers and the usual web vulnerabilities, texts."""

from __future__ import annotations

import re
from pathlib import Path

from conftest import PASSWORD, csrf_of, make_user, sign_in

from login_service.app import services

PKG = Path(__file__).resolve().parent.parent / "login_service"


def _admin(app):
    u = make_user(app, username="admin", admin=True, with_2fa=True)
    c = app.test_client()
    sign_in(c, username="admin", secret=u["secret"])
    return c, u


def test_admin_panel_is_404_for_others(app, client):
    assert client.get("/admin/").status_code == 404
    make_user(app)
    sign_in(client)
    assert client.get("/admin/").status_code == 404
    assert client.post("/admin/users", data={"username": "xuser"}).status_code == 404


def test_create_user_shows_the_link_once(app):
    c, _ = _admin(app)
    page = c.get("/admin/").data
    assert c.post("/admin/users", data={"username": "newuser"}).status_code == 400        # CSRF
    r = c.post("/admin/users", data={"csrf": csrf_of(page), "username": "NewUser", "name": "Nieuw"})
    m = re.search(rb'value="(https://login\.test/invite/[^"]+)"', r.data)
    assert m and b"onetime_invite" in r.data
    token = m.group(1).decode().rsplit("/", 1)[1]
    assert token not in c.get("/admin/").data.decode()                        # never shown again
    assert services(app).users.invited(token)["username"] == "newuser"
    assert c.post("/admin/users", data={"csrf": csrf_of(page), "username": "newuser"}).status_code == 409
    for bad in ["<script>@x.nl", "no", "has space", "-start", "a" * 33]:
        assert c.post("/admin/users", data={"csrf": csrf_of(page), "username": bad}).status_code == 400


def test_block_reset_delete_end_sessions(app):
    c, _ = _admin(app)
    s = services(app)
    bob = make_user(app, username="bob")
    b = app.test_client()
    sign_in(b, username="bob")
    csrf = csrf_of(c.get("/admin/").data)
    c.post(f"/admin/users/{bob['id']}/block", data={"csrf": csrf})
    assert b.get("/account/").status_code == 302 and sign_in(app.test_client(), username="bob").status_code == 401
    c.post(f"/admin/users/{bob['id']}/unblock", data={"csrf": csrf})
    sign_in(b, username="bob")
    r = c.post(f"/admin/users/{bob['id']}/reset", data={"csrf": csrf})
    assert b"onetime_reset" in r.data and b.get("/account/").status_code == 302
    assert sign_in(app.test_client(), username="bob").status_code == 401    # old password gone
    c.post(f"/admin/users/{bob['id']}/delete", data={"csrf": csrf})
    assert s.users.get(bob["id"]) is None


def test_last_admin_stays(app):
    c, admin = _admin(app)
    csrf = csrf_of(c.get("/admin/").data)
    for action in ("unadmin", "block", "delete"):
        r = c.post(f"/admin/users/{admin['id']}/{action}", data={"csrf": csrf})
        assert "lastAdmin" in r.headers["Location"], action
    assert services(app).users.get(admin["id"])["is_admin"] == 1


def test_register_app_validates_addresses(app):
    c, _ = _admin(app)
    csrf = csrf_of(c.get("/admin/").data)
    for bad in ["http://share.test/cb", "https://share.test/cb#x", "https://user:pw@share.test/cb", "javascript:alert(1)", ""]:
        r = c.post("/admin/apps", data={"csrf": csrf, "client_id": "file-share", "name": "FS", "redirect_uris": bad})
        assert r.status_code == 400, bad
    r = c.post("/admin/apps", data={"csrf": csrf, "client_id": "file-share", "name": "FS",
                                    "redirect_uris": "https://share.test/auth/callback"})
    assert b"onetime_secret" in r.data
    secret = re.search(rb'id="oneTime" value="([^"]+)"', r.data).group(1).decode()
    assert secret not in c.get("/admin/").data.decode()


def test_strict_headers(client):
    for path in ["/login", "/account/", "/.well-known/openid-configuration", "/nope"]:
        h = client.get(path).headers
        csp = h["Content-Security-Policy"]
        assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp
        assert "require-trusted-types-for 'script'" in csp
        assert h["X-Frame-Options"] == "DENY" and h["X-Content-Type-Options"] == "nosniff"
        assert h["Referrer-Policy"] == "no-referrer" and "Server" not in h
    assert client.get("/login").headers["Cache-Control"] == "no-store"


def test_hsts_and_host_cookie_when_secure(tmp_path):
    from conftest import make_settings

    from login_service import create_app
    app = create_app(make_settings(tmp_path, cookie_secure=True))
    r = app.test_client().get("/login", base_url="https://login.test")
    assert "max-age=63072000" in r.headers["Strict-Transport-Security"]
    cookie = r.headers["Set-Cookie"]
    assert cookie.startswith("__Host-ls_session=") and "Secure" in cookie and "HttpOnly" in cookie


def test_no_inline_code_or_html_injection_sinks():
    for p in (PKG / "templates").glob("*.html"):
        text = p.read_text()
        assert not re.search(r"\sstyle=", text) and not re.search(r"\son[a-z]+=", text), p
        for m in re.finditer(r"<script([^>]*)>(.*?)</script>", text, re.S):
            assert not m.group(2).strip(), p
    for p in (PKG / "static/js").glob("*.js"):
        text = p.read_text()
        assert "innerHTML" not in text and "eval(" not in text and "new Function" not in text, p


def test_names_are_escaped(app):
    c, _ = _admin(app)
    s = services(app)
    uid, _ = s.users.create("xuser", "<img src=x onerror=alert(1)>")
    page = c.get("/admin/").data
    assert b"<img src=x" not in page and b"&lt;img src=x" in page


def test_password_is_never_stored_or_logged(app, caplog):
    make_user(app)
    sign_in(app.test_client())
    sign_in(app.test_client(), password="wrong-password-xyz")
    row = services(app).db.one("SELECT password_hash FROM users")
    assert row["password_hash"].startswith("scrypt:") and PASSWORD not in caplog.text and "wrong-password-xyz" not in caplog.text


def test_texts_exist_in_both_languages_and_are_used():
    i18n = (PKG / "static/js/i18n.js").read_text()

    def keys(lang):
        start = i18n.index(f"\n  {lang}: {{") + len(f"\n  {lang}: {{")
        return set(re.findall(r"(?:^|[{,]|\n)\s*([A-Za-z_][A-Za-z0-9_]*):\s", i18n[start:i18n.index("\n  },", start)]))

    en, nl = keys("en"), keys("nl")
    assert en == nl
    html = "\n".join(p.read_text() for p in (PKG / "templates").glob("*.html"))
    js = "\n".join(p.read_text() for p in (PKG / "static/js").glob("*.js") if p.name != "i18n.js")
    py = "\n".join(p.read_text() for p in PKG.rglob("*.py"))
    asked = set(re.findall(r'data-(?:i18n|i18n-aria|i18n-title|i18n-ph|confirm)="([A-Za-z_0-9]+)"', html))
    asked |= set(re.findall(r"\bt\('([A-Za-z_0-9]+)'[,)]", js))
    assert sorted(asked - en) == []
    # Keys used with a prefix at run time: msg_<error>, done_<what>, onetime_<kind>.
    dynamic = {k for k in en if k.startswith(("msg_", "done_", "onetime_", "err_"))}
    for k in dynamic:
        base = k.split("_", 1)[1].removeprefix("user_")
        assert base in py or base in html or k.startswith("err_"), k
    unused = sorted(k for k in en - dynamic if f'"{k}"' not in html and f"'{k}'" not in html and f"'{k}'" not in js)
    assert unused == []


def test_favicons(client):
    page = client.get("/login").data
    assert b'rel="icon" href="/static/icons/favicon.svg"' in page and b'rel="apple-touch-icon"' in page
    for path, kind in [("/favicon.ico", "image/png"), ("/static/icons/favicon.svg", "image/svg+xml"),
                       ("/static/icons/favicon-32.png", "image/png"), ("/static/icons/apple-touch-icon.png", "image/png")]:
        r = client.get(path)
        assert r.status_code == 200 and r.mimetype == kind, path
