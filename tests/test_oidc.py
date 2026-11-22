"""The OpenID Connect flow, as an app sees it, and every way it must refuse."""

from __future__ import annotations

import base64
import json
import time

from conftest import (
    APP_LOGOUT,
    APP_REDIRECT,
    ISSUER,
    authorize,
    code_from,
    csrf_of,
    make_user,
    pkce,
    register_app,
    sign_in,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from login_service.app import services


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_id_token(client, token: str, audience: str) -> dict:
    """Verify like an app would: with the published JWKS only."""
    jwks = client.get("/jwks.json").get_json()
    head, body, sig = token.split(".")
    header = json.loads(_b64d(head))
    key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    pub = rsa.RSAPublicNumbers(int.from_bytes(_b64d(key["e"]), "big"), int.from_bytes(_b64d(key["n"]), "big")).public_key()
    pub.verify(_b64d(sig), f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    claims = json.loads(_b64d(body))
    assert header["alg"] == "RS256" and claims["iss"] == ISSUER and claims["aud"] == audience and claims["exp"] > time.time()
    return claims


def _exchange(client, code, verifier, secret, client_id="file-share", redirect_uri=APP_REDIRECT, basic=True):
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri, "code_verifier": verifier}
    if basic:
        auth = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
        return client.post("/token", data=data, headers={"Authorization": "Basic " + auth})
    return client.post("/token", data={**data, "client_id": client_id, "client_secret": secret})


def _flow(app, client, **user_kw):
    secret = register_app(app) or services(app).oidc.rotate_secret("file-share")
    u = make_user(app, **user_kw)
    sign_in(client, secret=u["secret"])
    verifier, challenge = pkce()
    r = authorize(client, challenge)
    assert r.status_code == 302 and r.headers["Location"].startswith(APP_REDIRECT + "?")
    return secret, u, verifier, code_from(r.headers["Location"])


def test_discovery_and_jwks(client):
    d = client.get("/.well-known/openid-configuration").get_json()
    assert d["issuer"] == ISSUER and d["code_challenge_methods_supported"] == ["S256"]
    assert d["response_types_supported"] == ["code"] and d["backchannel_logout_supported"] is True
    keys = client.get("/jwks.json").get_json()["keys"]
    assert keys and all(k["kty"] == "RSA" and "d" not in k for k in keys)        # never the private part


def test_full_flow_gives_a_valid_signed_id_token(app, client):
    secret, u, verifier, q = _flow(app, client)
    assert q["state"] == "st-123" and q["iss"] == ISSUER
    r = _exchange(client, q["code"], verifier, secret)
    assert r.status_code == 200 and r.headers["Cache-Control"] == "no-store"
    tok = r.get_json()
    claims = verify_id_token(client, tok["id_token"], "file-share")
    assert claims["sub"] == u["id"] and claims["preferred_username"] == "alice" and claims["nonce"] == "nonce-456"
    assert claims["amr"] == ["pwd"] and claims["sid"]
    info = client.get("/userinfo", headers={"Authorization": "Bearer " + tok["access_token"]}).get_json()
    assert info == {"sub": u["id"], "preferred_username": "alice", "name": "Alice"}


def test_amr_shows_2fa(app, client):
    secret, u, verifier, q = _flow(app, client, with_2fa=True)
    claims = verify_id_token(client, _exchange(client, q["code"], verifier, secret).get_json()["id_token"], "file-share")
    assert claims["amr"] == ["pwd", "otp"]


def test_code_works_once(app, client):
    secret, u, verifier, q = _flow(app, client)
    assert _exchange(client, q["code"], verifier, secret).status_code == 200
    assert _exchange(client, q["code"], verifier, secret).get_json() == {"error": "invalid_grant"}


def test_pkce_verifier_must_match(app, client):
    secret, u, verifier, q = _flow(app, client)
    other, _ = pkce()
    assert _exchange(client, q["code"], other, secret).get_json() == {"error": "invalid_grant"}
    assert _exchange(client, q["code"], verifier, secret).status_code == 400     # and the code is gone now


def test_client_must_authenticate(app, client):
    secret, u, verifier, q = _flow(app, client)
    r = _exchange(client, q["code"], verifier, "wrong-secret")
    assert r.status_code == 401 and r.get_json() == {"error": "invalid_client"}
    assert _exchange(client, q["code"], verifier, secret, basic=False).status_code == 200   # client_secret_post works too


def test_code_is_bound_to_client_and_redirect_uri(app, client):
    secret, u, verifier, q = _flow(app, client)
    other_secret = services(app).oidc.save_client("other-app", "Other", ["https://other.test/cb"], [], "")
    assert _exchange(client, q["code"], verifier, other_secret, client_id="other-app").get_json() == {"error": "invalid_grant"}
    secret, u2, verifier, q = _flow(app, app.test_client(), username="bob")  # (new secret)
    assert _exchange(client, q["code"], verifier, secret, redirect_uri=APP_REDIRECT + "x").get_json() == {"error": "invalid_grant"}


def test_expired_code(app, client):
    secret, u, verifier, q = _flow(app, client)
    services(app).db.execute("UPDATE codes SET expires = 1")
    assert _exchange(client, q["code"], verifier, secret).get_json() == {"error": "invalid_grant"}


def test_unregistered_redirect_is_never_followed(app, client):
    register_app(app)
    make_user(app)
    sign_in(client)
    _, challenge = pkce()
    for bad in ["https://evil.test/cb", APP_REDIRECT + "/../x", APP_REDIRECT + "?a=1", "https://share.test.evil.test/auth/callback"]:
        r = authorize(client, challenge, redirect_uri=bad)
        assert r.status_code == 400 and "Location" not in r.headers, bad
    assert authorize(client, challenge, client_id="nope").status_code == 400


def test_request_errors_go_back_to_the_app(app, client):
    register_app(app)
    make_user(app)
    sign_in(client)
    _, challenge = pkce()
    for kw, error in [({"code_challenge": None}, "invalid_request"), ({"code_challenge_method": "plain"}, "invalid_request"),
                      ({"nonce": None}, "invalid_request"), ({"scope": "profile"}, "invalid_scope"), ({"scope": "openid email"}, "invalid_scope"),
                      ({"scope": "openid admin"}, "invalid_scope"), ({"response_type": "token"}, "unsupported_response_type")]:
        r = authorize(client, challenge, **kw)
        q = code_from(r.headers["Location"])
        assert r.headers["Location"].startswith(APP_REDIRECT) and q["error"] == error and q["state"] == "st-123", kw
        assert "code" not in q


def test_not_signed_in_goes_to_login_then_back(app):
    register_app(app)
    make_user(app)
    c = app.test_client()
    _, challenge = pkce()
    r = authorize(c, challenge)
    assert r.headers["Location"].startswith("/login?next=/authorize")
    nxt = code_from(r.headers["Location"])["next"]
    r = c.post("/login", data={"csrf": csrf_of(c.get("/login").data), "username": "alice",
                               "password": "correct horse battery staple", "next": nxt})
    assert r.headers["Location"].startswith("/authorize?")
    r = c.get(r.headers["Location"])
    assert r.headers["Location"].startswith(APP_REDIRECT) and "code=" in r.headers["Location"]
    # prompt=none without a sign-in: an error back to the app, no login page
    r = authorize(app.test_client(), challenge, prompt="none")
    assert code_from(r.headers["Location"])["error"] == "login_required"


def test_signed_out_or_blocked_after_the_code(app, client):
    secret, u, verifier, q = _flow(app, client)
    services(app).end_user(u["id"])
    assert _exchange(client, q["code"], verifier, secret).get_json() == {"error": "invalid_grant"}


def test_userinfo_needs_a_valid_token(app, client):
    assert client.get("/userinfo").status_code == 401
    assert client.get("/userinfo", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_backchannel_logout_tokens(app, client, monkeypatch):
    sent = []
    s = services(app)
    s.oidc.save_client("file-share", "File Share", [APP_REDIRECT], [APP_LOGOUT], "https://share.test/backchannel")
    secret = s.oidc.rotate_secret("file-share")
    monkeypatch.setattr(s.oidc, "_post", lambda uri, token: sent.append(token))
    u = make_user(app)
    sign_in(client)
    verifier, challenge = pkce()
    q = code_from(authorize(client, challenge).headers["Location"])
    claims = verify_id_token(client, _exchange(client, q["code"], verifier, secret).get_json()["id_token"], "file-share")
    client.post("/logout", data={"csrf": csrf_of(client.get("/account/").data)})
    assert len(sent) == 1
    head, body, _ = sent[0].split(".")
    lt = json.loads(_b64d(body))
    assert json.loads(_b64d(head))["typ"] == "logout+jwt"
    assert lt["sid"] == claims["sid"] and lt["sub"] == u["id"] and "nonce" not in lt
    assert "http://schemas.openid.net/event/backchannel-logout" in lt["events"]


def test_rp_logout_needs_a_click_and_only_goes_to_registered_addresses(app, client):
    register_app(app)
    make_user(app)
    sign_in(client)
    r = client.get("/logout", query_string={"client_id": "file-share", "post_logout_redirect_uri": APP_LOGOUT, "state": "x"})
    assert r.status_code == 200 and b"logoutTitle" in r.data             # a link alone doesn't sign anyone out
    assert client.get("/account/").status_code == 200
    page = r.data
    r = client.post("/logout/confirm", data={"csrf": csrf_of(page), "client_id": "file-share",
                                             "post_logout_redirect_uri": APP_LOGOUT, "state": "x"})
    assert r.headers["Location"] == APP_LOGOUT + "?state=x"
    assert client.get("/account/").status_code == 302                    # signed out
    sign_in(client)
    page = client.get("/logout", query_string={"client_id": "file-share", "post_logout_redirect_uri": "https://evil.test/"}).data
    r = client.post("/logout/confirm", data={"csrf": csrf_of(page), "client_id": "file-share",
                                             "post_logout_redirect_uri": "https://evil.test/"})
    assert "evil" not in r.headers["Location"]


def test_client_secret_is_stored_hashed(app):
    secret = register_app(app)
    row = services(app).db.one("SELECT secret_hash FROM clients")
    assert secret not in row["secret_hash"] and len(row["secret_hash"]) == 64


def test_form_action_allows_registered_apps_only(app, client):
    register_app(app)
    csp = client.get("/login").headers["Content-Security-Policy"]
    assert "form-action 'self' https://share.test" in csp and "evil" not in csp
