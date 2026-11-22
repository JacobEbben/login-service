"""OpenID Connect endpoints.

GET  /.well-known/openid-configuration   discovery
GET  /jwks.json                          the public signing keys
GET  /authorize                          sign in (if needed) and send a one-time code back to the app
POST /token                              the app swaps the code for an ID token (client secret + PKCE)
GET  /userinfo                           (Bearer access token) the signed-in user's claims
GET  /logout                             RP-initiated logout: asks to confirm (no logout by a mere link)
POST /logout/confirm                     signs out here and in the apps, then back to the app
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from ..app import services
from ..oidc import AuthorizeError, TokenError
from ..security import client_key
from .web import check_form

log = logging.getLogger("login_service")
bp = Blueprint("oidc", __name__)


@bp.get("/.well-known/openid-configuration")
def discovery():
    iss = services().settings.issuer
    return jsonify({
        "issuer": iss,
        "authorization_endpoint": iss + "/authorize",
        "token_endpoint": iss + "/token",
        "userinfo_endpoint": iss + "/userinfo",
        "jwks_uri": iss + "/jwks.json",
        "end_session_endpoint": iss + "/logout",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile"],
        "claims_supported": ["sub", "preferred_username", "name", "auth_time", "amr", "sid"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": True,
        "backchannel_logout_supported": True,
        "backchannel_logout_session_supported": True,
    })


@bp.get("/jwks.json")
def jwks():
    resp = jsonify(services().keys.jwks())
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


@bp.get("/authorize")
def authorize():
    s = services()
    if not s.limiter.allow("authorize", client_key(), 60, 60):
        return render_template("message.html", key="tooMany"), 429
    args = {k: v for k, v in request.args.items()}
    try:
        req = s.oidc.check_authorize(args)
    except AuthorizeError as exc:
        if exc.redirect:
            return redirect(exc.redirect_url(s.settings.issuer))
        log.warning("bad authorization request from %s: %s", client_key(), exc.error)
        return render_template("message.html", key="badRequest"), 400
    user = s.users.current()
    if user is None:
        if req["prompt"] == "none":
            return redirect(AuthorizeError("login_required", "Not signed in.", req["redirect_uri"], req["state"])
                            .redirect_url(s.settings.issuer))
        return redirect(url_for("web.login", next=request.full_path))
    url = s.oidc.issue_code(req, user.id, str(session.get("sid")), s.users.session_auth_time(), user.amr)
    log.info("%s signed in to %s", user.username, req["client"]["client_id"])
    return redirect(url)


def _token_error(exc: TokenError):
    resp = jsonify(error=exc.error)
    resp.status_code = exc.status
    if exc.status == 401:
        resp.headers["WWW-Authenticate"] = 'Basic realm="token"'
    return resp


@bp.post("/token")
def token():
    s = services()
    if not s.limiter.allow("token", client_key(), 120, 60):
        return jsonify(error="slow_down"), 429
    form = {k: v for k, v in request.form.items()}
    try:
        client = s.oidc.authenticate_client(request.headers.get("Authorization"), form)
        return jsonify(s.oidc.exchange(client, form, s.users.get))
    except TokenError as exc:
        if exc.error != "invalid_grant":
            log.warning("token request refused (%s) from %s", exc.error, client_key())
        return _token_error(exc)


@bp.route("/userinfo", methods=["GET", "POST"])
def userinfo():
    s = services()
    auth = request.headers.get("Authorization", "")
    info = s.oidc.userinfo(auth[7:], s.users.get) if auth.startswith("Bearer ") else None
    if info is None:
        resp = jsonify(error="invalid_token")
        resp.status_code = 401
        resp.headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
        return resp
    return jsonify(info)


def _logout_target(args) -> tuple[str | None, str | None]:
    """The registered post-logout address for this request (or None), and the state."""
    s = services()
    client_id = args.get("client_id")
    hint = args.get("id_token_hint")
    if hint:
        try:
            client_id = s.keys.verify(hint, issuer=s.settings.issuer, leeway=10**9).get("aud")  # may be expired
        except ValueError:
            return None, None
    client = s.oidc.client(client_id)
    uri = args.get("post_logout_redirect_uri")
    state = args.get("state")
    if client and uri in client["logout_uris"]:
        return uri, state if isinstance(state, str) and len(state) <= 512 else None
    return None, None


@bp.get("/logout")
def logout():
    """An app asks to sign the user out. Not done on a GET: a link or image elsewhere
    must not be able to sign people out. The page asks to confirm (one click)."""
    s = services()
    uri, state = _logout_target(request.args)
    if s.users.current() is None:
        return redirect(_with_state(uri, state) if uri else url_for("web.login", error="signedOut"))
    return render_template("logout.html", args=request.args)


@bp.post("/logout/confirm")
def logout_confirm():
    check_form()
    s = services()
    uri, state = _logout_target(request.form)
    user = s.users.current()
    sid = s.users.end()
    if user is not None and sid:
        s.sign_out_sessions([sid], user.id)
    return redirect(_with_state(uri, state) if uri else url_for("web.login", error="signedOut"))


def _with_state(uri: str, state: str | None) -> str:
    from urllib.parse import urlencode
    return uri + (("&" if "?" in uri else "?") + urlencode({"state": state}) if state else "")
