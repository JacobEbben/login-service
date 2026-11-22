"""Admin panel (server-rendered forms with a CSRF field).

Admins only, and - with REQUIRE_ADMIN_2FA - only in a session that signed in
WITH the authenticator code; or the admin-password session (adminpw.py, GET/POST
/admin/login, only when ADMIN_PASSWORD_HASH is set). Others get 404, or the
admin-password login page when there is one.

Users:  POST /admin/users            create (e-mail, name) -> one-time invitation link
        POST /admin/users/<id>/reset  new invitation link; clears password + 2FA, ends sign-ins
        POST /admin/users/<id>/block | unblock | admin | unadmin | delete
Apps:   POST /admin/apps              register or edit (client id, name, addresses) -> secret once
        POST /admin/apps/<id>/secret  new client secret (shown once)
        POST /admin/apps/<id>/delete

One-time links and secrets are shown in the page that answers the POST and are
never stored in a cookie or the log. The last active admin can't be demoted,
blocked or deleted.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from functools import wraps

from flask import Blueprint, abort, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash

from ..adminpw import LABEL
from ..app import services
from ..oidc import CLIENT_ID_RE, valid_uri
from ..security import client_key, password_check_slot
from ..users import User, normalize_username
from .web import attempt_allowed, attempt_failed, attempt_succeeded, check_form

ADMIN_PASSWORD_ACCOUNT = "*admin-password*"


@dataclass(frozen=True)
class PasswordAdmin:
    """Who acts in an admin-password session (for the log; not a user)."""
    username: str = LABEL
    id: str = ""

log = logging.getLogger("login_service")
bp = Blueprint("admin", __name__)


def admin_only(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        s = services()
        user = s.users.current()
        actor: User | PasswordAdmin
        if user is not None and user.admin and not (s.settings.require_admin_2fa and "otp" not in user.amr.split()):
            actor = user
        elif s.adminpw.active():
            actor = PasswordAdmin()
        elif s.adminpw.configured() and user is None:
            return redirect(url_for("admin.login"))
        else:
            abort(404)
        if request.method == "POST":
            check_form()
        return fn(actor, *args, **kwargs)
    return wrapper


def _page(**extra):
    s = services()
    st = s.settings
    ctx = {"users": s.users.overview(), "apps": s.oidc.clients(), "issuer": st.issuer, "outbox": s.oidc.outbox_status(),
           "done": request.args.get("done", ""), "require_2fa": st.require_admin_2fa}
    ctx.update(extra)
    return render_template("admin.html", **ctx)


def _link(token: str) -> str:
    return services().settings.issuer + url_for("web.invite", token=token)


@bp.get("/")
@admin_only
def index(user):
    return _page()


@bp.post("/users")
@admin_only
def create_user(user):
    s = services()
    username = normalize_username(request.form.get("username"))
    if username is None:
        return _page(error="badUsername"), 400
    try:
        _, token = s.users.create(username, request.form.get("name", ""))
    except sqlite3.IntegrityError:
        return _page(error="usernameTaken"), 409
    log.info("%s created the account %s", user.username, username)
    return _page(one_time={"kind": "invite", "who": username, "value": _link(token)})


def _target(uid: str) -> dict:
    u = services().users.get(uid)
    if u is None:
        abort(404)
    return u


@bp.post("/users/<uid>/reset")
@admin_only
def reset_user(user, uid):
    s = services()
    target = _target(uid)
    s.end_user(uid)                 # first: the apps hear about the sign-ins that end
    token = s.users.reset(uid)
    log.info("%s reset the password and 2FA of %s", user.username, target["username"])
    return _page(one_time={"kind": "reset", "who": target["username"], "value": _link(token)})


@bp.post("/users/<uid>/<action>")
@admin_only
def user_action(user, uid, action):
    s = services()
    target = _target(uid)
    ok = True
    if action == "block":
        ok = not s.users.is_last_admin(uid)
        if ok:
            s.end_user(uid)
            ok = s.users.set_disabled(uid, True)
    elif action == "unblock":
        ok = s.users.set_disabled(uid, False)
    elif action == "admin":
        ok = s.users.set_admin(uid, True)
    elif action == "unadmin":
        ok = s.users.set_admin(uid, False)
    elif action == "delete":
        ok = not s.users.is_last_admin(uid)
        if ok:
            s.end_user(uid)
            ok = s.users.delete(uid)
    else:
        abort(404)
    if not ok:
        return redirect(url_for("admin.index", done="lastAdmin"))
    log.info("%s: %s %s", user.username, action, target["username"])
    return redirect(url_for("admin.index", done=f"user_{action}"))


def _uris(field: str, allow_local: bool) -> list[str] | None:
    values = [v.strip() for v in request.form.get(field, "").splitlines() if v.strip()]
    if len(values) > 10 or not all(valid_uri(v, allow_local) for v in values):
        return None
    return list(dict.fromkeys(values))


@bp.post("/apps")
@admin_only
def save_app(user):
    s = services()
    allow_local = s.settings.app_env != "production"
    client_id = request.form.get("client_id", "").strip().lower()
    name = " ".join(request.form.get("name", "").split())[:80]
    redirects, logouts = _uris("redirect_uris", allow_local), _uris("logout_uris", allow_local)
    backchannel = request.form.get("backchannel_uri", "").strip()
    if not CLIENT_ID_RE.match(client_id) or not name:
        return _page(error="badClientId"), 400
    if not redirects or logouts is None or (backchannel and not valid_uri(backchannel, allow_local)):
        return _page(error="badUris"), 400
    secret = s.oidc.save_client(client_id, name, redirects, logouts, backchannel)
    log.info("%s saved the app %s", user.username, client_id)
    if secret:
        return _page(one_time={"kind": "secret", "who": client_id, "value": secret})
    return redirect(url_for("admin.index", done="appSaved"))


@bp.post("/apps/<client_id>/secret")
@admin_only
def rotate_secret(user, client_id):
    secret = services().oidc.rotate_secret(client_id)
    if secret is None:
        abort(404)
    log.info("%s made a new secret for %s", user.username, client_id)
    return _page(one_time={"kind": "secret", "who": client_id, "value": secret})


@bp.post("/apps/<client_id>/delete")
@admin_only
def delete_app(user, client_id):
    if not services().oidc.delete_client(client_id):
        abort(404)
    log.info("%s removed the app %s", user.username, client_id)
    return redirect(url_for("admin.index", done="appDeleted"))


# ---- the admin password -----------------------------------------------------------------------

@bp.get("/login")
def login():
    s = services()
    if not s.adminpw.configured():
        abort(404)
    if s.adminpw.active():
        return redirect(url_for("admin.index"))
    return render_template("admin_login.html", error=request.args.get("error", ""))


@bp.post("/login")
def login_post():
    s = services()
    if not s.adminpw.configured():
        abort(404)
    check_form()
    if not attempt_allowed(ADMIN_PASSWORD_ACCOUNT, "adminpw"):
        log.warning("admin password login locked out for %s", client_key())
        return render_template("admin_login.html", error="locked"), 429
    password = request.form.get("password", "")
    try:
        with password_check_slot():
            ok = 0 < len(password) <= 1024 and check_password_hash(s.settings.admin_password_hash, password)
    except (ValueError, TypeError):           # a malformed hash in the settings
        ok = False
    if not ok:
        attempt_failed(ADMIN_PASSWORD_ACCOUNT)
        log.warning("wrong admin password from %s", client_key())
        return render_template("admin_login.html", error="badPassword"), 401
    attempt_succeeded(ADMIN_PASSWORD_ACCOUNT)
    s.adminpw.begin()
    log.info("admin signed in with the admin password from %s", client_key())
    return redirect(url_for("admin.index"))
