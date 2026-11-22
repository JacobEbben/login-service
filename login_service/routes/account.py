"""Account settings (signed in).

GET  /account                     overview: name, 2FA, sign-ins
POST /account/name
POST /account/password            current + new password (other sign-ins end)
POST /account/2fa/start           a new authenticator secret (shown as QR, not active yet)
POST /account/2fa/enable          confirm with a code from the app: 2FA on
POST /account/2fa/disable         password + current code: 2FA off (not for admins when it's required)
POST /account/sign-out-everywhere every sign-in here, and in the apps (back-channel)

Every POST carries the CSRF token. Changing a security setting asks for the
current password (or code) again, so a stolen session alone can't lock the
owner out or turn 2FA off.
"""

from __future__ import annotations

import logging
from functools import wraps

from flask import Blueprint, redirect, render_template, request, session, url_for

from .. import totp
from ..app import services
from ..security import password_check_slot
from ..users import password_problem
from .web import SETUP_KEY, _setup_context, attempt_allowed, attempt_failed, attempt_succeeded, check_form

log = logging.getLogger("login_service")
bp = Blueprint("account", __name__)


def signed_in(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = services().users.current()
        if user is None:
            return redirect(url_for("web.login", next=request.full_path.rstrip("?") if request.method == "GET" else "/account"))
        if request.method == "POST":
            check_form()
        return fn(user, *args, **kwargs)
    return wrapper


def _page(user, **extra):
    s = services()
    setup = session.get(SETUP_KEY) if isinstance(session.get(SETUP_KEY), str) else None
    ctx = {"me": user, "sessions": s.users.session_count(user.id),
           "required_2fa": user.admin and s.settings.require_admin_2fa, "done": request.args.get("done", "")}
    if setup and not user.has_2fa:
        ctx.update(setup=True, **_setup_context(setup, user.username))
    ctx.update(extra)
    return render_template("account.html", **ctx)


def _password_ok(user) -> bool:
    """Re-check the current password (counts against the same lockouts as signing in)."""
    s = services()
    if not attempt_allowed(user.username):
        return False
    with password_check_slot():
        ok = s.users.check_password(user.username, request.form.get("current", "")) is not None
    if ok:
        attempt_succeeded(user.username)
    else:
        attempt_failed(user.username)
    return ok


@bp.get("/")
@signed_in
def index(user):
    return _page(user)


@bp.post("/name")
@signed_in
def name(user):
    services().users.set_name(user.id, request.form.get("name", ""))
    return redirect(url_for("account.index", done="nameSaved"))


@bp.post("/password")
@signed_in
def password(user):
    if not _password_ok(user):
        return _page(user, error="badPassword"), 401
    new = request.form.get("new", "")
    problem = password_problem(new, user.username)
    if problem is None and new != request.form.get("new2", ""):
        problem = "pwMismatch"
    if problem:
        return _page(user, error=problem), 400
    s = services()
    other = [r["sid"] for r in s.db.all("SELECT sid FROM sessions WHERE user_id = ? AND sid != ?",
                                        (user.id, session.get("sid") or ""))]
    s.users.change_password(user.id, new, session.get("sid"))
    s.sign_out_sessions(other, user.id)
    log.info("%s changed their password", user.username)
    return redirect(url_for("account.index", done="passwordChanged"))


@bp.post("/2fa/start")
@signed_in
def start_2fa(user):
    if user.has_2fa:
        return redirect(url_for("account.index"))
    session[SETUP_KEY] = totp.new_secret()
    return redirect(url_for("account.index") + "#twofa")


@bp.post("/2fa/enable")
@signed_in
def enable_2fa(user):
    s = services()
    secret = session.get(SETUP_KEY)
    if user.has_2fa or not isinstance(secret, str):
        return redirect(url_for("account.index"))
    # The current password too: a stolen session alone must not be able to put the
    # attacker's authenticator on the account (the owner would be locked out).
    if not _password_ok(user):
        return _page(user, error="badPassword"), 401
    if not attempt_allowed(user.username, "code"):
        return _page(user, error="locked"), 429
    if not s.users.enable_2fa(user.id, secret, request.form.get("code", ""), only_if_unset=True):
        attempt_failed(user.username)
        return _page(user, error="badCode"), 400
    attempt_succeeded(user.username)
    session.pop(SETUP_KEY, None)
    # Other sign-ins end: whoever else had a session must now pass the new second factor.
    other = [r["sid"] for r in s.db.all("SELECT sid FROM sessions WHERE user_id = ? AND sid != ?",
                                        (user.id, session.get("sid") or ""))]
    s.db.execute("DELETE FROM sessions WHERE user_id = ? AND sid != ?", (user.id, session.get("sid") or ""))
    s.sign_out_sessions(other, user.id)
    log.info("%s turned 2FA on", user.username)
    return redirect(url_for("account.index", done="twofaOn"))


@bp.post("/2fa/cancel")
@signed_in
def cancel_2fa(user):
    session.pop(SETUP_KEY, None)
    return redirect(url_for("account.index"))


@bp.post("/2fa/disable")
@signed_in
def disable_2fa(user):
    s = services()
    if not user.has_2fa:
        return redirect(url_for("account.index"))
    if user.admin and s.settings.require_admin_2fa:
        return _page(user, error="twofaRequired"), 400
    if not _password_ok(user):
        return _page(user, error="badPassword"), 401
    record = s.users.get(user.id)
    if record is None or not s.users.totp_check(record, request.form.get("code", "")):
        attempt_failed(user.username)
        return _page(user, error="badCode"), 400
    s.users.disable_2fa(user.id)
    log.info("%s turned 2FA off", user.username)
    return redirect(url_for("account.index", done="twofaOff"))


@bp.post("/sign-out-everywhere")
@signed_in
def sign_out_everywhere(user):
    services().end_user(user.id)
    session.clear()
    return redirect(url_for("web.login", error="signedOutEverywhere"))
