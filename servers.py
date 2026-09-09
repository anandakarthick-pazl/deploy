"""Multi-server (SSH) management: CRUD + test-connection + switch current."""

from datetime import datetime

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

import audit
import ssh as ssh_helper
from models import Server, db
from permissions import requires_permission

servers_bp = Blueprint("servers", __name__)


# ---------------------------------------------------------------------------
# "Current server" helpers — exported so the sidebar / file manager / terminal
# can route operations to the right host.
# ---------------------------------------------------------------------------
def current_server() -> Server | None:
    """Return the Server object the user is currently working against, or None
    (= local). Stored in the session; falls back to None on any lookup failure."""
    sid = session.get("current_server_id")
    if not sid:
        return None
    try:
        s = Server.query.get(int(sid))
        return s
    except Exception:
        return None


def current_server_label() -> str:
    s = current_server()
    return "Local server" if not s else f"{s.name} ({s.label})"


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------
@servers_bp.route("/servers")
@requires_permission("servers.use")
def index():
    rows = Server.query.order_by(Server.name).all()
    return render_template("servers_list.html",
                           servers=rows, current=current_server())


@servers_bp.route("/servers/new", methods=["GET", "POST"])
@requires_permission("servers.manage")
def new():
    if request.method == "POST":
        return _save(None)
    return render_template("server_form.html", server=None, form={})


@servers_bp.route("/servers/<int:sid>/edit", methods=["GET", "POST"])
@requires_permission("servers.manage")
def edit(sid):
    s = Server.query.get_or_404(sid)
    if request.method == "POST":
        return _save(s)
    return render_template("server_form.html", server=s, form={})


@servers_bp.route("/servers/<int:sid>/delete", methods=["POST"])
@requires_permission("servers.manage")
def delete(sid):
    s = Server.query.get_or_404(sid)
    name = s.name
    # If the deleted server is currently selected, fall back to local.
    if session.get("current_server_id") == s.id:
        session.pop("current_server_id", None)
    try: ssh_helper.close_client(s.id)
    except Exception: pass
    db.session.delete(s)
    db.session.commit()
    audit.log("server.delete", "server", sid, name)
    flash(f"Deleted server '{name}'.", "info")
    return redirect(url_for("servers.index"))


def _save(s: Server | None):
    name      = (request.form.get("name") or "").strip()
    host      = (request.form.get("host") or "").strip()
    port      = int(request.form.get("port") or 22)
    username  = (request.form.get("username") or "").strip()
    auth_type = (request.form.get("auth_type") or "password").strip()
    description = (request.form.get("description") or "").strip() or None
    raw_pw    = request.form.get("password") or ""
    raw_key   = (request.form.get("private_key") or "").strip()
    raw_pp    = request.form.get("key_passphrase") or ""

    def _back(msg):
        flash(msg, "danger")
        # Preserve what was typed for a do-over
        return render_template("server_form.html", server=s, form=request.form)

    if not name or not host or not username:
        return _back("Name, host and username are required.")
    if auth_type not in ("password", "key"):
        return _back("Auth type must be password or key.")
    clash = Server.query.filter(Server.name == name, Server.id != (s.id if s else 0)).first()
    if clash:
        return _back(f"A server named '{name}' already exists.")

    new_row = s is None
    if new_row:
        s = Server(created_by=current_user.username)

    s.name        = name
    s.host        = host
    s.port        = port
    s.username    = username
    s.auth_type   = auth_type
    s.description = description

    if auth_type == "password":
        if new_row and not raw_pw:
            return _back("Password is required for new password-auth servers.")
        if raw_pw:
            s.password = raw_pw
        s.private_key = None
        s.key_passphrase = None
    else:
        if new_row and not raw_key:
            return _back("Paste an OpenSSH private key.")
        if raw_key:
            s.private_key = raw_key
        if raw_pp:
            s.key_passphrase = raw_pp
        s.password = None

    if new_row:
        db.session.add(s)
    db.session.commit()
    audit.log("server.save", "server", s.id, name,
              details={"new": new_row, "auth": auth_type})
    flash(f"{'Created' if new_row else 'Saved'} server '{name}'.", "success")
    return redirect(url_for("servers.index"))


# ---------------------------------------------------------------------------
# Test connection / switch / close
# ---------------------------------------------------------------------------
@servers_bp.route("/servers/<int:sid>/test", methods=["POST"])
@requires_permission("servers.use")
def test(sid):
    s = Server.query.get_or_404(sid)
    ok, msg = ssh_helper.test_connection(s)
    ssh_helper.update_check_state(s, ok, msg)
    audit.log("server.test", "server", sid, s.name, details={"ok": ok, "msg": msg[:200]})
    return jsonify(ok=ok, message=msg,
                   checked_at=s.last_check_at.isoformat() if s.last_check_at else None)


@servers_bp.route("/servers/<int:sid>/switch", methods=["POST"])
@requires_permission("servers.use")
def switch(sid):
    s = Server.query.get_or_404(sid)
    session["current_server_id"] = s.id
    audit.log("server.switch", "server", sid, s.name)
    flash(f"Now working against <b>{s.name}</b> ({s.label}).", "success")
    return redirect(request.referrer or url_for("servers.index"))


@servers_bp.route("/servers/switch-local", methods=["POST"])
@requires_permission("servers.use")
def switch_local():
    sid = session.pop("current_server_id", None)
    audit.log("server.switch_local", "server", sid, "local")
    flash("Now working against the <b>local server</b>.", "info")
    return redirect(request.referrer or url_for("servers.index"))
