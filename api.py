"""Bearer-token API for programmatic deploys + token management UI."""

import hashlib
import secrets
from datetime import datetime
from functools import wraps

from flask import Blueprint, abort, flash, g, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import audit
from models import ApiToken, Branch, Repo, User, db
from permissions import requires_permission

api_bp = Blueprint("api", __name__)


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _require_bearer():
    """Authenticate the request via Authorization: Bearer <token>. Returns the
    matching ApiToken row (and stamps last_used_*), or aborts with 401."""
    hdr = request.headers.get("Authorization", "")
    if not hdr.startswith("Bearer "):
        abort(401, "Missing or malformed Authorization header (expected 'Bearer <token>')")
    raw = hdr.removeprefix("Bearer ").strip()
    if not raw:
        abort(401, "Empty bearer token")
    token = ApiToken.query.filter_by(token_hash=_hash_token(raw)).first()
    if not token or not token.is_active:
        abort(401, "Invalid or revoked token")
    ip = request.headers.get("X-Real-IP") or request.remote_addr
    token.last_used_at = datetime.utcnow()
    token.last_used_ip = (ip or "")[:45] or None
    db.session.commit()
    g.api_user = token.user
    g.api_token = token
    return token


def bearer_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        _require_bearer()
        return fn(*args, **kwargs)
    return wrapped


def _user_can_access_repo(user: User, repo: Repo) -> bool:
    if user.is_admin:
        return True
    return repo in user.repos


# ---------------------------------------------------------------------------
# Programmatic deploy trigger
# ---------------------------------------------------------------------------
@api_bp.route("/api/repos/<owner>/<name>/branches/<branch_name>/deploy", methods=["POST"])
@bearer_required
def api_deploy(owner, name, branch_name):
    repo = Repo.query.filter_by(owner=owner, name=name).first()
    if not repo:
        return jsonify(error=f"unknown repo {owner}/{name}"), 404
    if not _user_can_access_repo(g.api_user, repo):
        return jsonify(error="forbidden"), 403
    branch = Branch.query.filter_by(repo_id=repo.id, name=branch_name).first()
    if not branch:
        return jsonify(error=f"unknown branch {branch_name}"), 404
    if not branch.is_active:
        return jsonify(error="branch is inactive"), 409

    from deploy_webhook import trigger_manual_deploy
    deploy_id = trigger_manual_deploy(branch, f"api:{g.api_user.username}")
    audit.log("deploy.api_trigger", "branch", branch.id, f"{repo.name}/{branch_name}",
              details={"token_id": g.api_token.id}, actor=g.api_user)
    return jsonify(
        accepted=True, deploy_id=deploy_id,
        live_url=url_for("admin.deploy_live", deploy_id=deploy_id, _external=True),
    ), 202


# ---------------------------------------------------------------------------
# Token management UI (per-user)
# ---------------------------------------------------------------------------
@api_bp.route("/tokens")
@requires_permission("tokens.manage")
def tokens_list():
    """Per-user token management page."""
    tokens = (ApiToken.query.filter_by(user_id=current_user.id)
              .order_by(ApiToken.revoked_at.is_(None).desc(), ApiToken.created_at.desc()).all())
    return render_template("api_tokens.html", tokens=tokens, new_token=None)


@api_bp.route("/tokens/new", methods=["POST"])
@requires_permission("tokens.manage")
def tokens_create():
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Give the token a name (e.g. 'CI deploy bot').", "danger")
        return redirect(url_for("api.tokens_list"))

    raw = "pkw_" + secrets.token_urlsafe(36)
    row = ApiToken(
        user_id=current_user.id, name=name,
        token_hash=_hash_token(raw),
        token_prefix=raw[:12],
    )
    db.session.add(row)
    db.session.commit()
    audit.log("token.create", "token", row.id, name)

    tokens = (ApiToken.query.filter_by(user_id=current_user.id)
              .order_by(ApiToken.revoked_at.is_(None).desc(), ApiToken.created_at.desc()).all())
    flash("Token created — copy it now, it won't be shown again.", "success")
    return render_template("api_tokens.html", tokens=tokens, new_token=raw)


@api_bp.route("/tokens/<int:token_id>/revoke", methods=["POST"])
@requires_permission("tokens.manage")
def tokens_revoke(token_id):
    t = ApiToken.query.get_or_404(token_id)
    if t.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    if not t.revoked_at:
        t.revoked_at = datetime.utcnow()
        db.session.commit()
        audit.log("token.revoke", "token", t.id, t.name)
        flash(f"Revoked token '{t.name}'.", "info")
    return redirect(url_for("api.tokens_list"))
