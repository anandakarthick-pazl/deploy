"""Admin dashboard: list repos, CRUD on repos + branches, deploy history, users."""

import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import desc, func
from werkzeug.utils import secure_filename

import audit
import permissions as perm
from models import ApiToken, AppSettings, AuditLog, Branch, Deploy, Repo, Role, RolePermission, Server, User, db, user_repos

DEPLOY_LOG_DIR = Path(os.getenv("DEPLOY_LOG_DIR", "/var/log/packwork-deploy/deploys"))
UPLOAD_DIR     = Path(__file__).resolve().parent / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_LOGO_EXT = {"png", "jpg", "jpeg", "gif", "svg", "webp"}
MAX_LOGO_SIZE    = 2 * 1024 * 1024  # 2 MB

admin_bp = Blueprint("admin", __name__)


# ---------------------------------------------------------------------------
# Decorators / helpers
# ---------------------------------------------------------------------------
def admin_required(fn):
    """Routes that only site admins should reach."""
    @wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapped


def _check_repo_access(repo):
    """Abort 403 if the current user can't see this repo. Admins always pass."""
    if not current_user.can_access_repo(repo):
        abort(403)


def _accessible_repo_ids():
    """List of repo IDs the current user can see (admins: all)."""
    if current_user.is_admin:
        return [r.id for r in Repo.query.with_entities(Repo.id).all()]
    return [r.id for r in current_user.repos]


def _parse_list(text: str) -> list:
    """Each non-empty line is one entry (used for recipients textarea)."""
    if not text:
        return []
    return [line.strip() for line in text.replace("\r", "").split("\n") if line.strip()]


def _list_to_text(items) -> str:
    if not items:
        return ""
    return "\n".join(items)


def _parse_commands(form) -> list:
    """Read the ordered list of commands from the row-based UI.

    The form has many `commands[]` inputs — Flask preserves their order.
    Empty rows are skipped.
    """
    return [c.strip() for c in form.getlist("commands[]") if c and c.strip()]


def _parse_env_vars(form) -> dict:
    """Read paired env_key[] / env_value[] inputs into a dict. Empty keys dropped."""
    keys = form.getlist("env_key[]")
    vals = form.getlist("env_value[]")
    out = {}
    for k, v in zip(keys, vals):
        k = (k or "").strip()
        if not k:
            continue
        out[k] = (v or "").rstrip("\r\n")   # preserve internal whitespace
    return out


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@admin_bp.route("/api/dashboard")
@perm.requires_permission("deploys.view")
def dashboard_data():
    """Lightweight JSON used by the dashboard's auto-refresh poll."""
    repos = current_user.accessible_repos().order_by(Repo.name).all()
    repo_ids = [r.id for r in repos]
    if repos:
        success_count = Deploy.query.filter(Deploy.repo_id.in_(repo_ids), Deploy.status == "success").count()
        failed_count  = Deploy.query.filter(Deploy.repo_id.in_(repo_ids), Deploy.status == "failed").count()
        pending_count = Deploy.query.filter(Deploy.repo_id.in_(repo_ids), Deploy.status == "pending").count()
        awaiting_count = Deploy.query.filter(Deploy.repo_id.in_(repo_ids), Deploy.status == "awaiting").count()
        recent = (Deploy.query.filter(Deploy.repo_id.in_(repo_ids))
                  .order_by(desc(Deploy.started_at)).limit(10).all())
    else:
        success_count = failed_count = pending_count = awaiting_count = 0
        recent = []
    return jsonify({
        "metrics": {
            "repos":    len(repos),
            "branches": sum(len(r.branches) for r in repos),
            "success":  success_count,
            "failed":   failed_count,
            "pending":  pending_count,
            "awaiting": awaiting_count,
        },
        "recent": [{
            "id": d.id, "started_at": d.started_at.isoformat(),
            "build_number": d.build_number,
            "repo_name": d.repo_name, "branch_name": d.branch_name,
            "status": d.status,
            "commit_sha": (d.commit_sha or "")[:7] or None,
            "pusher": d.pusher,
            "url": url_for("admin.deploy_detail", deploy_id=d.id),
            "edit_url": url_for("admin.branch_edit", branch_id=d.branch_id) if d.branch_id else None,
        } for d in recent],
    })


@admin_bp.route("/")
@perm.requires_permission("deploys.view")
def dashboard():
    repos = current_user.accessible_repos().order_by(Repo.name).all()
    repo_ids = [r.id for r in repos]

    # Metrics — filtered by what this user can see
    if repos:
        success_count = Deploy.query.filter(Deploy.repo_id.in_(repo_ids), Deploy.status == "success").count()
        failed_count  = Deploy.query.filter(Deploy.repo_id.in_(repo_ids), Deploy.status == "failed").count()
        pending_count = Deploy.query.filter(Deploy.repo_id.in_(repo_ids), Deploy.status == "pending").count()
    else:
        success_count = failed_count = pending_count = 0

    metrics = {
        "repos":   len(repos),
        "branches": sum(len(r.branches) for r in repos),
        "success": success_count,
        "failed":  failed_count,
        "pending": pending_count,
    }

    last_deploys = {}
    for repo in repos:
        last = (
            Deploy.query.filter_by(repo_name=repo.name)
            .order_by(desc(Deploy.started_at)).first()
        )
        last_deploys[repo.id] = last

    if repos:
        recent = (
            Deploy.query.filter(Deploy.repo_id.in_(repo_ids))
            .order_by(desc(Deploy.started_at)).limit(10).all()
        )
        awaiting = (
            Deploy.query.filter(Deploy.repo_id.in_(repo_ids), Deploy.status == "awaiting")
            .order_by(desc(Deploy.started_at)).all()
        )
    else:
        recent = []
        awaiting = []

    return render_template(
        "dashboard.html",
        repos=repos, metrics=metrics,
        last_deploys=last_deploys, recent=recent, awaiting=awaiting,
    )


# ---------------------------------------------------------------------------
# Repos CRUD (create/delete restricted to admins; non-admin can edit their permitted repos)
# ---------------------------------------------------------------------------
@admin_bp.route("/repos/new", methods=["GET", "POST"])
@perm.requires_permission("repos.create")
def repo_new():
    if request.method == "POST":
        name  = (request.form.get("name") or "").strip()
        owner = (request.form.get("owner") or "").strip()
        display_name = (request.form.get("display_name") or "").strip() or None
        server_id_raw = (request.form.get("server_id") or "").strip()
        server_id = int(server_id_raw) if server_id_raw.isdigit() else None
        recipients = _parse_list(request.form.get("recipients", ""))

        if not name or not owner:
            flash("Name and owner are required.", "danger")
            return render_template("repo_form.html", repo=None, mode="new",
                                   form=request.form, recipients_text=request.form.get("recipients", ""),
                                   servers=Server.query.order_by(Server.name).all())
        if Repo.query.filter_by(owner=owner, name=name).first():
            flash(f"{owner}/{name} already exists.", "danger")
            return render_template("repo_form.html", repo=None, mode="new",
                                   form=request.form, recipients_text=request.form.get("recipients", ""),
                                   servers=Server.query.order_by(Server.name).all())

        repo = Repo(name=name, owner=owner, display_name=display_name,
                    server_id=server_id, recipients=recipients)
        db.session.add(repo)
        db.session.commit()
        audit.log("repo.create", "repo", repo.id, f"{owner}/{name}")
        flash(f"Created {owner}/{name}.", "success")
        return redirect(url_for("admin.repo_detail", repo_id=repo.id))

    return render_template("repo_form.html", repo=None, mode="new", form={}, recipients_text="",
                           servers=Server.query.order_by(Server.name).all())


@admin_bp.route("/repos/<int:repo_id>")
@perm.requires_permission("repos.view")
def repo_detail(repo_id):
    repo = Repo.query.get_or_404(repo_id)
    _check_repo_access(repo)
    return render_template("repo_detail.html", repo=repo)


@admin_bp.route("/repos/<int:repo_id>/edit", methods=["GET", "POST"])
@perm.requires_permission("repos.edit")
def repo_edit(repo_id):
    repo = Repo.query.get_or_404(repo_id)
    _check_repo_access(repo)
    if request.method == "POST":
        repo.name         = (request.form.get("name") or "").strip()
        repo.owner        = (request.form.get("owner") or "").strip()
        repo.display_name = (request.form.get("display_name") or "").strip() or None
        server_id_raw     = (request.form.get("server_id") or "").strip()
        repo.server_id    = int(server_id_raw) if server_id_raw.isdigit() else None
        repo.recipients   = _parse_list(request.form.get("recipients", ""))
        repo.is_active    = bool(request.form.get("is_active"))
        db.session.commit()
        flash("Repo updated.", "success")
        return redirect(url_for("admin.repo_detail", repo_id=repo.id))
    return render_template(
        "repo_form.html", repo=repo, mode="edit", form={},
        recipients_text=_list_to_text(repo.recipients or []),
        servers=Server.query.order_by(Server.name).all(),
    )


@admin_bp.route("/repos/<int:repo_id>/delete", methods=["POST"])
@admin_required
def repo_delete(repo_id):
    repo = Repo.query.get_or_404(repo_id)
    name = f"{repo.owner}/{repo.name}"
    repo_id_snapshot = repo.id
    db.session.delete(repo)
    db.session.commit()
    audit.log("repo.delete", "repo", repo_id_snapshot, name)
    flash(f"Deleted {name} (and its branches).", "info")
    return redirect(url_for("admin.dashboard"))


# ---------------------------------------------------------------------------
# Branches CRUD (gated by repo access)
# ---------------------------------------------------------------------------
@admin_bp.route("/repos/<int:repo_id>/branches/new", methods=["GET", "POST"])
@perm.requires_permission("branches.edit")
def branch_new(repo_id):
    repo = Repo.query.get_or_404(repo_id)
    _check_repo_access(repo)
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        path = (request.form.get("path") or "").strip()
        commands   = _parse_commands(request.form)
        recipients = _parse_list(request.form.get("recipients", "")) or None

        if not name or not path:
            flash("Branch name and path are required.", "danger")
            return render_template(
                "branch_form.html", repo=repo, branch=None, mode="new",
                form=request.form, commands_list=commands,
                recipients_text=request.form.get("recipients", ""),
            )
        if Branch.query.filter_by(repo_id=repo.id, name=name).first():
            flash(f"Branch '{name}' already configured for this repo.", "danger")
            return render_template(
                "branch_form.html", repo=repo, branch=None, mode="new",
                form=request.form, commands_list=commands,
                recipients_text=request.form.get("recipients", ""),
            )

        branch = Branch(
            repo_id=repo.id, name=name, path=path,
            commands=commands, recipients=recipients,
            auto_deploy=bool(request.form.get("auto_deploy", "1")),
            health_check_url=(request.form.get("health_check_url") or "").strip() or None,
            schedule_cron=(request.form.get("schedule_cron") or "").strip() or None,
            env_vars=_parse_env_vars(request.form) or None,
        )
        db.session.add(branch)
        db.session.commit()
        audit.log("branch.create", "branch", branch.id, f"{repo.name}/{name}")
        try:
            from scheduler import refresh_jobs
            refresh_jobs(current_app)
        except Exception:
            current_app.logger.exception("scheduler refresh failed")
        flash(f"Added branch '{name}'.", "success")
        return redirect(url_for("admin.repo_detail", repo_id=repo.id))

    return render_template(
        "branch_form.html", repo=repo, branch=None, mode="new",
        form={}, commands_list=[], recipients_text="", env_vars={},
    )


@admin_bp.route("/branches/<int:branch_id>/edit", methods=["GET", "POST"])
@perm.requires_permission("branches.edit")
def branch_edit(branch_id):
    branch = Branch.query.get_or_404(branch_id)
    _check_repo_access(branch.repo)
    if request.method == "POST":
        branch.name        = (request.form.get("name") or "").strip()
        branch.path        = (request.form.get("path") or "").strip()
        branch.commands         = _parse_commands(request.form)
        branch.recipients       = _parse_list(request.form.get("recipients", "")) or None
        branch.auto_deploy      = bool(request.form.get("auto_deploy"))
        branch.health_check_url = (request.form.get("health_check_url") or "").strip() or None
        branch.schedule_cron    = (request.form.get("schedule_cron") or "").strip() or None
        branch.env_vars         = _parse_env_vars(request.form) or None
        branch.is_active        = bool(request.form.get("is_active"))
        db.session.commit()
        audit.log("branch.edit", "branch", branch.id, f"{branch.repo.name}/{branch.name}")
        try:
            from scheduler import refresh_jobs
            refresh_jobs(current_app)
        except Exception:
            current_app.logger.exception("scheduler refresh failed")
        flash("Branch updated.", "success")
        return redirect(url_for("admin.repo_detail", repo_id=branch.repo_id))
    return render_template(
        "branch_form.html", repo=branch.repo, branch=branch, mode="edit",
        form={},
        commands_list=list(branch.commands or []),
        recipients_text=_list_to_text(branch.recipients or []),
        env_vars=dict(branch.env_vars or {}),
    )


@admin_bp.route("/branches/<int:branch_id>/delete", methods=["POST"])
@perm.requires_permission("branches.delete")
def branch_delete(branch_id):
    branch = Branch.query.get_or_404(branch_id)
    _check_repo_access(branch.repo)
    repo_id = branch.repo_id
    name = branch.name
    repo_name_snap = branch.repo.name
    branch_id_snap = branch.id
    db.session.delete(branch)
    db.session.commit()
    audit.log("branch.delete", "branch", branch_id_snap, f"{repo_name_snap}/{name}")
    try:
        from scheduler import refresh_jobs
        refresh_jobs(current_app)
    except Exception:
        current_app.logger.exception("scheduler refresh failed")
    flash(f"Deleted branch '{name}'.", "info")
    return redirect(url_for("admin.repo_detail", repo_id=repo_id))


# ---------------------------------------------------------------------------
# Deploy history (filtered by user's repos)
# ---------------------------------------------------------------------------
@admin_bp.route("/deploys")
@perm.requires_permission("deploys.view")
def deploys():
    page = max(1, int(request.args.get("page", 1) or 1))
    per_page = 25

    # Filter values from query string
    f_repo   = (request.args.get("repo") or "").strip()
    f_branch = (request.args.get("branch") or "").strip()
    f_status = (request.args.get("status") or "").strip()
    f_pusher = (request.args.get("pusher") or "").strip()
    f_commit = (request.args.get("commit") or "").strip()
    f_search = (request.args.get("q") or "").strip()

    # Base query scoped to repos the user can see
    base = Deploy.query
    if not current_user.is_admin:
        ids = _accessible_repo_ids()
        base = base.filter(Deploy.repo_id.in_(ids))

    # Repo + branch choices come from the config tables (Repo / Branch) so that
    # repos and branches without any deploys yet still appear in the dropdowns.
    accessible_repos_q = (Repo.query if current_user.is_admin
                          else Repo.query.filter(Repo.id.in_(_accessible_repo_ids())))
    accessible_repos = accessible_repos_q.order_by(Repo.name).all()
    repo_obj_by_name = {r.name: r for r in accessible_repos}
    repo_choices = [r.name for r in accessible_repos]

    if f_repo and f_repo in repo_obj_by_name:
        branch_choices = sorted(b.name for b in repo_obj_by_name[f_repo].branches)
    else:
        branch_choices = []
        f_branch = ""    # don't carry a branch filter when no repo is selected

    # repo -> [branches] map for client-side dropdown update (no page reload).
    repo_branches_map = {
        r.name: sorted(b.name for b in r.branches) for r in accessible_repos
    }

    pusher_choices = [r[0] for r in base.with_entities(Deploy.pusher)
                      .filter(Deploy.pusher.isnot(None))
                      .distinct().order_by(Deploy.pusher).all()]
    status_choices = ["success", "failed", "pending", "awaiting"]

    # Apply filters
    q = base
    if f_repo:   q = q.filter(Deploy.repo_name == f_repo)
    if f_branch: q = q.filter(Deploy.branch_name == f_branch)
    if f_status: q = q.filter(Deploy.status == f_status)
    if f_pusher: q = q.filter(Deploy.pusher == f_pusher)
    if f_commit: q = q.filter(Deploy.commit_sha.like(f"{f_commit}%"))
    if f_search:
        like = f"%{f_search}%"
        q = q.filter(db.or_(
            Deploy.log.like(like),
            Deploy.commit_msg.like(like),
            Deploy.error.like(like),
        ))
    q = q.order_by(desc(Deploy.started_at))

    total = q.count()
    items = q.limit(per_page).offset((page - 1) * per_page).all()
    pages = (total + per_page - 1) // per_page

    return render_template(
        "deploys.html",
        items=items, page=page, pages=pages, total=total, per_page=per_page,
        filters={"repo": f_repo, "branch": f_branch, "status": f_status,
                 "pusher": f_pusher, "commit": f_commit, "q": f_search},
        repo_choices=repo_choices, branch_choices=branch_choices,
        repo_branches_map=repo_branches_map,
        pusher_choices=pusher_choices, status_choices=status_choices,
    )


@admin_bp.route("/deploys/<int:deploy_id>")
@perm.requires_permission("deploys.view")
def deploy_detail(deploy_id):
    d = Deploy.query.get_or_404(deploy_id)
    if not current_user.is_admin and d.repo_id not in _accessible_repo_ids():
        abort(403)
    return render_template("deploy_detail.html", d=d)


@admin_bp.route("/deploys/<int:deploy_id>/live")
@perm.requires_permission("deploys.view")
def deploy_live(deploy_id):
    d = Deploy.query.get_or_404(deploy_id)
    if not current_user.is_admin and d.repo_id not in _accessible_repo_ids():
        abort(403)
    return render_template("deploy_live.html", d=d)


@admin_bp.route("/deploys/<int:deploy_id>/rollback", methods=["POST"])
@perm.requires_permission("deploys.rollback")
def deploy_rollback(deploy_id):
    d = Deploy.query.get_or_404(deploy_id)
    if not current_user.is_admin and d.repo_id not in _accessible_repo_ids():
        abort(403)
    if d.status != "success":
        flash("You can only roll back to a successful build.", "danger")
        return redirect(url_for("admin.deploy_detail", deploy_id=d.id))
    from deploy_webhook import trigger_rollback
    try:
        new_id = trigger_rollback(d, current_user.username)
    except Exception as e:
        flash(f"Couldn't start rollback: {e}", "danger")
        return redirect(url_for("admin.deploy_detail", deploy_id=d.id))
    audit.log("deploy.rollback", "deploy", d.id, f"#{d.build_number} {d.repo_name}/{d.branch_name}")
    return redirect(url_for("admin.deploy_live", deploy_id=new_id))


@admin_bp.route("/deploys/<int:deploy_id>/delete", methods=["POST"])
@perm.requires_permission("deploys.delete")
def deploy_delete(deploy_id):
    d = Deploy.query.get_or_404(deploy_id)
    if not current_user.is_admin and d.repo_id not in _accessible_repo_ids():
        abort(403)
    if d.status == "pending":
        flash("Can't delete a build that's still running.", "danger")
        return redirect(url_for("admin.deploy_detail", deploy_id=d.id))

    # Snapshot the keys we need for renumbering before deletion.
    repo_name   = d.repo_name
    branch_name = d.branch_name
    deleted_num = d.build_number

    # Best-effort delete of the per-deploy log file.
    log_path = DEPLOY_LOG_DIR / f"{d.id}.log"
    try:
        log_path.unlink()
    except FileNotFoundError:
        pass

    label = f"Build #{deleted_num} ({repo_name}/{branch_name})"
    deploy_id_snap = d.id
    db.session.delete(d)
    db.session.flush()
    audit.log("deploy.delete", "deploy", deploy_id_snap, label)

    # Renumber to fill the gap. The unique key (repo_name, branch_name, build_number)
    # forbids two rows sharing a number, so we NULL the affected rows first, flush,
    # then re-assign sequential numbers.
    if deleted_num is not None:
        followups = (Deploy.query
                     .filter(Deploy.repo_name == repo_name,
                             Deploy.branch_name == branch_name,
                             Deploy.build_number > deleted_num)
                     .order_by(Deploy.build_number).all())
        for f in followups:
            f.build_number = None
        db.session.flush()
        for offset, f in enumerate(followups):
            f.build_number = deleted_num + offset
    db.session.commit()

    if deleted_num is not None and followups:
        flash(f"Deleted {label}. Subsequent builds renumbered to fill the gap.", "info")
    else:
        flash(f"Deleted {label}.", "info")
    # Stay on the deploys list (which is where the per-row delete button lives).
    return redirect(url_for("admin.deploys"))


@admin_bp.route("/deploys/<int:deploy_id>/run", methods=["POST"])
@perm.requires_permission("deploys.run_awaiting")
def deploy_run(deploy_id):
    """Convert an awaiting deploy to pending and start running it."""
    d = Deploy.query.get_or_404(deploy_id)
    if not current_user.is_admin and d.repo_id not in _accessible_repo_ids():
        abort(403)
    if d.status != "awaiting":
        flash(f"Deploy is already {d.status}; nothing to do.", "info")
        return redirect(url_for("admin.deploy_detail", deploy_id=d.id))
    from deploy_webhook import run_awaiting_deploy
    try:
        run_awaiting_deploy(d, current_user.username)
    except Exception as e:
        flash(f"Failed to start: {e}", "danger")
        return redirect(url_for("admin.deploy_detail", deploy_id=d.id))
    return redirect(url_for("admin.deploy_live", deploy_id=d.id))


@admin_bp.route("/deploys/<int:deploy_id>/log")
@perm.requires_permission("deploys.view")
def deploy_log_poll(deploy_id):
    """Polling endpoint for the live view.

    Returns: { status, current_command, content, next_offset, finished_at, error }
    where `content` is the substring of the log file starting at the given offset.
    """
    d = Deploy.query.get_or_404(deploy_id)
    if not current_user.is_admin and d.repo_id not in _accessible_repo_ids():
        abort(403)

    offset = int(request.args.get("offset", "0"))
    log_path = DEPLOY_LOG_DIR / f"{deploy_id}.log"

    content = ""
    size = 0
    if log_path.exists():
        try:
            size = log_path.stat().st_size
            if offset > size:
                # file was truncated/replaced — restart from the beginning
                offset = 0
            with open(log_path, "rb") as f:
                f.seek(offset)
                raw = f.read()
            content = raw.decode("utf-8", errors="replace")
        except FileNotFoundError:
            pass
    elif d.log:
        # log file was cleaned up but the row keeps the snapshot
        if offset == 0:
            content = d.log
            size = len(d.log)

    return jsonify({
        "status":          d.status,
        "current_command": d.current_command,
        "content":         content,
        "next_offset":     size,
        "finished_at":     d.finished_at.isoformat() if d.finished_at else None,
        "error":           d.error,
        "commit_sha":      d.commit_sha,
        "old_sha":         d.old_sha,
    })


# ---------------------------------------------------------------------------
# Users CRUD (admin only)
# ---------------------------------------------------------------------------
@admin_bp.route("/users")
@admin_required
def users_list():
    users = User.query.order_by(User.username).all()
    return render_template("users_list.html", users=users)


@admin_bp.route("/users/new", methods=["GET", "POST"])
@admin_required
def user_new():
    all_repos = Repo.query.order_by(Repo.owner, Repo.name).all()
    all_roles = Role.query.order_by(Role.is_system.desc(), Role.name).all()
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email    = (request.form.get("email") or "").strip().lower() or None
        password = request.form.get("password") or ""
        is_admin = bool(request.form.get("is_admin"))
        is_active = bool(request.form.get("is_active", "1"))
        send_email_flag = bool(request.form.get("send_credentials"))
        repo_ids = [int(i) for i in request.form.getlist("repo_ids")]
        role_id  = request.form.get("role_id") or None
        role_id  = int(role_id) if role_id else None

        def _back(msg, cat="danger"):
            flash(msg, cat)
            return render_template("user_form.html", user=None, mode="new",
                                   all_repos=all_repos, all_roles=all_roles, form=request.form,
                                   selected_repo_ids=set(repo_ids))

        if not username:
            return _back("Username is required.")
        if User.query.filter_by(username=username).first():
            return _back(f"User '{username}' already exists.")
        if email and User.query.filter_by(email=email).first():
            return _back(f"Email '{email}' is already used by another user.")
        if password and len(password) < 8:
            return _back("Password must be at least 8 characters (or leave blank for first-login setup).")
        if send_email_flag and not email:
            return _back("Provide an email if you want to send login details.")

        u = User(username=username, email=email, is_admin=is_admin, is_active=is_active, role_id=role_id)
        if password:
            u.set_password(password)
        # If we're sending an email and no password was set, create a reset token
        token_for_email = None
        if send_email_flag and not password:
            token_for_email = secrets.token_urlsafe(32)
            u.reset_token = token_for_email
            u.reset_token_expires = datetime.utcnow() + timedelta(hours=24)
        if repo_ids:
            u.repos = Repo.query.filter(Repo.id.in_(repo_ids)).all()
        db.session.add(u)
        db.session.commit()

        audit.log("user.create", "user", u.id, u.username, details={"is_admin": is_admin})
        if send_email_flag:
            from deploy_webhook import send_credentials_email
            send_credentials_email(u, password if password else None, token_for_email)
            flash(f"Created user '{username}' and emailed login details to {email}.", "success")
        elif not password:
            flash(f"Created user '{username}'. They'll set their password on first login.", "success")
        else:
            flash(f"Created user '{username}'.", "success")
        return redirect(url_for("admin.users_list"))

    return render_template("user_form.html", user=None, mode="new",
                           all_repos=all_repos, all_roles=all_roles,
                           form={}, selected_repo_ids=set())


@admin_bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def user_edit(user_id):
    user = User.query.get_or_404(user_id)
    all_repos = Repo.query.order_by(Repo.owner, Repo.name).all()
    all_roles = Role.query.order_by(Role.is_system.desc(), Role.name).all()
    if request.method == "POST":
        user.username  = (request.form.get("username") or "").strip()
        role_id        = request.form.get("role_id") or None
        user.role_id   = int(role_id) if role_id else None
        new_email      = (request.form.get("email") or "").strip().lower() or None
        if new_email and new_email != user.email:
            clash = User.query.filter(User.email == new_email, User.id != user.id).first()
            if clash:
                flash(f"Email '{new_email}' is already used by another user.", "danger")
                return render_template("user_form.html", user=user, mode="edit",
                                       all_repos=all_repos, form={},
                                       selected_repo_ids={r.id for r in user.repos})
        user.email     = new_email
        user.is_active = bool(request.form.get("is_active"))
        # Prevent locking yourself out: don't allow an admin to demote themselves
        if user.id == current_user.id:
            user.is_admin = True
        else:
            user.is_admin = bool(request.form.get("is_admin"))
        repo_ids = [int(i) for i in request.form.getlist("repo_ids")]
        user.repos = Repo.query.filter(Repo.id.in_(repo_ids)).all() if repo_ids else []
        db.session.commit()
        flash(f"Updated user '{user.username}'.", "success")
        return redirect(url_for("admin.users_list"))
    return render_template("user_form.html", user=user, mode="edit",
                           all_repos=all_repos, all_roles=all_roles, form={},
                           selected_repo_ids={r.id for r in user.repos})


@admin_bp.route("/users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def user_reset_password(user_id):
    user = User.query.get_or_404(user_id)
    new_password = request.form.get("password") or ""
    if new_password and len(new_password) < 8:
        flash("Password must be at least 8 characters.", "danger")
    elif new_password:
        user.set_password(new_password)
        db.session.commit()
        flash(f"Password for '{user.username}' updated.", "success")
    else:
        # Empty: clear password, force first-login setup
        user.password_hash = None
        db.session.commit()
        flash(f"Password cleared for '{user.username}'. They'll set a new one on next login.", "info")
    return redirect(url_for("admin.user_edit", user_id=user.id))


# ---------------------------------------------------------------------------
# Roles CRUD (admin only)
# ---------------------------------------------------------------------------
@admin_bp.route("/roles")
@admin_required
def roles_list():
    roles = Role.query.order_by(Role.is_system.desc(), Role.name).all()
    return render_template("roles_list.html", roles=roles)


@admin_bp.route("/roles/new", methods=["GET", "POST"])
@admin_required
def role_new():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        desc = (request.form.get("description") or "").strip() or None
        keys = set(request.form.getlist("perms"))
        invalid = keys - set(perm.PERMISSION_KEYS)
        if not name:
            flash("Role name is required.", "danger")
            return _render_role_form(None, name=name, description=desc, selected_keys=keys)
        if Role.query.filter_by(name=name).first():
            flash(f"Role '{name}' already exists.", "danger")
            return _render_role_form(None, name=name, description=desc, selected_keys=keys)
        if invalid:
            flash(f"Unknown permission key(s): {', '.join(invalid)}", "danger")
            return _render_role_form(None, name=name, description=desc, selected_keys=keys)

        role = Role(name=name, description=desc, is_system=False)
        for k in keys:
            role.permissions.append(RolePermission(permission_key=k))
        db.session.add(role)
        db.session.commit()
        audit.log("role.create", "role", role.id, name, details={"perms": sorted(keys)})
        flash(f"Created role '{name}' with {len(keys)} permission(s).", "success")
        return redirect(url_for("admin.roles_list"))
    return _render_role_form(None)


@admin_bp.route("/roles/<int:role_id>/edit", methods=["GET", "POST"])
@admin_required
def role_edit(role_id):
    role = Role.query.get_or_404(role_id)
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        desc = (request.form.get("description") or "").strip() or None
        keys = set(request.form.getlist("perms"))
        invalid = keys - set(perm.PERMISSION_KEYS)
        if not name:
            flash("Role name is required.", "danger")
            return _render_role_form(role, name=name, description=desc, selected_keys=keys)
        clash = Role.query.filter(Role.name == name, Role.id != role.id).first()
        if clash:
            flash(f"Another role already has the name '{name}'.", "danger")
            return _render_role_form(role, name=name, description=desc, selected_keys=keys)
        if invalid:
            flash(f"Unknown permission key(s): {', '.join(invalid)}", "danger")
            return _render_role_form(role, name=name, description=desc, selected_keys=keys)

        role.name = name
        role.description = desc
        # Replace permissions
        role.permissions.clear()
        for k in keys:
            role.permissions.append(RolePermission(permission_key=k))
        db.session.commit()
        audit.log("role.edit", "role", role.id, name, details={"perms": sorted(keys)})
        flash(f"Updated role '{name}'.", "success")
        return redirect(url_for("admin.roles_list"))
    return _render_role_form(role)


@admin_bp.route("/roles/<int:role_id>/delete", methods=["POST"])
@admin_required
def role_delete(role_id):
    role = Role.query.get_or_404(role_id)
    if role.is_system:
        flash("Built-in roles can't be deleted.", "danger")
        return redirect(url_for("admin.roles_list"))
    name = role.name
    db.session.delete(role)
    db.session.commit()
    audit.log("role.delete", "role", role_id, name)
    flash(f"Deleted role '{name}'.", "info")
    return redirect(url_for("admin.roles_list"))


def _render_role_form(role, *, name=None, description=None, selected_keys=None):
    if role is not None and selected_keys is None:
        selected_keys = role.permission_keys
    return render_template(
        "role_form.html", role=role,
        name=name if name is not None else (role.name if role else ""),
        description=description if description is not None else (role.description if role else ""),
        selected_keys=selected_keys or set(),
        grouped=perm.grouped_permissions(),
        user_count=(len(role.users) if role else 0),
    )


# ---------------------------------------------------------------------------
# Manual test build — runs the same deploy flow as a webhook push
# ---------------------------------------------------------------------------
@admin_bp.route("/branches/<int:branch_id>/test-build", methods=["POST"])
@perm.requires_permission("deploys.test_build")
def branch_test_build(branch_id):
    branch = Branch.query.get_or_404(branch_id)
    _check_repo_access(branch.repo)
    silent = request.form.get("silent") == "1"
    # Imported here to avoid a circular import at module load time.
    from deploy_webhook import trigger_manual_deploy
    deploy_id = trigger_manual_deploy(branch, current_user.username, silent=silent)
    audit.log(
        "deploy.test_build" + (".silent" if silent else ""),
        "branch", branch.id, f"{branch.repo.name}/{branch.name}",
    )
    if deploy_id:
        return redirect(url_for("admin.deploy_live", deploy_id=deploy_id))
    flash(
        f"Test build queued for {branch.repo.name}/{branch.name}.", "info",
    )
    return redirect(url_for("admin.repo_detail", repo_id=branch.repo_id))


# ---------------------------------------------------------------------------
# SMTP settings (admin only) + test email
# ---------------------------------------------------------------------------
@admin_bp.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    s = AppSettings.get()
    if request.method == "POST":
        section = (request.form.get("section") or "").strip()

        if section == "smtp":
            s.smtp_host      = (request.form.get("smtp_host") or "").strip() or None
            s.smtp_port      = int(request.form.get("smtp_port") or 0) or None
            s.smtp_user      = (request.form.get("smtp_user") or "").strip() or None
            new_pw           = request.form.get("smtp_password") or ""
            if new_pw:
                s.smtp_password = new_pw
            s.smtp_use_tls   = bool(request.form.get("smtp_use_tls"))
            s.mail_from      = (request.form.get("mail_from") or "").strip() or None
            s.mail_from_name = (request.form.get("mail_from_name") or "").strip() or None
            s.slack_webhook_url = (request.form.get("slack_webhook_url") or "").strip() or None
            s.alerts_enabled = bool(request.form.get("alerts_enabled"))
            def _flt(v):
                try: return float(v) if v not in (None, "") else None
                except ValueError: return None
            s.cpu_threshold  = _flt(request.form.get("cpu_threshold"))
            s.mem_threshold  = _flt(request.form.get("mem_threshold"))
            s.disk_threshold = _flt(request.form.get("disk_threshold"))

        elif section == "webhook":
            if request.form.get("regenerate_webhook_secret"):
                s.webhook_secret = secrets.token_hex(32)
            elif "webhook_secret" in request.form:
                new_secret = (request.form.get("webhook_secret") or "").strip()
                s.webhook_secret = new_secret or None

        elif section == "company":
            s.company_name = (request.form.get("company_name") or "").strip() or None

            logo = request.files.get("company_logo")
            if logo and logo.filename:
                ext = logo.filename.rsplit(".", 1)[-1].lower() if "." in logo.filename else ""
                if ext not in ALLOWED_LOGO_EXT:
                    flash(f"Logo must be one of: {', '.join(sorted(ALLOWED_LOGO_EXT))}.", "danger")
                    return redirect(url_for("admin.settings", tab="company"))
                logo.seek(0, os.SEEK_END)
                size = logo.tell(); logo.seek(0)
                if size > MAX_LOGO_SIZE:
                    flash(f"Logo must be ≤ {MAX_LOGO_SIZE // 1024 // 1024} MB.", "danger")
                    return redirect(url_for("admin.settings", tab="company"))

                if s.company_logo_path:
                    old = UPLOAD_DIR / Path(s.company_logo_path).name
                    try: old.unlink()
                    except FileNotFoundError: pass

                fname = f"company_logo_{secrets.token_hex(4)}.{ext}"
                target = UPLOAD_DIR / secure_filename(fname)
                logo.save(target)
                s.company_logo_path = f"uploads/{target.name}"

            if request.form.get("remove_logo") and s.company_logo_path:
                old = UPLOAD_DIR / Path(s.company_logo_path).name
                try: old.unlink()
                except FileNotFoundError: pass
                s.company_logo_path = None

        else:
            flash("Unknown settings section.", "danger")
            return redirect(url_for("admin.settings"))

        s.updated_by = current_user.username
        db.session.commit()
        audit.log(f"settings.{section}", "settings", 1, section)
        flash(f"{section.title()} settings saved.", "success")
        return redirect(url_for("admin.settings", tab=section))

    # Effective values for display
    from deploy_webhook import base_url, WEBHOOK_SECRET as ENV_SECRET
    effective_secret = s.webhook_secret or ENV_SECRET or ""
    webhook_url = f"{base_url()}/webhook"
    secret_source = "Settings page" if s.webhook_secret else ("env (WEBHOOK_SECRET)" if ENV_SECRET else "(not set)")
    active_tab = request.args.get("tab", "company")
    if active_tab not in ("company", "smtp", "webhook"):
        active_tab = "company"
    return render_template(
        "settings.html", s=s,
        webhook_url=webhook_url,
        effective_secret=effective_secret,
        secret_source=secret_source,
        active_tab=active_tab,
    )


@admin_bp.route("/settings/test-email", methods=["POST"])
@admin_required
def settings_test_email():
    from deploy_webhook import send_test_email
    recipient = (request.form.get("recipient") or "").strip()
    if not recipient:
        flash("Enter a recipient address.", "danger")
    else:
        ok, msg = send_test_email(recipient, current_user.username)
        flash(msg, "success" if ok else "danger")
    return redirect(url_for("admin.settings"))


# ---------------------------------------------------------------------------
# Users CRUD (admin only)
# ---------------------------------------------------------------------------
@admin_bp.route("/preferences/theme", methods=["POST"])
@login_required
def preferences_theme():
    """Save the current user's theme preference (light/dark/auto)."""
    new = (request.form.get("theme") or request.get_json(silent=True, force=True) or {}).get("theme") if request.is_json else request.form.get("theme")
    if new not in ("light", "dark", "auto"):
        return jsonify(ok=False, error="invalid theme"), 400
    current_user.theme = new
    db.session.commit()
    return jsonify(ok=True, theme=new)


@admin_bp.route("/audit")
@perm.requires_permission("audit.view")
def audit_log_view():
    page = max(1, int(request.args.get("page", 1) or 1))
    per_page = 50
    f_action = (request.args.get("action") or "").strip()
    f_user   = (request.args.get("user") or "").strip()

    q = AuditLog.query
    if f_action: q = q.filter(AuditLog.action.like(f"%{f_action}%"))
    if f_user:   q = q.filter(AuditLog.username == f_user)
    q = q.order_by(desc(AuditLog.created_at))
    total = q.count()
    items = q.limit(per_page).offset((page - 1) * per_page).all()
    pages = (total + per_page - 1) // per_page

    action_choices = [a[0] for a in
        AuditLog.query.with_entities(AuditLog.action).distinct().order_by(AuditLog.action).all()]
    user_choices = [u[0] for u in
        AuditLog.query.with_entities(AuditLog.username).filter(AuditLog.username.isnot(None))
        .distinct().order_by(AuditLog.username).all()]
    return render_template("audit_log.html",
        items=items, page=page, pages=pages, total=total, per_page=per_page,
        filters={"action": f_action, "user": f_user},
        action_choices=action_choices, user_choices=user_choices,
    )


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def user_delete(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You can't delete yourself.", "danger")
        return redirect(url_for("admin.users_list"))
    name = user.username
    user_id_snap = user.id
    db.session.delete(user)
    db.session.commit()
    audit.log("user.delete", "user", user_id_snap, name)
    flash(f"Deleted user '{name}'.", "info")
    return redirect(url_for("admin.users_list"))
