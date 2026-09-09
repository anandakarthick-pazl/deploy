"""
Git mirrors — push a branch's code to a second remote (Azure DevOps, GitLab,
a client's GitHub, ...) while keeping selected files out of that remote.

How a push works
----------------
A mirror push is a **snapshot**, not a history mirror:

    1. read HEAD of the source working tree (branch.path)
    2. sync the tree into a cached clone of the target, minus the excludes
    3. commit whatever changed as ONE commit and push it

History is deliberately not carried over. Excluded files still exist in the
source repo's earlier commits, so pushing real history would hand the target
exactly the content the exclude list is meant to withhold.

The cached clone lives in MIRROR_WORK_DIR/<mirror id> and is reused between
pushes, so only changed files move after the first run.
"""

import os
import shlex
import shutil
import subprocess
import threading
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path

from flask import (Blueprint, abort, current_app, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required

import audit
from models import Branch, GitMirror, MirrorPush, db
from permissions import requires_permission

mirrors_bp = Blueprint("mirrors", __name__)

WORK_ROOT = Path(os.getenv("MIRROR_WORK_DIR", "/var/lib/packwork-deploy/mirrors"))
GIT_TIMEOUT = int(os.getenv("MIRROR_GIT_TIMEOUT", "1800"))   # 30 min for the first clone/push
DEFAULT_COMMIT_TEMPLATE = "Sync from {repo}/{branch} @ {short_sha}"

# Always excluded, whatever the user configures. Copying .git would overwrite
# the target's own repository metadata; the others are never wanted downstream.
HARD_EXCLUDES = [".git/", ".git", ".gitmodules"]

# Offered as a starting point in the config form.
SUGGESTED_EXCLUDES = [
    ".env",
    ".env.*",
    "node_modules/",
    "venv/",
    "__pycache__/",
    "*.log",
    "*.pem",
    "*.key",
    "ecosystem.config.js",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _check_branch_access(branch):
    """Abort 403 unless the user may touch this branch's repo."""
    if not branch or not branch.repo:
        abort(404)
    if not current_user.can_access_repo(branch.repo):
        abort(403)


def _parse_excludes(text: str) -> list:
    """One pattern per line; blank lines and # comments dropped."""
    if not text:
        return []
    out = []
    for line in text.replace("\r", "").split("\n"):
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _git_env(mirror: GitMirror) -> dict:
    """Environment for git so it never prompts and uses the right SSH key."""
    env = dict(os.environ)
    ssh = "ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes"
    if mirror.ssh_key_path:
        ssh += f" -i {shlex.quote(mirror.ssh_key_path)} -o IdentitiesOnly=yes"
    env["GIT_SSH_COMMAND"] = ssh
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _run(cmd, cwd=None, env=None, timeout=GIT_TIMEOUT):
    """Run a shell command, return (rc, combined output)."""
    try:
        r = subprocess.run(
            cmd, cwd=cwd, shell=True, capture_output=True, text=True,
            timeout=timeout, check=False, env=env,
        )
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, f"command timed out after {timeout}s: {cmd}"


def _scrub(text: str) -> str:
    """Strip anything credential-shaped out of git output before it is stored."""
    if not text:
        return ""
    import re
    text = re.sub(r"(https?://)[^/\s:@]+:[^/\s@]+@", r"\1***:***@", text)
    return text


def _count_excluded(source: Path, patterns: list) -> int:
    """How many *tracked* files the exclude list keeps out of the target.

    Uses `git ls-files` rather than walking the tree so untracked junk
    (node_modules, build output) doesn't inflate the number.
    """
    rc, out = _run("git ls-files", cwd=str(source), timeout=120)
    if rc != 0 or not out:
        return 0
    n = 0
    for rel in out.splitlines():
        if _matches_any(rel, patterns):
            n += 1
    return n


def _matches_any(rel_path: str, patterns: list) -> bool:
    """Approximate rsync's matching for the excluded-file count."""
    for p in patterns:
        p = p.rstrip("/")
        if not p:
            continue
        if fnmatch(rel_path, p) or fnmatch(os.path.basename(rel_path), p):
            return True
        # directory pattern: match anything beneath it
        if rel_path.startswith(p + "/") or f"/{p}/" in f"/{rel_path}":
            return True
    return False


def _rsync_cmd(source: Path, workdir: Path, patterns: list) -> str:
    excl = " ".join(
        f"--exclude={shlex.quote(p)}" for p in (HARD_EXCLUDES + list(patterns))
    )
    # Trailing slash on source: copy the *contents* of the tree.
    # Excluded paths are not deleted on the receiver, which is what protects
    # the target's own .git directory from --delete.
    return (
        f"rsync -a --delete --itemize-changes {excl} "
        f"{shlex.quote(str(source) + '/')} {shlex.quote(str(workdir) + '/')}"
    )


def _render_commit_msg(mirror: GitMirror, branch: Branch, sha: str, actor: str) -> str:
    tpl = (mirror.commit_template or "").strip() or DEFAULT_COMMIT_TEMPLATE
    fields = {
        "repo": branch.repo.name,
        "owner": branch.repo.owner,
        "branch": branch.name,
        "sha": sha or "",
        "short_sha": (sha or "")[:8],
        "user": actor or "system",
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mirror": mirror.name,
    }
    try:
        return tpl.format(**fields)[:500]
    except (KeyError, IndexError, ValueError):
        # A bad placeholder must never block a push.
        return DEFAULT_COMMIT_TEMPLATE.format(**fields)[:500]


# ---------------------------------------------------------------------------
# The push worker
# ---------------------------------------------------------------------------
def _do_push(app, mirror_id: int, push_id: int):
    """Runs in a background thread. Owns the MirrorPush row from start to end."""
    with app.app_context():
        push = MirrorPush.query.get(push_id)
        mirror = GitMirror.query.get(mirror_id)
        if not push or not mirror:
            return

        branch = Branch.query.get(mirror.branch_id)
        lines: list[str] = []

        def emit(msg: str):
            lines.append(msg)
            push.log = _scrub("\n".join(lines))[-500_000:]
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()

        def finish(status: str, error: str | None = None):
            push.status = status
            push.error = _scrub(error or "")[:5000] or None
            push.finished_at = datetime.utcnow()
            push.log = _scrub("\n".join(lines))[-500_000:]
            mirror.last_push_at = push.finished_at
            mirror.last_status = status
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()

        try:
            source = Path(branch.path)
            if not source.is_dir():
                return finish("failed", f"source path does not exist: {source}")
            if not (source / ".git").exists():
                return finish("failed", f"source path is not a git repo: {source}")

            env = _git_env(mirror)
            patterns = list(mirror.exclude_patterns or [])
            workdir = WORK_ROOT / str(mirror.id)
            target = mirror.target_branch or "main"

            emit(f"=== mirror push: {branch.repo.name}/{branch.name} -> {mirror.name}")
            emit(f"    remote : {mirror.remote_url}")
            emit(f"    branch : {target}")
            emit(f"    excludes: {len(patterns)} pattern(s)")
            emit("")

            # --- source revision ------------------------------------------
            rc, sha = _run("git rev-parse HEAD", cwd=str(source), timeout=60)
            if rc != 0:
                return finish("failed", f"git rev-parse failed in source: {sha}")
            push.source_sha = sha.strip()
            emit(f"[1/6] source HEAD {sha.strip()[:12]}")

            # --- prepare the cached clone of the target -------------------
            WORK_ROOT.mkdir(parents=True, exist_ok=True)
            if not (workdir / ".git").is_dir():
                if workdir.exists():
                    shutil.rmtree(workdir, ignore_errors=True)
                workdir.mkdir(parents=True, exist_ok=True)
                emit(f"[2/6] initialising workspace {workdir}")
                for cmd in ("git init -q",
                            f"git remote add origin {shlex.quote(mirror.remote_url)}"):
                    rc, out = _run(cmd, cwd=str(workdir), env=env)
                    if rc != 0:
                        return finish("failed", f"{cmd} failed: {out}")
            else:
                emit(f"[2/6] reusing workspace {workdir}")
                _run(f"git remote set-url origin {shlex.quote(mirror.remote_url)}",
                     cwd=str(workdir), env=env)

            # Fetch the target branch. A missing branch (or an empty repo) is
            # fine — we create it locally and push it into existence.
            emit(f"[3/6] fetching origin/{target}")
            rc, out = _run(f"git fetch --depth=1 origin {shlex.quote(target)}",
                           cwd=str(workdir), env=env)
            if rc == 0:
                _run(f"git checkout -q -B {shlex.quote(target)} FETCH_HEAD",
                     cwd=str(workdir), env=env)
                emit("      target branch fetched")
            else:
                low = (out or "").lower()
                if "could not read from remote" in low or "permission denied" in low \
                        or "authentication failed" in low or "repository not found" in low:
                    emit(_scrub(out))
                    return finish(
                        "failed",
                        "cannot reach the target remote — check the URL and that the "
                        "SSH key is registered with the provider. Details in the log.",
                    )
                _run(f"git checkout -q -B {shlex.quote(target)}", cwd=str(workdir), env=env)
                emit(f"      origin/{target} not found — it will be created by this push")

            # --- sync the tree --------------------------------------------
            emit(f"[4/6] syncing files (excluding {len(patterns) + len(HARD_EXCLUDES)} pattern(s))")
            rc, out = _run(_rsync_cmd(source, workdir, patterns), timeout=GIT_TIMEOUT)
            if rc != 0:
                emit(_scrub(out)[:20_000])
                return finish("failed", f"rsync failed (exit {rc})")
            changed_lines = [l for l in out.splitlines() if l and not l.startswith("sending")]
            emit(f"      {len(changed_lines)} path(s) written")
            push.files_excluded = _count_excluded(source, patterns)
            emit(f"      {push.files_excluded} tracked file(s) held back by the exclude list")

            # --- commit ----------------------------------------------------
            rc, _ = _run("git add -A", cwd=str(workdir), env=env)
            rc, staged = _run("git diff --cached --numstat", cwd=str(workdir), env=env)
            n_changed = len([l for l in staged.splitlines() if l.strip()])
            push.files_changed = n_changed

            if n_changed == 0:
                emit("[5/6] target already matches the source — nothing to push")
                return finish("no_changes")

            emit(f"[5/6] committing {n_changed} changed file(s)")
            msg = _render_commit_msg(mirror, branch, push.source_sha, push.triggered_by)
            author = "-c user.name='Packwork Deploy' -c user.email='deploy@pazl.info'"
            rc, out = _run(f"git {author} commit -q -m {shlex.quote(msg)}",
                           cwd=str(workdir), env=env)
            if rc != 0:
                emit(_scrub(out))
                return finish("failed", f"git commit failed: {out[:300]}")
            emit(f"      {msg}")

            # --- push ------------------------------------------------------
            force = " --force" if mirror.force_push else ""
            emit(f"[6/6] pushing to {mirror.short_host} ({target}){force}")
            rc, out = _run(
                f"git push{force} origin HEAD:{shlex.quote(target)}",
                cwd=str(workdir), env=env,
            )
            emit(_scrub(out)[:20_000])
            if rc != 0:
                hint = ""
                if "non-fast-forward" in out or "rejected" in out:
                    hint = (" The target has commits this snapshot doesn't contain. "
                            "Enable 'force push' if the mirror should always match the source.")
                return finish("failed", f"git push failed (exit {rc}).{hint}")

            rc, pushed = _run("git rev-parse HEAD", cwd=str(workdir), env=env, timeout=60)
            push.pushed_sha = pushed.strip() if rc == 0 else None
            emit("")
            emit(f"=== done — {n_changed} file(s) pushed to {target}")
            finish("success")

        except Exception as e:                     # noqa: BLE001 — worker must never die silently
            app.logger.exception("mirror push failed")
            lines.append(f"unexpected error: {e}")
            finish("failed", str(e))


def start_push(mirror: GitMirror, triggered_by: str, trigger_type: str = "manual") -> int:
    """Create the MirrorPush row and hand it to a worker thread. Returns its id."""
    branch = Branch.query.get(mirror.branch_id)
    push = MirrorPush(
        mirror_id=mirror.id,
        branch_id=mirror.branch_id,
        mirror_label=f"{branch.repo.name}/{branch.name} -> {mirror.name}",
        remote_url=mirror.remote_url,
        target_branch=mirror.target_branch,
        triggered_by=triggered_by,
        trigger_type=trigger_type,
        status="running",
    )
    db.session.add(push)
    db.session.commit()

    app = current_app._get_current_object()
    threading.Thread(target=_do_push, args=(app, mirror.id, push.id), daemon=True).start()
    return push.id


def push_for_deploy(branch_id: int, triggered_by: str) -> list:
    """Called after a successful deploy: fire every mirror with push_on_deploy."""
    out = []
    try:
        rows = GitMirror.query.filter_by(
            branch_id=branch_id, is_active=True, push_on_deploy=True,
        ).all()
        for m in rows:
            out.append(start_push(m, triggered_by, trigger_type="deploy"))
    except Exception:
        current_app.logger.exception("post-deploy mirror push failed")
    return out


# ---------------------------------------------------------------------------
# Routes — configure
# ---------------------------------------------------------------------------
@mirrors_bp.route("/branches/<int:branch_id>/mirrors/new", methods=["GET", "POST"])
@requires_permission("mirrors.manage")
def mirror_new(branch_id):
    branch = Branch.query.get_or_404(branch_id)
    _check_branch_access(branch)

    if request.method == "POST":
        name       = (request.form.get("name") or "").strip() or "mirror"
        remote_url = (request.form.get("remote_url") or "").strip()
        target     = (request.form.get("target_branch") or "").strip() or "main"
        excludes   = _parse_excludes(request.form.get("exclude_patterns", ""))

        if not remote_url:
            flash("Remote URL is required.", "danger")
            return render_template(
                "mirror_form.html", branch=branch, mirror=None, mode="new",
                form=request.form, excludes_text=request.form.get("exclude_patterns", ""),
                suggested=SUGGESTED_EXCLUDES, ssh_keys=_available_ssh_keys(),
            )
        if GitMirror.query.filter_by(branch_id=branch.id, name=name).first():
            flash(f"A mirror named '{name}' already exists on this branch.", "danger")
            return render_template(
                "mirror_form.html", branch=branch, mirror=None, mode="new",
                form=request.form, excludes_text=request.form.get("exclude_patterns", ""),
                suggested=SUGGESTED_EXCLUDES, ssh_keys=_available_ssh_keys(),
            )

        m = GitMirror(
            branch_id=branch.id, name=name, remote_url=remote_url,
            target_branch=target,
            ssh_key_path=(request.form.get("ssh_key_path") or "").strip() or None,
            exclude_patterns=excludes or None,
            commit_template=(request.form.get("commit_template") or "").strip() or None,
            push_on_deploy=bool(request.form.get("push_on_deploy")),
            force_push=bool(request.form.get("force_push")),
            is_active=True,
        )
        db.session.add(m)
        db.session.commit()
        audit.log("mirror.create", "mirror", m.id,
                  f"{branch.repo.name}/{branch.name} -> {name}",
                  details={"remote_url": remote_url, "target_branch": target,
                           "excludes": len(excludes)})
        flash(f"Mirror '{name}' configured. Use 'Test connection' before the first push.",
              "success")
        return redirect(url_for("admin.repo_detail", repo_id=branch.repo_id))

    return render_template(
        "mirror_form.html", branch=branch, mirror=None, mode="new",
        form={}, excludes_text="\n".join(SUGGESTED_EXCLUDES),
        suggested=SUGGESTED_EXCLUDES, ssh_keys=_available_ssh_keys(),
    )


@mirrors_bp.route("/mirrors/<int:mirror_id>/edit", methods=["GET", "POST"])
@requires_permission("mirrors.manage")
def mirror_edit(mirror_id):
    m = GitMirror.query.get_or_404(mirror_id)
    branch = Branch.query.get_or_404(m.branch_id)
    _check_branch_access(branch)

    if request.method == "POST":
        old_url = m.remote_url
        m.name            = (request.form.get("name") or "").strip() or m.name
        m.remote_url      = (request.form.get("remote_url") or "").strip() or m.remote_url
        m.target_branch   = (request.form.get("target_branch") or "").strip() or "main"
        m.ssh_key_path    = (request.form.get("ssh_key_path") or "").strip() or None
        m.exclude_patterns = _parse_excludes(request.form.get("exclude_patterns", "")) or None
        m.commit_template = (request.form.get("commit_template") or "").strip() or None
        m.push_on_deploy  = bool(request.form.get("push_on_deploy"))
        m.force_push      = bool(request.form.get("force_push"))
        m.is_active       = bool(request.form.get("is_active"))
        db.session.commit()

        # The cached clone points at the old remote — drop it so the next push
        # re-clones from the new URL instead of pushing to the wrong place.
        if old_url != m.remote_url:
            shutil.rmtree(WORK_ROOT / str(m.id), ignore_errors=True)

        audit.log("mirror.update", "mirror", m.id,
                  f"{branch.repo.name}/{branch.name} -> {m.name}")
        flash(f"Mirror '{m.name}' updated.", "success")
        return redirect(url_for("admin.repo_detail", repo_id=branch.repo_id))

    return render_template(
        "mirror_form.html", branch=branch, mirror=m, mode="edit",
        form={}, excludes_text="\n".join(m.exclude_patterns or []),
        suggested=SUGGESTED_EXCLUDES, ssh_keys=_available_ssh_keys(),
    )


@mirrors_bp.route("/mirrors/<int:mirror_id>/delete", methods=["POST"])
@requires_permission("mirrors.manage")
def mirror_delete(mirror_id):
    m = GitMirror.query.get_or_404(mirror_id)
    branch = Branch.query.get_or_404(m.branch_id)
    _check_branch_access(branch)
    label, repo_id = m.name, branch.repo_id

    shutil.rmtree(WORK_ROOT / str(m.id), ignore_errors=True)
    db.session.delete(m)
    db.session.commit()
    audit.log("mirror.delete", "mirror", mirror_id,
              f"{branch.repo.name}/{branch.name} -> {label}")
    flash(f"Mirror '{label}' removed. Nothing was deleted on the remote.", "info")
    return redirect(url_for("admin.repo_detail", repo_id=repo_id))


# ---------------------------------------------------------------------------
# Routes — push + history
# ---------------------------------------------------------------------------
@mirrors_bp.route("/mirrors/<int:mirror_id>/push", methods=["POST"])
@requires_permission("mirrors.push")
def mirror_push(mirror_id):
    m = GitMirror.query.get_or_404(mirror_id)
    branch = Branch.query.get_or_404(m.branch_id)
    _check_branch_access(branch)

    if not m.is_active:
        flash(f"Mirror '{m.name}' is disabled — enable it before pushing.", "warning")
        return redirect(url_for("admin.repo_detail", repo_id=branch.repo_id))

    running = MirrorPush.query.filter_by(mirror_id=m.id, status="running").first()
    if running:
        flash(f"A push to '{m.name}' is already running.", "warning")
        return redirect(url_for("mirrors.mirror_push_detail", push_id=running.id))

    push_id = start_push(m, current_user.username, trigger_type="manual")
    audit.log("mirror.push", "mirror", m.id,
              f"{branch.repo.name}/{branch.name} -> {m.name}")
    return redirect(url_for("mirrors.mirror_push_detail", push_id=push_id))


@mirrors_bp.route("/mirrors/pushes/<int:push_id>")
@requires_permission("mirrors.view")
def mirror_push_detail(push_id):
    p = MirrorPush.query.get_or_404(push_id)
    branch = Branch.query.get(p.branch_id) if p.branch_id else None
    if branch:
        _check_branch_access(branch)
    return render_template("mirror_push.html", push=p, branch=branch)


@mirrors_bp.route("/mirrors/pushes/<int:push_id>/log")
@requires_permission("mirrors.view")
def mirror_push_log(push_id):
    """Polled by the detail page while a push is running."""
    p = MirrorPush.query.get_or_404(push_id)
    if p.branch_id:
        branch = Branch.query.get(p.branch_id)
        if branch:
            _check_branch_access(branch)
    return jsonify(
        status=p.status,
        log=p.log or "",
        error=p.error,
        files_changed=p.files_changed,
        files_excluded=p.files_excluded,
        pushed_sha=p.pushed_sha,
        done=p.status != "running",
    )


@mirrors_bp.route("/mirrors/<int:mirror_id>/test", methods=["POST"])
@requires_permission("mirrors.manage")
def mirror_test(mirror_id):
    """Check the remote is reachable and the key works — no data is sent."""
    m = GitMirror.query.get_or_404(mirror_id)
    branch = Branch.query.get_or_404(m.branch_id)
    _check_branch_access(branch)

    rc, out = _run(
        f"git ls-remote --heads {shlex.quote(m.remote_url)}",
        env=_git_env(m), timeout=45,
    )
    if rc == 0:
        heads = [l.split("refs/heads/")[-1] for l in out.splitlines() if "refs/heads/" in l]
        if heads:
            found = "exists" if m.target_branch in heads else "will be created on first push"
            flash(f"Connected. {len(heads)} branch(es) on the remote; "
                  f"'{m.target_branch}' {found}.", "success")
        else:
            flash("Connected. The remote is empty — the first push will create "
                  f"'{m.target_branch}'.", "success")
    else:
        flash(f"Connection failed: {_scrub(out)[:400]}", "danger")
    return redirect(url_for("admin.repo_detail", repo_id=branch.repo_id))


@mirrors_bp.route("/mirrors")
@requires_permission("mirrors.view")
def mirror_history():
    """Recent pushes across every mirror the user can see."""
    q = MirrorPush.query.order_by(MirrorPush.id.desc())
    if not current_user.is_admin:
        allowed = [b.id for r in current_user.repos for b in r.branches]
        q = q.filter(MirrorPush.branch_id.in_(allowed or [0]))
    pushes = q.limit(100).all()
    return render_template("mirror_history.html", pushes=pushes)


SSH_KEY_DIR = Path(os.getenv("SSH_KEY_DIR", "/root/.ssh"))
_SSH_SKIP = {"known_hosts", "known_hosts.old", "authorized_keys", "config", "environment"}
# ssh tries these in order when no -i is given, so the first one present is
# what the "(default)" dropdown entry will actually use.
_DEFAULT_KEY_ORDER = ["id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"]


def _pub_for(private_path: Path) -> str:
    """The matching public key, read from <key>.pub or derived from the key."""
    pub_file = private_path.with_name(private_path.name + ".pub")
    if pub_file.is_file():
        try:
            return pub_file.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            pass
    # No .pub on disk — derive it. Fails silently for passphrase-protected keys.
    rc, out = _run(f"ssh-keygen -y -f {shlex.quote(str(private_path))}", timeout=15)
    return out.strip() if rc == 0 and out.startswith("ssh-") else ""


def _fingerprint_for(private_path: Path) -> str:
    pub_file = private_path.with_name(private_path.name + ".pub")
    target = pub_file if pub_file.is_file() else private_path
    rc, out = _run(f"ssh-keygen -lf {shlex.quote(str(target))}", timeout=15)
    return out.strip() if rc == 0 else ""


def _available_ssh_keys() -> list:
    """Keys under SSH_KEY_DIR with their public half, for the config form.

    Only public material is returned — the private key is never read into the
    app, let alone rendered. The public key is what has to be registered on the
    target provider, so it is shown with a copy button next to the dropdown.
    """
    out = []
    default_name = None
    try:
        names = {f.name for f in SSH_KEY_DIR.iterdir() if f.is_file()}
        for cand in _DEFAULT_KEY_ORDER:
            if cand in names:
                default_name = cand
                break

        for f in sorted(SSH_KEY_DIR.iterdir()):
            if not f.is_file() or f.name.endswith(".pub") or f.name in _SSH_SKIP:
                continue
            pub = _pub_for(f)
            out.append({
                "path": str(f),
                "name": f.name,
                "pub": pub,
                "fingerprint": _fingerprint_for(f),
                "is_default": f.name == default_name,
                "comment": pub.split(" ", 2)[2] if pub.count(" ") >= 2 else "",
            })
    except Exception:
        current_app.logger.exception("could not list ssh keys")
    return out


@mirrors_bp.route("/mirrors/ssh-keys")
@requires_permission("mirrors.manage")
def ssh_keys_json():
    """Public keys for the config form's copy box. Public material only."""
    return jsonify(keys=_available_ssh_keys())


@mirrors_bp.route("/mirrors/ssh-keys/generate", methods=["POST"])
@requires_permission("mirrors.manage")
def ssh_key_generate():
    """Create a dedicated key so one target can be revoked on its own.

    RSA-4096, not ed25519: Azure DevOps rejects anything that doesn't start
    with "ssh-rsa". RSA is accepted by GitHub and GitLab too, so it is the one
    type that works with every target we support.
    """
    label = (request.form.get("label") or "").strip() or "mirror"
    safe = "".join(c for c in label if c.isalnum() or c in "-_")[:40] or "mirror"
    path = SSH_KEY_DIR / f"mirror_{safe}"
    wants_json = request.form.get("json") == "1"
    back = request.form.get("next") or url_for("mirrors.mirror_history")

    def fail(msg, level="danger"):
        if wants_json:
            return jsonify(ok=False, error=msg), 400
        flash(msg, level)
        return redirect(back)

    if path.exists():
        return fail(f"A key named {path.name} already exists — pick another name.", "warning")

    SSH_KEY_DIR.mkdir(parents=True, exist_ok=True)
    rc, out = _run(
        f"ssh-keygen -t rsa -b 4096 -m PEM -N '' "
        f"-C {shlex.quote(f'packwork-deploy:{safe}')} -f {shlex.quote(str(path))}",
        timeout=120,
    )
    if rc != 0:
        return fail(f"Key generation failed: {_scrub(out)[:300]}")

    os.chmod(path, 0o600)
    audit.log("mirror.sshkey_generate", "sshkey", None, path.name)

    if wants_json:
        entry = next((k for k in _available_ssh_keys() if k["path"] == str(path)), None)
        return jsonify(ok=True, key=entry)

    flash(f"Created {path.name}. Select it below, copy the public key, and add it "
          "to the target repository before pushing.", "success")
    return redirect(back)
