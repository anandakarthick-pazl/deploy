"""
Packwork deploy webhook + admin dashboard.

Endpoints (public):
    POST /webhook        — GitHub push events; runs git pull + post-deploy commands + email
    GET  /health         — JSON health for monitoring

Endpoints (login required):
    GET  /               — dashboard
    GET  /login          — auth
    /admin/...           — repo + branch CRUD, deploy history

Configuration source for repos:
    Primary:  MySQL (packworx_deploy database, table `repos` + `branches`)
    Fallback: legacy repos.json next to this file (used only if DB is unreachable)
"""

import hashlib
import hmac
import json
import os
import secrets
import smtplib
import subprocess
import threading
import traceback
import urllib.request
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from flask import Flask, abort, jsonify, request
from flask_login import LoginManager
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from admin import admin_bp
from auth import auth_bp
from models import AppSettings, Branch, Deploy, Repo, User, db

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR        = Path(__file__).resolve().parent
LEGACY_JSON     = Path(os.getenv("REPOS_CONFIG", BASE_DIR / "repos.json"))
WEBHOOK_SECRET  = os.getenv("WEBHOOK_SECRET", "")
SECRET_KEY      = os.getenv("SECRET_KEY", secrets.token_hex(32))

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "packworx_deploy")

# SMTP
SMTP_HOST      = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT      = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER      = os.getenv("SMTP_USER", "")
SMTP_PASS      = os.getenv("SMTP_PASS", "")
MAIL_FROM      = os.getenv("MAIL_FROM", SMTP_USER)
MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME", "Packwork Deploy")
MAIL_TO        = os.getenv("MAIL_TO", "")    # global fallback when no recipients set

CMD_TIMEOUT     = int(os.getenv("CMD_TIMEOUT", "600"))
LOG_CHARS       = 16_000   # how much command output we keep on the Deploy row after finish
DEPLOY_LOG_DIR  = Path(os.getenv("DEPLOY_LOG_DIR", "/var/log/packwork-deploy/deploys"))
DEPLOY_LOG_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = SECRET_KEY
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True, "pool_recycle": 280}

    db.init_app(app)

    login_manager = LoginManager(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in."

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    from api import api_bp
    app.register_blueprint(api_bp)
    from server_monitor import monitor_bp
    app.register_blueprint(monitor_bp)
    from file_manager import fm_bp
    app.register_blueprint(fm_bp)
    from terminal import term_bp
    app.register_blueprint(term_bp)
    from servers import servers_bp
    app.register_blueprint(servers_bp)
    from mirrors import mirrors_bp
    app.register_blueprint(mirrors_bp)
    # Interactive PTY terminal (WebSocket). Attached via flask-sock.
    try:
        from terminal_pty import sock as pty_sock
        pty_sock.init_app(app)
    except Exception:
        app.logger.exception("failed to attach interactive terminal")

    @app.context_processor
    def inject_branding():
        """Make company name + logo available in every template."""
        name, logo = "Company", None
        try:
            s = AppSettings.query.get(1)
            if s:
                name = s.company_name or "Company"
                logo = s.company_logo_path
        except Exception:
            pass
        return {"branding": {"name": name, "logo": logo}}

    @app.context_processor
    def inject_permissions():
        """Expose has_perm(key) to every template so the sidebar can hide items."""
        from flask_login import current_user
        from permissions import has_permission as _hp
        return {"has_perm": lambda key: _hp(current_user, key)}

    @app.context_processor
    def inject_current_server():
        """Make current_server / all_servers available in every template."""
        from servers import current_server
        try:
            srv = current_server()
        except Exception:
            srv = None
        try:
            from models import Server
            all_srv = Server.query.order_by(Server.name).all()
        except Exception:
            all_srv = []
        return {"current_server": srv, "all_servers": all_srv}

    @app.route("/health", methods=["GET"])
    def health():
        try:
            repo_count = Repo.query.count()
            return jsonify(status="ok", repos=repo_count)
        except Exception as e:
            return jsonify(status="db_error", error=str(e)), 500

    @app.route("/webhook", methods=["POST"])
    def webhook():
        return _handle_webhook()

    # Cron scheduler — boots in only one gunicorn worker via an OS file lock.
    try:
        from scheduler import start_scheduler
        start_scheduler(app)
    except Exception:
        app.logger.exception("Scheduler bootstrap failed")

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _next_build_number(repo_name: str, branch_name: str) -> int:
    """Compute the next sequential build number scoped to (repo, branch)."""
    current = db.session.query(func.max(Deploy.build_number)).filter_by(
        repo_name=repo_name, branch_name=branch_name,
    ).scalar()
    return (current or 0) + 1


def _create_deploy(*, repo_id, branch_id, repo_name, branch_name, pusher,
                   commit_msg, commit_sha=None, status="pending"):
    """Insert a Deploy row with an auto-assigned build_number, retrying on race."""
    for _ in range(5):
        deploy = Deploy(
            repo_id=repo_id, branch_id=branch_id,
            repo_name=repo_name, branch_name=branch_name,
            build_number=_next_build_number(repo_name, branch_name),
            pusher=pusher, commit_msg=(commit_msg or "")[:500],
            commit_sha=commit_sha, status=status,
        )
        db.session.add(deploy)
        try:
            db.session.commit()
            return deploy
        except IntegrityError:
            # Another thread won the race on the same (repo, branch, n) — try again.
            db.session.rollback()
    raise RuntimeError("Could not allocate build_number after 5 attempts")


def _read_deploy_env_keys(path: str = "/etc/packwork-deploy.env") -> set[str]:
    """Names of env vars defined for the deploy webhook itself.

    These must be stripped before we hand the environment to user-supplied
    deploy commands — otherwise things like DB_NAME=packworx_deploy leak into
    every npm-run-migrate the user runs and Sequelize connects to the wrong
    database (the .env files in each service can't override an inherited var,
    because dotenv's default is override=false).
    """
    keys: set[str] = set()
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k = line.split("=", 1)[0].strip()
                if k.replace("_", "").isalnum():
                    keys.add(k)
    except Exception:
        pass
    # Don't strip PATH even if it appears in the env file — the user's command
    # needs PATH to find binaries.
    keys.discard("PATH")
    return keys


_DEPLOY_OWNED_ENV_KEYS = _read_deploy_env_keys()


def _shell_env(extra: dict | None = None):
    base = {k: v for k, v in os.environ.items() if k not in _DEPLOY_OWNED_ENV_KEYS}
    base["PATH"] = os.environ.get("PATH", "") + ":/usr/local/bin:/usr/bin:/bin"
    if extra:
        # Coerce all values to strings so subprocess doesn't choke on ints/None
        base.update({k: ("" if v is None else str(v)) for k, v in extra.items()})
    return base


def _run_cmd(cmd, cwd, timeout=CMD_TIMEOUT, extra_env=None):
    """Capture mode (used for cheap git ops): return (rc, combined_output)."""
    result = subprocess.run(
        cmd, cwd=cwd, shell=True, capture_output=True, text=True,
        timeout=timeout, check=False, env=_shell_env(extra_env),
    )
    return result.returncode, (result.stdout + result.stderr).strip()


# ---------------------------------------------------------------------------
# Local / remote command dispatch used by the deploy worker.
#
# A deploy targets either the local box (Repo.server_id is NULL) or a remote
# host stored in `servers`. Both runners present the same interface so the
# worker doesn't have to fork its logic.
# ---------------------------------------------------------------------------
import shlex as _shlex


class LocalRunner:
    label = "local"

    def is_dir(self, path):
        return Path(path).is_dir()

    def run_cmd(self, cmd, cwd, extra_env=None, timeout=CMD_TIMEOUT):
        return _run_cmd(cmd, cwd=cwd, timeout=timeout, extra_env=extra_env)

    def stream_cmd(self, cmd, cwd, log_path, max_capture=50_000,
                   timeout=CMD_TIMEOUT, extra_env=None):
        return _stream_cmd_to_file(cmd, cwd=cwd, log_path=log_path,
                                   max_capture=max_capture, timeout=timeout,
                                   extra_env=extra_env)


class RemoteRunner:
    """Runs every command over SSH against a single configured Server."""

    def __init__(self, server):
        from ssh import get_client
        self.server = server
        self.label = f"remote ({server.username}@{server.host}:{server.port})"
        self.client = get_client(server)

    def _wrap(self, cmd, cwd, extra_env=None):
        env_prefix = ""
        if extra_env:
            env_prefix = " ".join(
                f"export {k}={_shlex.quote(str(v))};" for k, v in extra_env.items()
            ) + " "
        return f"{env_prefix}cd {_shlex.quote(cwd)} && {cmd}"

    def is_dir(self, path):
        rc, _ = self.run_cmd(f"test -d {_shlex.quote(path)}", cwd="/")
        return rc == 0

    def run_cmd(self, cmd, cwd, extra_env=None, timeout=CMD_TIMEOUT):
        full = self._wrap(cmd, cwd, extra_env) + " 2>&1"
        stdin, stdout, stderr = self.client.exec_command(full, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        rc = stdout.channel.recv_exit_status()
        return rc, out.strip()

    def stream_cmd(self, cmd, cwd, log_path, max_capture=50_000,
                   timeout=CMD_TIMEOUT, extra_env=None):
        full = self._wrap(cmd, cwd, extra_env) + " 2>&1"
        captured = []
        captured_size = 0
        with open(log_path, "a", encoding="utf-8", buffering=1) as logf:
            logf.write(f"\n$ {cmd}\n")
            try:
                stdin, stdout, stderr = self.client.exec_command(full, timeout=timeout)
            except Exception as e:
                logf.write(f"(failed to start over SSH: {e})\n")
                return 127, str(e)
            try:
                for line in iter(stdout.readline, ""):
                    logf.write(line)
                    if captured_size < max_capture:
                        captured.append(line)
                        captured_size += len(line)
                rc = stdout.channel.recv_exit_status()
            except Exception as e:
                logf.write(f"(stream error: {e})\n")
                return 1, "".join(captured)
            logf.write(f"(exit {rc})\n")
            return rc, "".join(captured)


def _make_runner(server):
    """Pick the right runner for a deploy. `server` is the Server row or None."""
    if server is None:
        return LocalRunner()
    return RemoteRunner(server)


def _stream_cmd_to_file(cmd, cwd, log_path, max_capture=50_000, timeout=CMD_TIMEOUT, extra_env=None):
    """
    Run cmd, streaming combined stdout/stderr to log_path line-by-line.
    Also returns up to `max_capture` chars captured in memory (for the email body).
    Returns (rc, captured_output).
    """
    captured = []
    captured_size = 0
    with open(log_path, "a", encoding="utf-8", buffering=1) as logf:
        logf.write(f"\n$ {cmd}\n")
        try:
            proc = subprocess.Popen(
                cmd, cwd=cwd, shell=True, env=_shell_env(extra_env),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except Exception as e:
            logf.write(f"(failed to start: {e})\n")
            return 127, str(e)

        try:
            for line in proc.stdout:
                logf.write(line)
                if captured_size < max_capture:
                    captured.append(line)
                    captured_size += len(line)
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            logf.write(f"(killed after {timeout}s timeout)\n")
            return 124, "".join(captured)
        except Exception as e:
            logf.write(f"(stream error: {e})\n")

        logf.write(f"(exit {proc.returncode})\n")
        return proc.returncode, "".join(captured)


def _effective_webhook_secret() -> str:
    """DB-backed secret overrides the env var. Empty means 'unsigned mode'."""
    try:
        s = AppSettings.query.get(1)
        if s and s.webhook_secret:
            return s.webhook_secret
    except Exception:
        pass
    return WEBHOOK_SECRET


def _verify_signature(payload, signature):
    secret = _effective_webhook_secret()
    if not secret:
        return True
    if not signature or not signature.startswith("sha256="):
        return False
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={digest}", signature)


def _git_pull_and_diff(repo_path, branch):
    code, old_sha = _run_cmd("git rev-parse HEAD", cwd=repo_path)
    if code != 0:
        raise RuntimeError(f"git rev-parse failed: {old_sha}")
    code, out = _run_cmd(f"git fetch origin {branch}", cwd=repo_path)
    if code != 0:
        raise RuntimeError(f"git fetch failed: {out}")
    code, out = _run_cmd(f"git reset --hard origin/{branch}", cwd=repo_path)
    if code != 0:
        raise RuntimeError(f"git reset failed: {out}")
    code, new_sha = _run_cmd("git rev-parse HEAD", cwd=repo_path)

    grouped = {"Added": [], "Modified": [], "Deleted": [], "Renamed": [], "Other": []}
    if old_sha != new_sha:
        _, raw = _run_cmd(f"git diff --name-status {old_sha} {new_sha}", cwd=repo_path)
        for line in raw.splitlines():
            parts = line.split("\t")
            status, files = parts[0], parts[1:]
            if status.startswith("A"):     grouped["Added"].extend(files)
            elif status.startswith("M"):   grouped["Modified"].extend(files)
            elif status.startswith("D"):   grouped["Deleted"].extend(files)
            elif status.startswith("R"):   grouped["Renamed"].append(" -> ".join(files))
            else:                          grouped["Other"].append(" ".join(parts))
    return old_sha, new_sha, grouped


def _run_post_deploy(commands, cwd):
    results = []
    for cmd in commands:
        rc, out = _run_cmd(cmd, cwd=cwd)
        results.append((cmd, rc, out))
        if rc != 0:
            break
    return results


def _resolve_recipients(branch_cfg, repo_cfg):
    for src in (branch_cfg.get("recipients"), repo_cfg.get("recipients")):
        if src:
            if isinstance(src, str):
                src = [r.strip() for r in src.split(",")]
            return [r for r in src if r]
    if MAIL_TO:
        return [r.strip() for r in MAIL_TO.split(",") if r.strip()]
    return []


# ---------------------------------------------------------------------------
# Email rendering
# ---------------------------------------------------------------------------
def _build_email_html(ctx):
    def section(title, items, color):
        if not items:
            return ""
        rows = "".join(f"<li style='margin:2px 0;'>{f}</li>" for f in items)
        return (
            f"<h3 style='color:{color};margin:14px 0 6px;'>{title} ({len(items)})</h3>"
            f"<ul style='margin:0;padding-left:20px;font-family:Consolas,monospace;font-size:13px;'>{rows}</ul>"
        )

    changes = ctx["changes"]
    files_html = "".join([
        section("Added",    changes.get("Added", []),    "#2e7d32"),
        section("Modified", changes.get("Modified", []), "#1565c0"),
        section("Deleted",  changes.get("Deleted", []),  "#c62828"),
        section("Renamed",  changes.get("Renamed", []),  "#6a1b9a"),
        section("Other",    changes.get("Other", []),    "#555555"),
    ]) or "<p><em>No file changes detected.</em></p>"

    cmd_html = ""
    if ctx["cmd_results"]:
        rows = []
        for cmd, rc, out in ctx["cmd_results"]:
            colour = "#2e7d32" if rc == 0 else "#c62828"
            short  = (out[:1500] + "\n... (truncated)") if len(out) > 1500 else out
            rows.append(
                f"<div style='margin:8px 0;'>"
                f"<div style='font-family:Consolas,monospace;font-size:13px;color:{colour};'>"
                f"<b>$ {cmd}</b> &nbsp;<span>(exit {rc})</span></div>"
                f"<pre style='background:#f5f5f5;border:1px solid #e0e0e0;border-radius:4px;"
                f"padding:8px;font-size:12px;white-space:pre-wrap;margin:4px 0 0;'>{short or '(no output)'}</pre>"
                f"</div>"
            )
        cmd_html = "<h3 style='margin:18px 0 6px;'>Post-deploy commands</h3>" + "".join(rows)

    banner = "Deployment Successful" if ctx["success"] else "Deployment FAILED"
    banner_color = "#0d6efd" if ctx["success"] else "#c62828"
    build_label = f"Build #{ctx['build_number']}" if ctx.get("build_number") else ""
    return f"""
    <html><body style="font-family:Arial,sans-serif;color:#222;">
      <div style="max-width:780px;margin:auto;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden;">
        <div style="background:{banner_color};color:white;padding:16px 20px;">
          <h2 style="margin:0;">{banner}</h2>
          <div style="opacity:.9;font-size:14px;">{ctx['repo']} &middot; {ctx['branch']} &middot; {build_label}</div>
        </div>
        <div style="padding:18px 20px;">
          <table style="font-size:14px;border-collapse:collapse;">
            <tr><td style="padding:2px 8px 2px 0;"><b>Build:</b></td><td><b style="font-size:16px;">#{ctx.get('build_number') or '—'}</b></td></tr>
            <tr><td style="padding:2px 8px 2px 0;"><b>Repository:</b></td><td>{ctx['owner']}/{ctx['repo']}</td></tr>
            <tr><td style="padding:2px 8px 2px 0;"><b>Branch:</b></td><td>{ctx['branch']}</td></tr>
            <tr><td style="padding:2px 8px 2px 0;"><b>Deploy path:</b></td><td><code>{ctx['path']}</code></td></tr>
            <tr><td style="padding:2px 8px 2px 0;"><b>Pushed by:</b></td><td>{ctx['pusher']}</td></tr>
            <tr><td style="padding:2px 8px 2px 0;"><b>Old commit:</b></td><td><code>{ctx['old_sha'][:10]}</code></td></tr>
            <tr><td style="padding:2px 8px 2px 0;"><b>New commit:</b></td><td><code>{ctx['new_sha'][:10]}</code></td></tr>
            <tr><td style="padding:2px 8px 2px 0;"><b>Message:</b></td><td>{ctx['commit_msg']}</td></tr>
            <tr><td style="padding:2px 8px 2px 0;"><b>Deployed at:</b></td><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
          </table>
          <hr style="margin:16px 0;border:none;border-top:1px solid #eee;">
          <h3 style="margin:0 0 6px;">File Changes</h3>
          {files_html}
          {cmd_html}
        </div>
        <div style="background:#fafafa;color:#777;font-size:12px;padding:10px 20px;">
          Automated message from {_company_name()} deploy webhook.
        </div>
      </div>
    </body></html>
    """


def _load_smtp_config():
    """Return effective SMTP config: DB values override env defaults."""
    cfg = {
        "host":     SMTP_HOST,
        "port":     SMTP_PORT,
        "user":     SMTP_USER,
        "password": SMTP_PASS,
        "use_tls":  True,
        "from":     MAIL_FROM,
        "from_name": MAIL_FROM_NAME,
    }
    try:
        s = AppSettings.query.get(1)
        if s:
            if s.smtp_host:      cfg["host"]      = s.smtp_host
            if s.smtp_port:      cfg["port"]      = s.smtp_port
            if s.smtp_user:      cfg["user"]      = s.smtp_user
            if s.smtp_password:  cfg["password"]  = s.smtp_password
            cfg["use_tls"] = bool(s.smtp_use_tls) if s.smtp_use_tls is not None else True
            if s.mail_from:      cfg["from"]      = s.mail_from
            if s.mail_from_name: cfg["from_name"] = s.mail_from_name
    except Exception:
        # DB unreachable — fall through to env-only config
        pass
    return cfg


def _send_email(subject, html, recipients, cfg=None):
    cfg = cfg or _load_smtp_config()
    if not (cfg["user"] and cfg["password"]):
        return
    if not recipients:
        return

    sender_addr = cfg["from"] or cfg["user"]
    from_header = f"{cfg['from_name']} <{sender_addr}>" if cfg.get("from_name") else sender_addr
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_header
    msg["To"]      = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(cfg["host"], cfg["port"], timeout=30) as s:
        if cfg.get("use_tls", True):
            s.starttls()
        s.login(cfg["user"], cfg["password"])
        s.sendmail(sender_addr, recipients, msg.as_string())


def base_url() -> str:
    return os.getenv("BASE_URL", "https://deploy.pazl.info").rstrip("/")


def _company_name() -> str:
    try:
        s = AppSettings.query.get(1)
        if s and s.company_name:
            return s.company_name
    except Exception:
        pass
    return "Company"


def send_credentials_email(user, plain_password: str | None, reset_token: str | None) -> None:
    """Email a new user their login details (or a 'set your password' link)."""
    if not user.email:
        return
    company = _company_name()
    login_url = f"{base_url()}/login"

    if plain_password:
        body_block = f"""
          <p>Your account has been created. You can sign in with:</p>
          <table style="font-size:14px;">
            <tr><td><b>Username:</b></td><td><code>{user.username}</code></td></tr>
            <tr><td><b>Password:</b></td><td><code>{plain_password}</code></td></tr>
          </table>
          <p>For security, please change your password after signing in.</p>
          <p><a href="{login_url}" style="background:#0d6efd;color:white;padding:8px 14px;border-radius:5px;text-decoration:none;">Sign in</a></p>
        """
    elif reset_token:
        setup_url = f"{base_url()}/reset-password/{reset_token}"
        body_block = f"""
          <p>Your account has been created. Click below to set your password (link expires in 24 hours):</p>
          <p><a href="{setup_url}" style="background:#0d6efd;color:white;padding:8px 14px;border-radius:5px;text-decoration:none;">Set my password</a></p>
          <p style="font-size:12px;color:#666;">Or paste this URL into your browser: <br>{setup_url}</p>
        """
    else:
        return  # nothing actionable to send

    html = f"""
    <html><body style="font-family:Arial,sans-serif;color:#222;">
      <div style="max-width:680px;margin:auto;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden;">
        <div style="background:#0d6efd;color:white;padding:16px 20px;">
          <h2 style="margin:0;">Welcome to {company}</h2>
        </div>
        <div style="padding:18px 20px;">
          <p>Hi {user.username},</p>
          {body_block}
        </div>
      </div>
    </body></html>"""
    try:
        _send_email(f"{company} — your account is ready", html, [user.email])
    except Exception:
        app.logger.exception("send_credentials_email failed for %s", user.username)


def send_reset_email(user, reset_token: str) -> None:
    """Send a password reset link to a user's email."""
    if not user.email:
        return
    company = _company_name()
    reset_url = f"{base_url()}/reset-password/{reset_token}"
    html = f"""
    <html><body style="font-family:Arial,sans-serif;color:#222;">
      <div style="max-width:680px;margin:auto;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden;">
        <div style="background:#0d6efd;color:white;padding:16px 20px;">
          <h2 style="margin:0;">{company} — Password reset</h2>
        </div>
        <div style="padding:18px 20px;">
          <p>Hi {user.username},</p>
          <p>You (or someone using your email) requested a password reset. Click below to choose a new password (link expires in 24 hours):</p>
          <p><a href="{reset_url}" style="background:#0d6efd;color:white;padding:8px 14px;border-radius:5px;text-decoration:none;">Reset my password</a></p>
          <p style="font-size:12px;color:#666;">If you didn't request this, you can safely ignore this email — your password will not change.</p>
          <p style="font-size:12px;color:#666;">Or paste this URL into your browser: <br>{reset_url}</p>
        </div>
      </div>
    </body></html>"""
    try:
        _send_email(f"{company} — reset your password", html, [user.email])
    except Exception:
        app.logger.exception("send_reset_email failed for %s", user.username)


def _post_slack_raw(title: str, color: str, fields: list[dict]) -> bool:
    """Post a generic Slack attachment. Used by the metrics sampler."""
    url = _slack_webhook_url()
    if not url:
        return False
    payload = {
        "attachments": [{
            "color": color,
            "title": title,
            "fields": fields,
            "footer": _company_name() + " · server monitor",
            "ts": int(datetime.utcnow().timestamp()),
        }]
    }
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=10).read()
        return True
    except Exception:
        app.logger.exception("Slack post failed")
        return False


def _slack_webhook_url() -> str | None:
    try:
        s = AppSettings.query.get(1)
        if s and s.slack_webhook_url:
            return s.slack_webhook_url
    except Exception:
        pass
    return None


def _post_slack(ctx, deploy) -> None:
    url = _slack_webhook_url()
    if not url:
        return
    success      = ctx.get("success")
    status_emoji = "✅" if success else "❌"
    color        = "#10b981" if success else "#ef4444"
    title        = f"{status_emoji}  {ctx['repo']} / {ctx['branch']}  ·  Build #{ctx.get('build_number')}"
    new_sha      = (ctx.get("new_sha") or "")[:7]
    commit_msg   = (ctx.get("commit_msg") or "").splitlines()[0][:140] if ctx.get("commit_msg") else "—"
    pusher       = ctx.get("pusher") or "—"
    deploy_link  = f"{base_url()}/deploys/{deploy.id}"

    fields = []
    if new_sha:                  fields.append({"title": "Commit",  "value": f"`{new_sha}` {commit_msg}", "short": False})
    fields.append({"title": "Pushed by", "value": pusher, "short": True})
    fields.append({"title": "Status",    "value": "Success" if success else "Failed", "short": True})

    failed = next((c for c in ctx.get("cmd_results", []) if c[1] != 0), None)
    if failed:
        fields.append({"title": "Failing step", "value": f"`{failed[0]}` (exit {failed[1]})", "short": False})

    payload = {
        "attachments": [{
            "color": color,
            "title": title,
            "title_link": deploy_link,
            "fields": fields,
            "footer": _company_name() + " · deploy",
            "ts": int(datetime.utcnow().timestamp()),
        }]
    }
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10).read()
    except Exception:
        app.logger.exception("Slack post failed")


def _run_health_check(url: str, log_path: Path, timeout: int = 15) -> tuple[bool, int]:
    """Return (ok, status_code). ok = 2xx response within timeout."""
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"\n=== Health check ===\nGET {url}\n")
        req = urllib.request.Request(url, headers={"User-Agent": "PackworkDeploy-HealthCheck/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body_preview = resp.read(800).decode("utf-8", errors="replace")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"HTTP {status}\n{body_preview}\n")
        return (200 <= status < 300, status)
    except Exception as e:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"health check FAILED: {e}\n")
        return (False, 0)


def send_test_email(recipient: str, sender_username: str) -> tuple[bool, str]:
    """Used by the settings page. Returns (ok, message)."""
    cfg = _load_smtp_config()
    if not cfg["user"] or not cfg["password"]:
        return False, "SMTP not configured — set host/user/password in the Settings page first."
    brand = cfg.get("from_name") or _company_name() or "Deploy"
    html = f"""
    <html><body style="font-family:Arial,sans-serif;color:#222;">
      <h3 style="color:#0d6efd;">{brand} — test email</h3>
      <p>This is a test message sent from the deploy dashboard.</p>
      <table>
        <tr><td><b>Sent by:</b></td><td>{sender_username}</td></tr>
        <tr><td><b>SMTP host:</b></td><td>{cfg['host']}:{cfg['port']}</td></tr>
        <tr><td><b>From:</b></td><td>{cfg.get('from_name') or ''} &lt;{cfg['from'] or cfg['user']}&gt;</td></tr>
        <tr><td><b>Time:</b></td><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
      </table>
      <p style="color:#6c757d;font-size:12px;margin-top:18px;">If you received this, your SMTP settings work.</p>
    </body></html>
    """
    try:
        _send_email(f"{brand} — Test Email", html, [recipient], cfg=cfg)
        return True, f"Test email sent to {recipient}."
    except Exception as e:
        return False, f"Send failed: {e}"


def run_awaiting_deploy(deploy, triggered_by: str) -> int:
    """Convert an `awaiting` deploy row to `pending` and run it. Returns deploy id."""
    branch = Branch.query.get(deploy.branch_id) if deploy.branch_id else None
    if not branch:
        raise RuntimeError(f"deploy #{deploy.id} has no live branch — cannot run")
    repo = branch.repo
    repo_cfg   = {"owner": repo.owner, "recipients": repo.recipients or []}
    branch_cfg = {
        "path": branch.path,
        "commands": branch.commands or [],
        "recipients": branch.recipients or None,
        "health_check_url": branch.health_check_url,
        "env_vars": branch.env_vars or {},
    }
    deploy.status = "pending"
    deploy.pusher = f"{triggered_by} (approved push by {deploy.pusher or '?'})"
    db.session.commit()
    threading.Thread(
        target=_run_deploy,
        args=(app, repo.name, repo.owner, branch.name, branch_cfg, repo_cfg,
              deploy.pusher, deploy.commit_msg or "(awaiting push)", repo.id, branch.id),
        kwargs={"existing_deploy_id": deploy.id},
        daemon=True,
    ).start()
    return deploy.id


def trigger_rollback(source_deploy: "Deploy", triggered_by: str) -> int:
    """Create a new Deploy that resets the working tree to source_deploy's commit."""
    branch = Branch.query.get(source_deploy.branch_id) if source_deploy.branch_id else None
    if not branch:
        raise RuntimeError("Branch was deleted — cannot rollback")
    if not source_deploy.commit_sha:
        raise RuntimeError("Source build has no commit SHA recorded")

    repo = branch.repo
    repo_cfg   = {"owner": repo.owner, "recipients": repo.recipients or []}
    branch_cfg = {
        "path": branch.path,
        "commands": branch.commands or [],
        "recipients": branch.recipients or None,
        "health_check_url": branch.health_check_url,
        "env_vars": branch.env_vars or {},
    }
    short_sha = source_deploy.commit_sha[:7]
    commit_msg = f"Rollback to build #{source_deploy.build_number} ({short_sha}) by {triggered_by}"

    deploy = _create_deploy(
        repo_id=repo.id, branch_id=branch.id,
        repo_name=repo.name, branch_name=branch.name,
        pusher=triggered_by, commit_msg=commit_msg, status="pending",
    )
    deploy.target_sha = source_deploy.commit_sha
    db.session.commit()
    deploy_id = deploy.id

    threading.Thread(
        target=_run_deploy,
        args=(app, repo.name, repo.owner, branch.name, branch_cfg, repo_cfg,
              triggered_by, commit_msg, repo.id, branch.id),
        kwargs={"existing_deploy_id": deploy_id},
        daemon=True,
    ).start()
    return deploy_id


def trigger_manual_deploy(branch: "Branch", triggered_by: str, silent: bool = False) -> int:
    """Run the same deploy flow as a webhook push, but from a UI button.

    Creates the Deploy row in the caller's transaction so we can return its id
    immediately and redirect the user to the live view.

    `silent=True` suppresses the success/failure email and Slack post — used
    for ad-hoc test runs that shouldn't spam the configured recipients.
    """
    repo = branch.repo
    repo_cfg   = {"owner": repo.owner, "recipients": repo.recipients or []}
    branch_cfg = {
        "path": branch.path,
        "commands": branch.commands or [],
        "recipients": branch.recipients or None,
        "health_check_url": branch.health_check_url,
        "env_vars": branch.env_vars or {},
    }
    commit_msg = f"Manual test build triggered by {triggered_by}"
    if silent:
        commit_msg += " (silent)"

    deploy = _create_deploy(
        repo_id=repo.id, branch_id=branch.id,
        repo_name=repo.name, branch_name=branch.name,
        pusher=triggered_by, commit_msg=commit_msg,
        status="pending",
    )
    deploy.silent = silent
    db.session.commit()
    deploy_id = deploy.id

    threading.Thread(
        target=_run_deploy,
        args=(app, repo.name, repo.owner, branch.name, branch_cfg, repo_cfg,
              triggered_by, commit_msg, repo.id, branch.id),
        kwargs={"existing_deploy_id": deploy_id},
        daemon=True,
    ).start()
    return deploy_id


# ---------------------------------------------------------------------------
# Config resolution: DB first, fall back to repos.json
# ---------------------------------------------------------------------------
def _lookup_repo_branch(repo_name, branch_name):
    """Return (repo_cfg, branch_cfg, repo_id, branch_id) or (None, None, None, None)."""
    # 1) DB
    try:
        repo = Repo.query.filter_by(name=repo_name, is_active=True).first()
        if repo:
            for br in repo.branches:
                if br.name == branch_name and br.is_active:
                    repo_cfg = {
                        "owner": repo.owner,
                        "recipients": repo.recipients or [],
                    }
                    branch_cfg = {
                        "path": br.path,
                        "commands": br.commands or [],
                        "recipients": br.recipients or None,
                        "auto_deploy": br.auto_deploy,
                        "health_check_url": br.health_check_url,
                        "env_vars": br.env_vars or {},
                    }
                    return repo_cfg, branch_cfg, repo.id, br.id
    except Exception:
        # DB unreachable — fall through to JSON
        pass

    # 2) repos.json fallback
    if LEGACY_JSON.exists():
        try:
            data = json.loads(LEGACY_JSON.read_text())
            repos = data.get("repos", {})
            rcfg = repos.get(repo_name)
            if rcfg and branch_name in rcfg.get("branches", {}):
                return rcfg, rcfg["branches"][branch_name], None, None
        except Exception:
            pass
    return None, None, None, None


# ---------------------------------------------------------------------------
# Deploy worker (background thread)
# ---------------------------------------------------------------------------
def _run_deploy(app, repo_name, owner, branch_name, branch_cfg, repo_cfg,
                pusher, commit_msg, repo_id, branch_id, existing_deploy_id=None):
    path             = branch_cfg["path"]
    commands         = branch_cfg.get("commands") or []
    recipients       = _resolve_recipients(branch_cfg, repo_cfg)
    health_check_url = branch_cfg.get("health_check_url")
    extra_env        = branch_cfg.get("env_vars") or {}

    ctx = {
        "repo": repo_name, "owner": owner, "branch": branch_name, "path": path,
        "pusher": pusher, "commit_msg": commit_msg,
        "old_sha": "", "new_sha": "",
        "changes": {}, "cmd_results": [], "success": False,
        "build_number": None,
    }

    with app.app_context():
        if existing_deploy_id:
            deploy = Deploy.query.get(existing_deploy_id)
        else:
            deploy = _create_deploy(
                repo_id=repo_id, branch_id=branch_id,
                repo_name=repo_name, branch_name=branch_name,
                pusher=pusher, commit_msg=commit_msg, status="pending",
            )

        ctx["build_number"] = deploy.build_number
        log_path = DEPLOY_LOG_DIR / f"{deploy.id}.log"

        # Pick a runner (local subprocess or SSH) based on the repo's server_id.
        repo_row = Repo.query.get(repo_id) if repo_id else None
        target_server = repo_row.server if (repo_row and repo_row.server_id) else None
        try:
            runner = _make_runner(target_server)
        except Exception as e:
            runner = None
            runner_err = f"could not connect to remote server: {e}"
        else:
            runner_err = None

        def set_current(cmd_text):
            deploy.current_command = (cmd_text or "")[:1023] if cmd_text else None
            db.session.commit()

        def header_to_log():
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(f"=== Deploy #{deploy.id} ===\n")
                f.write(f"Repo:    {owner}/{repo_name}\n")
                f.write(f"Branch:  {branch_name}\n")
                f.write(f"Path:    {path}\n")
                f.write(f"Pusher:  {pusher}\n")
                f.write(f"Message: {commit_msg}\n")
                if target_server:
                    f.write(f"Server:  {target_server.name} "
                            f"({target_server.username}@{target_server.host}:{target_server.port})\n")
                else:
                    f.write(f"Server:  local\n")
                f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        header_to_log()

        try:
            if runner is None:
                raise RuntimeError(runner_err)
            if not runner.is_dir(path):
                where = "on " + runner.label if target_server else "locally"
                raise RuntimeError(f"deploy path does not exist {where}: {path}")

            # --- git operations (streamed to log so the live view shows them too)
            set_current("git rev-parse HEAD")
            rc, old_sha = runner.run_cmd("git rev-parse HEAD", cwd=path)
            if rc != 0:
                # Unborn HEAD — a freshly created/cloned repo that has no commits
                # yet. That's a legitimate first-deploy state, not a failure: the
                # fetch + reset below bring the first commit in. Carry on with an
                # empty old_sha, which downstream code treats as "initial deploy".
                old_sha = ""
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write("\nOld commit: (none — no commits in this repo yet)\n")
            else:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(f"\nOld commit: {old_sha[:10]}\n")
            ctx["old_sha"] = old_sha
            deploy.old_sha = old_sha or None
            db.session.commit()

            set_current(f"git fetch origin {branch_name}")
            rc, _ = runner.stream_cmd(f"git fetch origin {branch_name}", path, log_path, max_capture=2000)
            if rc != 0:
                # A fetch can fail because the remote is empty, because the branch
                # doesn't exist there, or for network/auth reasons. Those need very
                # different fixes, so say which one it is instead of "git fetch failed".
                rc_ls, heads = runner.run_cmd("git ls-remote --heads origin", cwd=path)
                if rc_ls == 0:
                    names = [ln.split("refs/heads/", 1)[-1]
                             for ln in heads.splitlines() if "refs/heads/" in ln]
                    if not names:
                        raise RuntimeError(
                            "remote repository is empty — it has no branches yet. "
                            f"Push a first commit to '{branch_name}' before deploying."
                        )
                    if branch_name not in names:
                        raise RuntimeError(
                            f"branch '{branch_name}' does not exist on origin. "
                            f"Available branches: {', '.join(sorted(names))}"
                        )
                raise RuntimeError("git fetch failed")

            # Rollback support: if target_sha is set, reset to it instead of branch HEAD.
            reset_target = deploy.target_sha or f"origin/{branch_name}"
            if deploy.target_sha:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(f"\n(rolling back: target SHA {deploy.target_sha[:10]})\n")
            set_current(f"git reset --hard {reset_target}")
            rc, _ = runner.stream_cmd(f"git reset --hard {reset_target}", path, log_path, max_capture=2000)
            if rc != 0:
                raise RuntimeError("git reset failed")

            rc, new_sha = runner.run_cmd("git rev-parse HEAD", cwd=path)
            ctx["new_sha"]    = new_sha
            deploy.commit_sha = new_sha
            db.session.commit()

            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"\nNew commit: {new_sha[:10]}\n")

            if not old_sha:
                # Initial deploy into a previously empty repo: there is no old
                # commit to diff against, so `git diff <old> <new>` would be
                # malformed. Everything in the new tree is new.
                _, raw = runner.run_cmd("git ls-tree -r --name-only HEAD", cwd=path)
                files = [ln for ln in raw.splitlines() if ln.strip()]
                ctx["changes"] = {"Added": files, "Modified": [],
                                  "Deleted": [], "Renamed": [], "Other": []}
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(f"\n--- Initial checkout: {len(files)} file(s) ---\n")
            elif old_sha != new_sha:
                _, raw = runner.run_cmd(f"git diff --name-status {old_sha} {new_sha}", cwd=path)
                grouped = {"Added": [], "Modified": [], "Deleted": [], "Renamed": [], "Other": []}
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(f"\n--- File changes ---\n{raw}\n")
                for line in raw.splitlines():
                    parts = line.split("\t")
                    status, files = parts[0], parts[1:]
                    if   status.startswith("A"): grouped["Added"].extend(files)
                    elif status.startswith("M"): grouped["Modified"].extend(files)
                    elif status.startswith("D"): grouped["Deleted"].extend(files)
                    elif status.startswith("R"): grouped["Renamed"].append(" -> ".join(files))
                    else:                        grouped["Other"].append(" ".join(parts))
                ctx["changes"] = grouped

            # --- post-deploy commands (streamed live, with branch env vars exported)
            if old_sha != new_sha and commands:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(f"\n=== Post-deploy commands ({len(commands)}) ===\n")
                    if extra_env:
                        f.write(f"(injected env vars: {', '.join(extra_env.keys())})\n")
                for cmd in commands:
                    set_current(cmd)
                    rc, captured = runner.stream_cmd(cmd, cwd=path, log_path=log_path, extra_env=extra_env)
                    ctx["cmd_results"].append((cmd, rc, captured))
                    if rc != 0:
                        break

            set_current(None)

            failed = next((c for c in ctx["cmd_results"] if c[1] != 0), None)
            ctx["success"] = failed is None

            # Optional health check after commands succeed.
            if ctx["success"] and health_check_url:
                set_current(f"health-check: {health_check_url}")
                ok, code = _run_health_check(health_check_url, log_path)
                if not ok:
                    ctx["success"] = False
                    deploy.error = f"Health check failed (HTTP {code or 'no-response'}) for {health_check_url}"
                else:
                    with open(log_path, "a", encoding="utf-8") as f:
                        f.write(f"health check passed (HTTP {code})\n")

            set_current(None)

            deploy.status      = "success" if ctx["success"] else "failed"
            deploy.finished_at = datetime.utcnow()
            if not ctx["success"] and failed and not deploy.error:
                deploy.error = f"`{failed[0]}` exit {failed[1]}"

            try:
                content = log_path.read_text(encoding="utf-8", errors="replace")
                deploy.log = content[-LOG_CHARS:]
            except Exception:
                pass
            db.session.commit()

            build_tag = f"#{ctx['build_number']}" if ctx.get("build_number") else ""
            subject = f"[{repo_name}/{branch_name}] " + (
                f"Build {build_tag} succeeded — {ctx['new_sha'][:7]}" if ctx["success"]
                else f"Build {build_tag} FAILED — {ctx['new_sha'][:7]}"
            )
            if deploy.silent:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write("\n(silent run — email and Slack notification suppressed)\n")
            else:
                _send_email(subject, _build_email_html(ctx), recipients)
                _post_slack(ctx, deploy)

            # Mirror the new code to any second remote configured with
            # "push on deploy". Never allowed to affect the deploy's own result.
            if ctx["success"] and branch_id:
                try:
                    from mirrors import push_for_deploy
                    ids = push_for_deploy(branch_id, pusher or "webhook")
                    if ids:
                        with open(log_path, "a", encoding="utf-8") as f:
                            f.write(f"\nqueued {len(ids)} mirror push(es): {ids}\n")
                except Exception:
                    app.logger.exception("mirror push after deploy failed")
        except Exception:
            err = traceback.format_exc()
            ctx["success"] = False
            try:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(f"\n=== EXCEPTION ===\n{err}\n")
            except Exception:
                pass
            set_current(None)
            deploy.status      = "failed"
            deploy.error       = err[-2000:]
            deploy.finished_at = datetime.utcnow()
            try:
                deploy.log = log_path.read_text(encoding="utf-8", errors="replace")[-LOG_CHARS:]
            except Exception:
                pass
            db.session.commit()
            build_tag = f"#{ctx['build_number']}" if ctx.get("build_number") else ""
            if not deploy.silent:
                try:
                    _send_email(
                        f"[{repo_name}/{branch_name}] Build {build_tag} FAILED",
                        _build_email_html({**ctx, "cmd_results": [("(exception)", 1, err)]}),
                        recipients,
                    )
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Webhook handler (called from create_app's route)
# ---------------------------------------------------------------------------
def _handle_webhook():
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not _verify_signature(request.data, signature):
        abort(401, "Invalid signature")

    event = request.headers.get("X-GitHub-Event", "")
    if event == "ping":
        return jsonify(pong=True)
    if event and event != "push":
        return jsonify(skipped=True, reason=f"event {event} ignored")

    payload = request.get_json(silent=True) or {}
    repo_name = ((payload.get("repository") or {}).get("name")) or ""
    ref       = payload.get("ref", "")
    branch    = ref.split("refs/heads/", 1)[-1] if ref.startswith("refs/heads/") else ""

    if not repo_name or not branch:
        return jsonify(skipped=True, reason="no repo/branch in payload"), 200

    repo_cfg, branch_cfg, repo_id, branch_id = _lookup_repo_branch(repo_name, branch)
    if not branch_cfg:
        return jsonify(skipped=True, reason=f"{repo_name}/{branch} not configured"), 200

    pusher      = (payload.get("pusher") or {}).get("name", "unknown")
    head_commit = payload.get("head_commit") or {}
    commit_msg  = head_commit.get("message", "(no message)")
    head_sha    = head_commit.get("id") or payload.get("after") or None

    # ---- Auto-deploy gate -------------------------------------------------
    if not branch_cfg.get("auto_deploy", True):
        # Record an "awaiting" deploy row and email recipients that a manual
        # approval is needed. No git pull, no commands run.
        deploy = _create_deploy(
            repo_id=repo_id, branch_id=branch_id,
            repo_name=repo_name, branch_name=branch,
            pusher=pusher, commit_msg=commit_msg,
            commit_sha=head_sha, status="awaiting",
        )

        try:
            base_url = os.getenv("BASE_URL", "https://deploy.pazl.info")
            link = f"{base_url}/deploys/{deploy.id}"
            recipients = _resolve_recipients(branch_cfg, repo_cfg)
            html = f"""
            <html><body style="font-family:Arial,sans-serif;color:#222;">
              <div style="max-width:680px;margin:auto;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden;">
                <div style="background:#f59e0b;color:white;padding:16px 20px;">
                  <h2 style="margin:0;">Manual deploy required</h2>
                  <div style="opacity:.95;font-size:14px;">{repo_name} &middot; {branch} &middot; Build #{deploy.build_number}</div>
                </div>
                <div style="padding:18px 20px;">
                  <p>Auto-deploy is <b>disabled</b> for this branch, so the push was
                  recorded but no commands have been run. Sign into the dashboard
                  and click <b>Deploy now</b> to apply the change.</p>
                  <table style="font-size:14px;border-collapse:collapse;">
                    <tr><td style="padding:2px 8px 2px 0;"><b>Build:</b></td><td><b style="font-size:16px;">#{deploy.build_number}</b></td></tr>
                    <tr><td style="padding:2px 8px 2px 0;"><b>Pushed by:</b></td><td>{pusher}</td></tr>
                    <tr><td style="padding:2px 8px 2px 0;"><b>Commit:</b></td><td><code>{(head_sha or '')[:10]}</code></td></tr>
                    <tr><td style="padding:2px 8px 2px 0;"><b>Message:</b></td><td>{commit_msg}</td></tr>
                  </table>
                  <p style="margin-top:18px;">
                    <a href="{link}" style="background:#0d6efd;color:white;padding:8px 14px;border-radius:5px;text-decoration:none;">Open deploy &rarr;</a>
                  </p>
                </div>
              </div>
            </body></html>"""
            _send_email(
                f"[{repo_name}/{branch}] Build #{deploy.build_number} — Manual deploy required",
                html, recipients,
            )
        except Exception:
            app.logger.exception("awaiting email failed")

        return jsonify(
            accepted=True, awaiting_manual=True,
            repo=repo_name, branch=branch, deploy_id=deploy.id,
        ), 202

    # ---- auto_deploy == True: run as usual --------------------------------
    threading.Thread(
        target=_run_deploy,
        args=(app, repo_name, repo_cfg["owner"], branch, branch_cfg, repo_cfg,
              pusher, commit_msg, repo_id, branch_id),
        daemon=True,
    ).start()

    return jsonify(
        accepted=True, repo=repo_name, branch=branch, path=branch_cfg["path"],
    ), 202


# ---------------------------------------------------------------------------
# Module-level app (for gunicorn)
# ---------------------------------------------------------------------------
app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000, debug=True)
