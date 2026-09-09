"""Admin-only command runner. One-shot, not interactive — but streams output
so the UI feels live.

Output goes to /var/log/packwork-deploy/terminal/<run_id>.log; the runs table
keeps metadata (command, status, PID, exit code, timing) and a few saved
snippets.
"""

import os
import signal
import subprocess
import threading
import time
from datetime import datetime
from functools import wraps
from pathlib import Path

import psutil
from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import desc

import audit
from models import TerminalRun, TerminalSnippet, db
from permissions import requires_permission

term_bp = Blueprint("term", __name__)

LOG_DIR = Path(os.getenv("TERMINAL_LOG_DIR", "/var/log/packwork-deploy/terminal"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_TIMEOUT = int(os.getenv("TERMINAL_TIMEOUT", "600"))     # 10 min default kill
DEFAULT_CWD     = os.getenv("TERMINAL_DEFAULT_CWD", "/srv/code/Source_Code/packworx")


def admin_only(fn):
    @wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Background runner
# ---------------------------------------------------------------------------
def _shell_env():
    return {**os.environ, "PATH": os.environ.get("PATH", "") + ":/usr/local/bin:/usr/bin:/bin"}


def _run_thread(app, run_id, command, cwd, timeout, server_id):
    """Run command locally OR on the given remote server. Streams output to the
    same per-run log file."""
    log_path = LOG_DIR / f"{run_id}.log"
    with app.app_context():
        run = TerminalRun.query.get(run_id)

        # Pick mode
        if server_id:
            from models import Server
            server = Server.query.get(server_id)
            target = f"{server.username}@{server.host}:{server.port}" if server else "(missing)"
        else:
            server = None
            target = "local"

        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"$ {command}\n(target: {target})\n")
            if cwd: f.write(f"(cwd: {cwd})\n")
            f.write("\n")

        # --- LOCAL execution ---
        if not server:
            try:
                with open(log_path, "a", encoding="utf-8", buffering=1) as f:
                    proc = subprocess.Popen(
                        command, cwd=cwd or None, shell=True,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, bufsize=1, env=_shell_env(),
                    )
                    run.pid = proc.pid; db.session.commit()
                    start = time.time()
                    try:
                        for line in proc.stdout:
                            f.write(line)
                            if time.time() - start > timeout:
                                proc.kill()
                                f.write(f"\n(killed after {timeout}s timeout)\n")
                                run.status = "timeout"; break
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        f.write(f"\n(killed after {timeout}s timeout)\n")
                        run.status = "timeout"
                    run.exit_code = proc.returncode
                    if run.status == "running":
                        run.status = "done" if proc.returncode == 0 else "failed"
                    f.write(f"\n(exit {proc.returncode})\n")
            except Exception as e:
                run.status = "failed"
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(f"\n(runner crashed: {e})\n")
            finally:
                run.finished_at = datetime.utcnow()
                db.session.commit()
            return

        # --- REMOTE execution over SSH ---
        try:
            import ssh as ssh_helper
            client = ssh_helper.get_client(server)
            wrapped = command if not cwd else f"cd {cwd!r} && {command}"
            with open(log_path, "a", encoding="utf-8", buffering=1) as f:
                stdin, stdout, stderr = client.exec_command(
                    wrapped, get_pty=True, timeout=timeout,
                )
                channel = stdout.channel
                start = time.time()
                # Use a small chunk loop so we capture incremental output
                try:
                    while True:
                        if channel.recv_ready():
                            f.write(channel.recv(4096).decode("utf-8", errors="replace"))
                        elif channel.exit_status_ready():
                            # Drain whatever's left
                            while channel.recv_ready():
                                f.write(channel.recv(4096).decode("utf-8", errors="replace"))
                            break
                        else:
                            time.sleep(0.05)
                        if time.time() - start > timeout:
                            channel.close()
                            f.write(f"\n(killed after {timeout}s timeout)\n")
                            run.status = "timeout"; break
                    rc = channel.recv_exit_status()
                    run.exit_code = rc
                    if run.status == "running":
                        run.status = "done" if rc == 0 else "failed"
                    f.write(f"\n(exit {rc})\n")
                except Exception as e:
                    run.status = "failed"
                    f.write(f"\n(ssh error: {e})\n")
        except Exception as e:
            run.status = "failed"
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"\n(ssh connect failed: {e})\n")
        finally:
            run.finished_at = datetime.utcnow()
            db.session.commit()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@term_bp.route("/terminal")
@requires_permission("terminal.use")
def page():
    runs = (TerminalRun.query.order_by(desc(TerminalRun.started_at)).limit(20).all())
    snippets = TerminalSnippet.query.order_by(TerminalSnippet.label).all()
    return render_template("terminal.html",
                           runs=runs, snippets=snippets,
                           default_cwd=DEFAULT_CWD)


@term_bp.route("/terminal/run", methods=["POST"])
@requires_permission("terminal.use")
def run():
    command = (request.form.get("command") or "").strip()
    cwd     = (request.form.get("cwd")     or "").strip() or None
    timeout = int(request.form.get("timeout") or DEFAULT_TIMEOUT)
    if not command:
        return jsonify(ok=False, error="empty command"), 400
    if timeout < 1 or timeout > 3600:
        return jsonify(ok=False, error="timeout out of range (1..3600 s)"), 400

    run_row = TerminalRun(
        user_id=current_user.id, username=current_user.username,
        command=command[:2048], cwd=cwd, status="running",
    )
    db.session.add(run_row)
    db.session.commit()
    audit.log("terminal.run", "terminal", run_row.id, command[:200],
              details={"cwd": cwd, "timeout": timeout})

    # Hand off to a background thread, threading the current server through.
    from deploy_webhook import app as flask_app
    from servers import current_server
    srv = current_server()
    server_id = srv.id if srv else None
    threading.Thread(target=_run_thread,
                     args=(flask_app, run_row.id, command, cwd, timeout, server_id),
                     daemon=True).start()
    return jsonify(ok=True, run_id=run_row.id, target=("local" if not srv else srv.name))


@term_bp.route("/terminal/output/<int:run_id>")
@requires_permission("terminal.use")
def output(run_id):
    """Polling endpoint: returns log content from `offset` and the run state."""
    r = TerminalRun.query.get_or_404(run_id)
    offset = int(request.args.get("offset", "0"))
    log_path = LOG_DIR / f"{run_id}.log"
    content = ""
    size = 0
    if log_path.exists():
        try:
            size = log_path.stat().st_size
            if offset > size: offset = 0
            with open(log_path, "rb") as f:
                f.seek(offset)
                content = f.read().decode("utf-8", errors="replace")
        except OSError:
            pass
    return jsonify({
        "status": r.status, "pid": r.pid, "exit_code": r.exit_code,
        "content": content, "next_offset": size,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
    })


@term_bp.route("/terminal/kill/<int:run_id>", methods=["POST"])
@requires_permission("terminal.use")
def kill(run_id):
    r = TerminalRun.query.get_or_404(run_id)
    if r.status != "running" or not r.pid:
        return jsonify(ok=False, error=f"run is {r.status}"), 400
    try:
        psutil.Process(r.pid).terminate()
    except psutil.NoSuchProcess:
        pass
    r.status = "killed"
    r.finished_at = datetime.utcnow()
    db.session.commit()
    audit.log("terminal.kill", "terminal", run_id, str(r.pid))
    return jsonify(ok=True)


# Snippets ------------------------------------------------------------------
@term_bp.route("/terminal/snippets/new", methods=["POST"])
@requires_permission("terminal.use")
def snippet_new():
    label   = (request.form.get("label") or "").strip()
    command = (request.form.get("command") or "").strip()
    cwd     = (request.form.get("cwd") or "").strip() or None
    if not label or not command:
        flash("Label and command are required.", "danger")
        return redirect(url_for("term.page"))
    s = TerminalSnippet(label=label[:128], command=command[:2048], cwd=cwd,
                        created_by=current_user.username)
    db.session.add(s)
    db.session.commit()
    audit.log("terminal.snippet_new", "snippet", s.id, label)
    flash(f"Saved snippet '{label}'.", "success")
    return redirect(url_for("term.page"))


@term_bp.route("/terminal/snippets/<int:snippet_id>/delete", methods=["POST"])
@requires_permission("terminal.use")
def snippet_delete(snippet_id):
    s = TerminalSnippet.query.get_or_404(snippet_id)
    label = s.label
    db.session.delete(s)
    db.session.commit()
    audit.log("terminal.snippet_delete", "snippet", snippet_id, label)
    return redirect(url_for("term.page"))
