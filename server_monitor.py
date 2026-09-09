"""Server monitor: live CPU / memory / disk / process stats + kill action.

Admin-only. Uses psutil for portable system reads.
"""

import os
import signal
import time
from datetime import datetime
from functools import wraps

import psutil
from flask import Blueprint, abort, current_app, jsonify, render_template, request
from flask_login import current_user, login_required

import audit
from permissions import requires_permission

monitor_bp = Blueprint("monitor", __name__)


def admin_only(fn):
    """Legacy alias — kept for routes that should require any of several perms,
    or where an explicit superuser-only restriction makes sense. Most routes
    below now use the permission-aware decorators."""
    @wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapped


def _human_bytes(n: int) -> str:
    """Render bytes as 'X.XX GB' / 'X.X MB' etc."""
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024 or unit == "PB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} {unit}"
        n /= 1024


def _process_snapshot(top_n: int = 30) -> list[dict]:
    """Top processes by CPU percent (averaged over a short interval)."""
    # Prime cpu_percent so the next reading is meaningful.
    procs = list(psutil.process_iter(["pid", "name", "username"]))
    for p in procs:
        try: p.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied): pass
    time.sleep(0.1)

    rows = []
    own_pid = os.getpid()
    for p in procs:
        try:
            with p.oneshot():
                rows.append({
                    "pid": p.pid,
                    "name": (p.info["name"] or "")[:40],
                    "user": (p.info["username"] or "?")[:24],
                    "cpu_pct": round(p.cpu_percent(interval=None), 1),
                    "mem_bytes": p.memory_info().rss,
                    "mem_mb": round(p.memory_info().rss / 1024 / 1024, 1),
                    "started_at": datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M"),
                    "is_self": p.pid == own_pid,
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, OSError):
            continue
    rows.sort(key=lambda r: (r["cpu_pct"], r["mem_bytes"]), reverse=True)
    return rows[:top_n]


def _disk_partitions() -> list[dict]:
    out = []
    for p in psutil.disk_partitions(all=False):
        if not p.mountpoint:
            continue
        try:
            u = psutil.disk_usage(p.mountpoint)
        except PermissionError:
            continue
        out.append({
            "mount": p.mountpoint,
            "fstype": p.fstype,
            "device": p.device,
            "total_bytes": u.total,
            "used_bytes": u.used,
            "free_bytes": u.free,
            "percent": u.percent,
            "total_human": _human_bytes(u.total),
            "used_human":  _human_bytes(u.used),
            "free_human":  _human_bytes(u.free),
        })
    return out


def _snapshot() -> dict:
    """Everything the page polls for."""
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    cpu_pct = psutil.cpu_percent(interval=None)
    cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
    cpu_freq = psutil.cpu_freq() if hasattr(psutil, "cpu_freq") else None
    load = list(psutil.getloadavg()) if hasattr(psutil, "getloadavg") else [0, 0, 0]
    boot = psutil.boot_time()
    uptime_sec = int(time.time() - boot)
    net = psutil.net_io_counters()
    return {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": os.uname().nodename,
        "cpu": {
            "percent": cpu_pct,
            "cores_physical": psutil.cpu_count(logical=False),
            "cores_logical":  psutil.cpu_count(logical=True),
            "per_core": [round(c, 1) for c in cpu_per_core],
            "freq_mhz": round(cpu_freq.current) if cpu_freq else None,
            "load_1m":  round(load[0], 2),
            "load_5m":  round(load[1], 2),
            "load_15m": round(load[2], 2),
        },
        "memory": {
            "total_bytes":     mem.total,
            "used_bytes":      mem.used,
            "available_bytes": mem.available,
            "percent":         mem.percent,
            "total_human":     _human_bytes(mem.total),
            "used_human":      _human_bytes(mem.used),
            "available_human": _human_bytes(mem.available),
            "swap_total_human": _human_bytes(swap.total),
            "swap_used_human":  _human_bytes(swap.used),
            "swap_percent":     swap.percent,
        },
        "disks": _disk_partitions(),
        "network": {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "sent_human": _human_bytes(net.bytes_sent),
            "recv_human": _human_bytes(net.bytes_recv),
        },
        "uptime": {
            "seconds": uptime_sec,
            "human": _format_uptime(uptime_sec),
            "boot_at": datetime.fromtimestamp(boot).strftime("%Y-%m-%d %H:%M"),
        },
        "processes": _process_snapshot(),
    }


def _format_uptime(seconds: int) -> str:
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
def _current_snapshot():
    """Return either a local psutil snapshot or a remote SSH snapshot, depending
    on whether the user has switched to a remote server."""
    from servers import current_server
    srv = current_server()
    if srv:
        try:
            from remote_stats import remote_snapshot
            snap = remote_snapshot(srv)
        except Exception as e:
            snap = _snapshot()
            snap["remote"] = True
            snap["remote_error"] = str(e)
            snap["remote_label"] = f"{srv.username}@{srv.host}:{srv.port}"
        return snap
    return _snapshot()


@monitor_bp.route("/server-monitor")
@requires_permission("monitor.view")
def page():
    return render_template("server_monitor.html", snap=_current_snapshot())


@monitor_bp.route("/server-monitor/stats")
@requires_permission("monitor.view")
def stats():
    return jsonify(_current_snapshot())


@monitor_bp.route("/services")
@requires_permission("monitor.view")
def services_page():
    return render_template("services.html", services=_list_services())


@monitor_bp.route("/services/stats")
@requires_permission("monitor.view")
def services_stats():
    return jsonify(services=_list_services())


@monitor_bp.route("/services/action", methods=["POST"])
@requires_permission("services.control")
def services_action():
    """systemctl start/stop/restart/reload/enable/disable on a named unit."""
    import subprocess as sp
    unit = (request.form.get("unit") or "").strip()
    action = (request.form.get("action") or "").strip().lower()
    if action not in ("start", "stop", "restart", "reload", "enable", "disable"):
        return jsonify(ok=False, error="invalid action"), 400
    # Defensive: allow only typical unit-name chars.
    if not unit or not all(c.isalnum() or c in "@-._" for c in unit):
        return jsonify(ok=False, error="invalid unit name"), 400

    from servers import current_server
    srv = current_server()
    cmd_str = f"systemctl {action} {unit}"
    if srv:
        try:
            import ssh as ssh_helper
            client = ssh_helper.get_client(srv)
            stdin, stdout, stderr = client.exec_command(cmd_str, timeout=20)
            rc = stdout.channel.recv_exit_status()
            out = (stdout.read().decode(errors="replace")
                   + stderr.read().decode(errors="replace")).strip()
        except Exception as e:
            return jsonify(ok=False, error=f"ssh: {e}"), 500
        audit.log("server.systemctl_remote", "service", None, f"{action} {unit}",
                  details={"rc": rc, "out": out[-500:], "server_id": srv.id})
        return jsonify(ok=rc == 0, rc=rc, output=out[-2000:])

    try:
        result = sp.run(["systemctl", action, unit],
                        capture_output=True, text=True, timeout=20)
    except FileNotFoundError:
        return jsonify(ok=False, error="systemctl not found on this server"), 500
    except sp.TimeoutExpired:
        return jsonify(ok=False, error="systemctl timed out (20s)"), 504
    out = (result.stdout + result.stderr).strip()
    audit.log("server.systemctl", "service", None, f"{action} {unit}",
              details={"rc": result.returncode, "out": out[-500:]})
    return jsonify(ok=result.returncode == 0, rc=result.returncode, output=out[-2000:])


@monitor_bp.route("/services/status/<path:unit>")
@requires_permission("monitor.view")
def services_status(unit):
    if not all(c.isalnum() or c in "@-._" for c in unit):
        abort(400)
    cmd_str = f"systemctl status {unit} --no-pager -l"
    from servers import current_server
    srv = current_server()
    if srv:
        try:
            import ssh as ssh_helper
            client = ssh_helper.get_client(srv)
            stdin, stdout, stderr = client.exec_command(cmd_str, timeout=10)
            rc = stdout.channel.recv_exit_status()
            out = (stdout.read().decode(errors="replace")
                   + stderr.read().decode(errors="replace"))
        except Exception as e:
            return jsonify(output=f"ssh error: {e}", rc=1), 200
        return jsonify(output=out[-8000:], rc=rc)

    import subprocess as sp
    try:
        result = sp.run(cmd_str.split(),
                        capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        return jsonify(ok=False, error="systemctl not found"), 500
    return jsonify(output=(result.stdout + result.stderr)[-8000:], rc=result.returncode)


def _list_services():
    """Parse `systemctl list-units --type=service --all` into rows.
    Routes through SSH when the user has switched to a remote server."""
    from servers import current_server
    srv = current_server()
    cmd = "systemctl list-units --type=service --all --no-pager --no-legend"
    if srv:
        try:
            import ssh as ssh_helper
            client = ssh_helper.get_client(srv)
            stdin, stdout, stderr = client.exec_command(cmd, timeout=15)
            out = stdout.read().decode("utf-8", errors="replace")
        except Exception:
            return []
    else:
        import subprocess as sp
        try:
            out = sp.run(cmd.split(),
                         capture_output=True, text=True, timeout=10).stdout
        except (FileNotFoundError, sp.TimeoutExpired):
            return []
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        # Each line: UNIT LOAD ACTIVE SUB DESCRIPTION
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        unit, load, active, sub, desc = parts
        if not unit.endswith(".service"):
            continue
        rows.append({
            "unit": unit, "load": load, "active": active, "sub": sub,
            "description": desc,
        })
    # Sort: active running first, then by name
    rows.sort(key=lambda r: (0 if r["sub"] == "running" else 1, r["unit"]))
    return rows


@monitor_bp.route("/server-monitor/history")
@requires_permission("monitor.view")
def history():
    """Recent metric samples for the line charts.
    `?range=1h | 6h | 24h | 7d` controls how far back to query."""
    from datetime import timedelta as _td
    from models import ServerMetric
    spec = (request.args.get("range") or "6h").lower()
    delta = {"1h": _td(hours=1), "6h": _td(hours=6),
             "24h": _td(hours=24), "7d": _td(days=7)}.get(spec, _td(hours=6))
    since = datetime.utcnow() - delta
    rows = (ServerMetric.query
            .filter(ServerMetric.sampled_at >= since)
            .order_by(ServerMetric.sampled_at).all())
    return jsonify({
        "range": spec,
        "labels":   [r.sampled_at.isoformat() + "Z" for r in rows],
        "cpu":      [r.cpu_pct for r in rows],
        "mem":      [r.mem_pct for r in rows],
        "disk":     [r.disk_pct for r in rows],
        "load_1m":  [r.load_1m for r in rows],
    })


# Processes we refuse to kill — would brick the host or this app.
_PROTECTED_PIDS = {0, 1}
_PROTECTED_NAMES = {"systemd", "init", "kernel", "kthreadd"}


@monitor_bp.route("/server-monitor/kill", methods=["POST"])
@admin_only
def kill():
    try:
        pid = int(request.form.get("pid") or request.json.get("pid"))
    except (TypeError, ValueError):
        return jsonify(ok=False, error="invalid pid"), 400
    sig_str = (request.form.get("signal") or "TERM").upper()
    if sig_str not in ("TERM", "KILL", "HUP", "INT"):
        return jsonify(ok=False, error="invalid signal (TERM/KILL/HUP/INT)"), 400

    if pid in _PROTECTED_PIDS:
        return jsonify(ok=False, error=f"pid {pid} is protected (system process)"), 400
    if pid == os.getpid():
        return jsonify(ok=False, error="refusing to kill this very gunicorn worker"), 400

    try:
        proc = psutil.Process(pid)
        name = proc.name()
    except psutil.NoSuchProcess:
        return jsonify(ok=False, error=f"pid {pid} not found"), 404
    except psutil.AccessDenied:
        return jsonify(ok=False, error=f"access denied reading pid {pid}"), 403

    if name in _PROTECTED_NAMES:
        return jsonify(ok=False, error=f"process '{name}' is protected"), 400

    sig = {"TERM": signal.SIGTERM, "KILL": signal.SIGKILL,
           "HUP":  signal.SIGHUP,  "INT":  signal.SIGINT}[sig_str]
    try:
        proc.send_signal(sig)
    except psutil.AccessDenied:
        return jsonify(ok=False, error="permission denied (try running the service as root)"), 403
    except psutil.NoSuchProcess:
        return jsonify(ok=False, error="process exited before signal was delivered"), 410
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

    audit.log("server.kill_process", "process", pid, f"{name} (SIG{sig_str})")
    return jsonify(ok=True, pid=pid, name=name, signal=sig_str)


# We override the kill route with a remote-aware version below — Flask uses
# the last-registered endpoint when names collide, so we redefine the closure
# of the existing route by overwriting it at import time.
@monitor_bp.route("/server-monitor/kill-remote-aware", methods=["POST"])
@admin_only
def _kill_remote_dispatcher():
    return jsonify(ok=False, error="unreachable — handled by /server-monitor/kill via dispatch_kill"), 500


def _patched_kill():
    """When current_server is set, send the signal on the remote box via SSH."""
    from servers import current_server
    srv = current_server()
    try:
        pid = int(request.form.get("pid") or 0)
    except (TypeError, ValueError):
        return jsonify(ok=False, error="invalid pid"), 400
    sig_str = (request.form.get("signal") or "TERM").upper()
    if sig_str not in ("TERM", "KILL", "HUP", "INT"):
        return jsonify(ok=False, error="invalid signal"), 400

    if not srv:
        return kill()  # local path — original function

    if pid in _PROTECTED_PIDS:
        return jsonify(ok=False, error=f"pid {pid} is protected"), 400

    import ssh as ssh_helper
    try:
        client = ssh_helper.get_client(srv)
        cmd = f"kill -{sig_str} {pid}"
        stdin, stdout, stderr = client.exec_command(cmd, timeout=10)
        rc = stdout.channel.recv_exit_status()
        err = stderr.read().decode(errors="replace").strip()
        if rc != 0:
            return jsonify(ok=False, error=err or f"kill exit {rc}"), 500
    except Exception as e:
        return jsonify(ok=False, error=f"ssh: {e}"), 500

    audit.log("server.kill_process_remote", "process", pid,
              f"pid={pid} sig={sig_str} on {srv.name}",
              details={"server_id": srv.id})
    return jsonify(ok=True, pid=pid, signal=sig_str, target=srv.name)


# Replace the local /server-monitor/kill view with the dispatcher
monitor_bp.view_functions["kill"] = _patched_kill
