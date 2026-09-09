"""Interactive PTY terminal over WebSocket (xterm.js).

A real bash process attached to a pseudo-tty, plumbed bidirectionally to the
browser via flask-sock. Tab completion, vim, top, Ctrl+C — all work like a
normal SSH session.

Admin-only. Audit-logged on session start.
"""

import fcntl
import json
import os
import pty
import select
import signal
import struct
import termios
from datetime import datetime
from functools import wraps

from flask import abort, request
from flask_login import current_user
from flask_sock import Sock

import audit

# Default shell + cwd
SHELL = os.getenv("TERMINAL_SHELL", "/bin/bash")
DEFAULT_CWD = os.getenv("TERMINAL_DEFAULT_CWD", "/srv/code/Source_Code/packworx")

sock = Sock()


def admin_required_ws(fn):
    """Reject the WebSocket handshake if the user lacks the terminal.shell permission."""
    from permissions import has_permission
    @wraps(fn)
    def wrapped(ws, *a, **kw):
        if not current_user.is_authenticated or not has_permission(current_user, "terminal.shell"):
            try: ws.close(code=4403, message=b"forbidden")
            except Exception: pass
            return
        return fn(ws, *a, **kw)
    return wrapped


@sock.route("/pty/ws")
@admin_required_ws
def pty_socket(ws):
    """Open an interactive shell. Routes to a local bash PTY OR, when the user
    has switched to a remote server, a paramiko `invoke_shell()` session."""
    from servers import current_server
    server = current_server()
    if server is not None:
        return _serve_remote(ws, server)
    return _serve_local(ws)


def _serve_local(ws):
    pid, master_fd = pty.fork()
    if pid == 0:
        # CHILD — replace with bash
        os.environ["TERM"]      = "xterm-256color"
        os.environ["COLORTERM"] = "truecolor"
        try: os.chdir(DEFAULT_CWD)
        except OSError: pass
        os.execvp(SHELL, [SHELL, "-il"])
        os._exit(127)   # unreachable

    # PARENT — manage the master end
    audit.log("terminal.pty_open", "terminal", pid,
              f"{current_user.username}@local:{SHELL}",
              details={"shell": SHELL, "cwd": DEFAULT_CWD, "target": "local"})

    # Non-blocking reads
    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    closed = False

    def child_alive():
        try:
            wpid, _ = os.waitpid(pid, os.WNOHANG)
            return wpid == 0
        except ChildProcessError:
            return False

    try:
        # Use threads-via-select: poll the master fd, then poll the WS with a tiny timeout.
        while True:
            if not child_alive():
                break

            # Output: PTY → WebSocket
            r, _, _ = select.select([master_fd], [], [], 0.05)
            if master_fd in r:
                try:
                    data = os.read(master_fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                try:
                    ws.send(data.decode("utf-8", errors="replace"))
                except Exception:
                    break

            # Input: WebSocket → PTY (short timeout so we keep cycling)
            try:
                msg = ws.receive(timeout=0.05)
            except Exception:
                break
            if msg is None:
                continue

            try:
                if isinstance(msg, bytes):
                    msg = msg.decode("utf-8", errors="replace")
                if not msg:
                    continue
                # Frames are JSON: {"type":"input","data":"..."} or {"type":"resize","rows":N,"cols":M}
                try:
                    frame = json.loads(msg)
                except ValueError:
                    # Treat raw text as input
                    frame = {"type": "input", "data": msg}

                t = frame.get("type")
                if t == "input":
                    os.write(master_fd, frame.get("data", "").encode("utf-8"))
                elif t == "resize":
                    rows = int(frame.get("rows", 24))
                    cols = int(frame.get("cols", 80))
                    fcntl.ioctl(master_fd, termios.TIOCSWINSZ,
                                struct.pack("HHHH", rows, cols, 0, 0))
                elif t == "ping":
                    ws.send(json.dumps({"type": "pong"}))
            except OSError:
                # The PTY was likely closed
                break
            except Exception:
                continue
    finally:
        closed = True
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        try:
            os.close(master_fd)
        except OSError:
            pass
        # Reap the child
        try:
            os.waitpid(pid, os.WNOHANG)
        except Exception:
            pass
        audit.log("terminal.pty_close", "terminal", pid, current_user.username)


def _serve_remote(ws, server):
    """Open an SSH session against `server` and bridge it to the WebSocket."""
    import ssh as ssh_helper
    audit.log("terminal.pty_open", "server", server.id,
              f"{current_user.username}@{server.label}",
              details={"target": "remote", "host": server.host})
    try:
        client = ssh_helper.get_client(server)
        chan = client.invoke_shell(term="xterm-256color", width=120, height=30)
        chan.settimeout(0.0)   # non-blocking
    except Exception as e:
        try: ws.send(f"\r\n\x1b[31mFailed to connect to {server.label}: {e}\x1b[0m\r\n")
        except Exception: pass
        try: ws.close()
        except Exception: pass
        audit.log("terminal.pty_close", "server", server.id,
                  f"connect-failed: {e}")
        return

    try:
        while True:
            if chan.closed or chan.exit_status_ready():
                break
            # Output: SSH channel → WebSocket
            try:
                data = chan.recv(4096)
                if data:
                    ws.send(data.decode("utf-8", errors="replace"))
            except Exception:
                # non-blocking returned nothing
                pass

            # Input: WebSocket → SSH channel (short timeout, then loop)
            try:
                msg = ws.receive(timeout=0.05)
            except Exception:
                break
            if msg is None:
                continue
            try:
                if isinstance(msg, bytes):
                    msg = msg.decode("utf-8", errors="replace")
                if not msg: continue
                try:
                    frame = json.loads(msg)
                except ValueError:
                    frame = {"type": "input", "data": msg}
                t = frame.get("type")
                if t == "input":
                    chan.send(frame.get("data", "").encode("utf-8"))
                elif t == "resize":
                    rows = int(frame.get("rows", 24))
                    cols = int(frame.get("cols", 80))
                    chan.resize_pty(width=cols, height=rows)
                elif t == "ping":
                    ws.send(json.dumps({"type": "pong"}))
            except Exception:
                continue
    finally:
        try: chan.close()
        except Exception: pass
        audit.log("terminal.pty_close", "server", server.id, current_user.username)
