"""Thin paramiko wrapper used by the multi-server feature.

Handles both password and key-based auth (including OpenSSH and PuTTY .ppk
keys after a one-time conversion at upload time). One persistent client per
(server_id, gunicorn-worker-thread) — cached so terminal sessions don't pay
the TCP/SSH handshake every request.
"""

import io
import threading
from datetime import datetime
from typing import Optional, Tuple

import paramiko

# Cache: keyed by server_id within this Python worker.
# Each worker has its own cache — that's fine, we just pay one extra connect
# per worker-thread when a route falls onto a new thread.
_client_cache: dict[int, paramiko.SSHClient] = {}
_cache_lock = threading.Lock()


def _load_key(text: str, passphrase: Optional[str]) -> paramiko.PKey:
    """Try every common key format. PPK is OpenSSH-loadable if exported as
    'OpenSSH' by puttygen; otherwise we surface a helpful error."""
    text = (text or "").strip()
    if not text:
        raise ValueError("empty private key")
    if "PuTTY-User-Key-File" in text:
        raise ValueError(
            "This looks like a PuTTY .ppk key. Convert it to OpenSSH format first: "
            "in PuTTYgen → Load your .ppk → Conversions → Export OpenSSH key → save "
            "and paste the resulting file here."
        )
    buf = io.StringIO(text)
    last_err = None
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey, paramiko.DSSKey):
        try:
            buf.seek(0)
            return cls.from_private_key(buf, password=passphrase or None)
        except paramiko.SSHException as e:
            last_err = e
        except Exception as e:
            last_err = e
    raise ValueError(f"could not parse private key: {last_err}")


def _connect_new(server) -> paramiko.SSHClient:
    """Open a fresh SSH connection for `server` (a models.Server row)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=server.host, port=server.port or 22, username=server.username,
        timeout=15, banner_timeout=15, auth_timeout=15, allow_agent=False, look_for_keys=False,
    )
    if server.auth_type == "key":
        kwargs["pkey"] = _load_key(server.private_key, server.key_passphrase)
    else:
        kwargs["password"] = server.password or ""
    client.connect(**kwargs)
    return client


def get_client(server, *, force_new: bool = False) -> paramiko.SSHClient:
    """Return a cached SSH client for the given server, opening one if needed.
    `force_new=True` always opens fresh (used by the test-connection button)."""
    if force_new:
        return _connect_new(server)
    with _cache_lock:
        existing = _client_cache.get(server.id)
        if existing:
            try:
                t = existing.get_transport()
                if t and t.is_active():
                    return existing
            except Exception:
                pass
            try: existing.close()
            except Exception: pass
            _client_cache.pop(server.id, None)
        client = _connect_new(server)
        _client_cache[server.id] = client
        return client


def close_client(server_id: int) -> None:
    with _cache_lock:
        c = _client_cache.pop(server_id, None)
    if c:
        try: c.close()
        except Exception: pass


def test_connection(server) -> Tuple[bool, str]:
    """Open a fresh SSH session, run `echo ok`, return (success, message)."""
    try:
        c = _connect_new(server)
        try:
            stdin, stdout, stderr = c.exec_command("echo packwork-ssh-ok && uname -a", timeout=10)
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()
            if "packwork-ssh-ok" not in out:
                return False, err or out or "no response"
            uname = out.split("\n", 1)[1] if "\n" in out else ""
            return True, f"OK — {uname}" if uname else "OK"
        finally:
            try: c.close()
            except Exception: pass
    except paramiko.AuthenticationException as e:
        return False, f"authentication failed: {e}"
    except paramiko.SSHException as e:
        return False, f"SSH error: {e}"
    except OSError as e:
        return False, f"connection error: {e}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def update_check_state(server, ok: bool, msg: str) -> None:
    """Persist the result of a connection test on the server row."""
    from models import db
    server.last_check_at = datetime.utcnow()
    server.last_check_ok = ok
    server.last_check_msg = msg[:1024]
    db.session.commit()
