"""Admin-only file manager: browse / view / edit / delete / upload / download / rename / mkdir.

Defaults to /srv/code/Source_Code/packworx as the starting jail, but full-filesystem
access is allowed for admins by passing an absolute path. Every mutation is
recorded in the audit log.
"""

import io
import mimetypes
import os
import shutil
import zipfile
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

import audit
from fs import current_fs
from permissions import requires_permission

fm_bp = Blueprint("fm", __name__)

DEFAULT_ROOT  = Path(os.getenv("FM_DEFAULT_ROOT", "/srv/code/Source_Code/packworx"))
EDIT_SIZE_MAX = 5 * 1024 * 1024            # 5 MB — refuse to load larger files into the editor
UPLOAD_SIZE_MAX = 100 * 1024 * 1024        # 100 MB per upload
TEXT_PROBE    = 8192                       # bytes to sniff for text vs binary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def admin_only(fn):
    @wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapped


def _resolve(path_str: str):
    """Resolve to an absolute, normalized path. For local mode we use Path.resolve();
    for remote we hand back a plain string normalised via posixpath.normpath."""
    from servers import current_server
    if not path_str:
        return str(_remote_default_root() if current_server() else DEFAULT_ROOT)

    if current_server():
        # Treat the user input as posix; default-root if relative
        import posixpath
        p = path_str if path_str.startswith("/") else posixpath.join(str(_remote_default_root()), path_str)
        return posixpath.normpath(p)

    p = Path(path_str)
    if not p.is_absolute():
        p = DEFAULT_ROOT / p
    return str(p.resolve(strict=False))


def _remote_default_root() -> str:
    """Reasonable starting dir on the remote — the user's home, fall back to /."""
    return "/root"


def _looks_text(path: Path) -> bool:
    """Heuristic for 'safe to load into the editor'."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(TEXT_PROBE)
        if b"\x00" in chunk:
            return False
        chunk.decode("utf-8")
        return True
    except (UnicodeDecodeError, OSError):
        return False


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} {unit}"
        n /= 1024


def _icon_for(p: Path) -> str:
    if p.is_dir():
        return "folder-fill"
    suf = p.suffix.lower()
    return {
        ".py": "file-earmark-code", ".js": "file-earmark-code", ".ts": "file-earmark-code",
        ".jsx": "file-earmark-code", ".tsx": "file-earmark-code",
        ".html": "file-earmark-code", ".css": "file-earmark-code", ".scss": "file-earmark-code",
        ".sh": "file-earmark-terminal", ".bash": "file-earmark-terminal",
        ".json": "file-earmark-text", ".yml": "file-earmark-text", ".yaml": "file-earmark-text",
        ".toml": "file-earmark-text", ".ini": "file-earmark-text", ".conf": "file-earmark-text",
        ".md": "file-earmark-richtext", ".txt": "file-earmark-text",
        ".log": "file-earmark-ruled",
        ".png": "file-earmark-image", ".jpg": "file-earmark-image", ".jpeg": "file-earmark-image",
        ".gif": "file-earmark-image", ".svg": "file-earmark-image", ".webp": "file-earmark-image",
        ".pdf": "file-earmark-pdf",
        ".zip": "file-earmark-zip", ".tar": "file-earmark-zip", ".gz": "file-earmark-zip",
        ".sql": "file-earmark-spreadsheet",
        ".env": "file-earmark-lock",
    }.get(suf, "file-earmark")


def _crumbs(p: Path):
    """Breadcrumb list of (label, full_path) from / to p."""
    parts = p.parts            # ('/', 'srv', 'code', ...)
    acc = ""
    out = []
    for part in parts:
        if part == "/":
            acc = "/"
        else:
            acc = (acc.rstrip("/") + "/" + part) if acc != "/" else "/" + part
        out.append((part, acc))
    return out


# ---------------------------------------------------------------------------
# Browse / view / edit
# ---------------------------------------------------------------------------
@fm_bp.route("/files")
@requires_permission("files.view")
def index():
    raw = request.args.get("path", "")
    target = _resolve(raw)
    fs = current_fs()

    if not fs.exists(target):
        flash(f"Path not found: {target}", "danger")
        return redirect(url_for("fm.index"))

    parent = _parent_of(target)

    if fs.is_dir(target):
        entries = []
        try:
            for name, full, st in fs.listdir(target):
                size = st.size if not st.is_dir else None
                entries.append({
                    "name":    name,
                    "is_dir":  st.is_dir,
                    "is_link": st.is_link,
                    "size":    size,
                    "size_h":  _human_bytes(size) if size is not None else "—",
                    "mtime":   st.mtime.strftime("%Y-%m-%d %H:%M"),
                    "mode":    oct(st.mode),
                    "icon":    _icon_for_name(name, st.is_dir),
                    "path":    full,
                })
        except (PermissionError, IOError) as e:
            flash(f"Permission denied reading {target}: {e}", "danger")
            return redirect(url_for("fm.index"))
        return render_template(
            "file_manager.html",
            mode="list", path=target, parent=parent,
            entries=entries, crumbs=_crumbs_str(target),
            default_root=_default_root_str(),
        )

    # It's a file — show the editor or fall back to binary view.
    try:
        st = fs.stat(target)
    except Exception as e:
        flash(f"Can't stat {target}: {e}", "danger")
        return redirect(url_for("fm.index", path=parent))

    if st.size > EDIT_SIZE_MAX:
        return render_template("file_manager.html",
            mode="too_big", path=target, size_h=_human_bytes(st.size),
            crumbs=_crumbs_str(target), parent=parent,
            default_root=_default_root_str())

    is_text = fs.looks_text(target)
    content = ""
    if is_text:
        try: content = fs.read_text(target)
        except Exception as e:
            flash(f"Read failed: {e}", "danger")
            return redirect(url_for("fm.index", path=parent))

    return render_template(
        "file_manager.html",
        mode="edit" if is_text else "binary",
        path=target, parent=parent,
        crumbs=_crumbs_str(target), content=content,
        size_h=_human_bytes(st.size),
        mime=mimetypes.guess_type(target)[0] or "application/octet-stream",
        default_root=_default_root_str(),
    )


def _parent_of(path: str) -> str | None:
    if path in ("/", ""):
        return None
    s = path.rstrip("/")
    return s.rsplit("/", 1)[0] or "/"


def _default_root_str() -> str:
    from servers import current_server
    return _remote_default_root() if current_server() else str(DEFAULT_ROOT)


def _crumbs_str(path_str: str):
    """Posix-style breadcrumb that works for both local and remote string paths."""
    parts = []
    acc = ""
    parts.append(("/", "/"))
    for seg in path_str.strip("/").split("/"):
        if not seg: continue
        acc = (acc + "/" + seg) if acc else "/" + seg
        parts.append((seg, acc))
    return parts


def _icon_for_name(name: str, is_dir: bool) -> str:
    if is_dir: return "folder-fill"
    suf = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
    return _icon_for(Path("x" + suf))


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------
@fm_bp.route("/files/save", methods=["POST"])
@requires_permission("files.edit")
def save():
    target = _resolve(request.form.get("path", ""))
    fs = current_fs()
    if fs.is_dir(target):
        flash(f"Cannot save: {target} is a directory.", "danger")
        return redirect(url_for("fm.index", path=target))
    content = request.form.get("content", "")
    try:
        fs.write_text(target, content)
    except Exception as e:
        flash(f"Save failed: {e}", "danger")
        return redirect(url_for("fm.index", path=target))
    audit.log("file.edit", "file", None, target, details={"size": len(content), "fs": fs.name})
    flash(f"Saved {target.rsplit('/',1)[-1]} ({_human_bytes(len(content.encode()))}).", "success")
    return redirect(url_for("fm.index", path=target))


@fm_bp.route("/files/delete", methods=["POST"])
@requires_permission("files.edit")
def delete():
    target = _resolve(request.form.get("path", ""))
    fs = current_fs()
    if not fs.exists(target):
        flash("Already gone.", "info")
        return redirect(url_for("fm.index"))
    parent = _parent_of(target)
    try:
        fs.delete(target)
    except Exception as e:
        flash(f"Delete failed: {e}", "danger")
        return redirect(url_for("fm.index", path=parent))
    audit.log("file.delete", "file", None, target, details={"fs": fs.name})
    flash(f"Deleted {target.rsplit('/',1)[-1]}.", "info")
    return redirect(url_for("fm.index", path=parent))


@fm_bp.route("/files/rename", methods=["POST"])
@requires_permission("files.edit")
def rename():
    target = _resolve(request.form.get("path", ""))
    new = (request.form.get("new_name") or "").strip()
    if not new or "/" in new or "\\" in new or new in (".", ".."):
        flash("Invalid name.", "danger")
        return redirect(url_for("fm.index", path=_parent_of(target)))
    fs = current_fs()
    if not fs.exists(target):
        flash("Source no longer exists.", "danger")
        return redirect(url_for("fm.index"))
    parent = _parent_of(target)
    dst = (parent.rstrip("/") + "/" + new) if parent != "/" else "/" + new
    try:
        fs.rename(target, dst)
    except Exception as e:
        flash(f"Rename failed: {e}", "danger")
        return redirect(url_for("fm.index", path=parent))
    audit.log("file.rename", "file", None, f"{target} -> {dst}", details={"fs": fs.name})
    flash(f"Renamed to {new}.", "success")
    return redirect(url_for("fm.index", path=parent))


@fm_bp.route("/files/mkdir", methods=["POST"])
@requires_permission("files.edit")
def mkdir():
    parent = _resolve(request.form.get("parent", ""))
    name = (request.form.get("name") or "").strip()
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        flash("Invalid folder name.", "danger")
        return redirect(url_for("fm.index", path=parent))
    target = parent.rstrip("/") + "/" + name if parent != "/" else "/" + name
    fs = current_fs()
    try:
        fs.mkdir(target)
    except Exception as e:
        flash(f"Mkdir failed: {e}", "danger")
        return redirect(url_for("fm.index", path=parent))
    audit.log("file.mkdir", "file", None, target, details={"fs": fs.name})
    flash(f"Created folder '{name}'.", "success")
    return redirect(url_for("fm.index", path=parent))


@fm_bp.route("/files/upload", methods=["POST"])
@requires_permission("files.edit")
def upload():
    parent = _resolve(request.form.get("parent", ""))
    fs = current_fs()
    if not fs.is_dir(parent):
        flash("Upload target is not a directory.", "danger")
        return redirect(url_for("fm.index", path=parent))

    f = request.files.get("file")
    if not f or not f.filename:
        flash("Pick a file to upload.", "danger")
        return redirect(url_for("fm.index", path=parent))

    f.stream.seek(0, os.SEEK_END); size = f.stream.tell(); f.stream.seek(0)
    if size > UPLOAD_SIZE_MAX:
        flash(f"File too large (>{_human_bytes(UPLOAD_SIZE_MAX)}).", "danger")
        return redirect(url_for("fm.index", path=parent))

    name = secure_filename(f.filename) or "upload"
    target = parent.rstrip("/") + "/" + name if parent != "/" else "/" + name
    try:
        fs.upload_stream(target, f.stream)
    except Exception as e:
        flash(f"Upload failed: {e}", "danger")
        return redirect(url_for("fm.index", path=parent))
    audit.log("file.upload", "file", None, target, details={"size": size, "fs": fs.name})
    flash(f"Uploaded {name} ({_human_bytes(size)}).", "success")
    return redirect(url_for("fm.index", path=parent))


@fm_bp.route("/files/download")
@requires_permission("files.view")
def download():
    target = _resolve(request.args.get("path", ""))
    fs = current_fs()
    if not fs.exists(target) or not fs.is_file(target):
        abort(404)
    audit.log("file.download", "file", None, target, details={"fs": fs.name})
    stream, fname = fs.open_send(target)
    return send_file(stream, as_attachment=True, download_name=fname)


@fm_bp.route("/files/zip")
@requires_permission("files.view")
def zip_download():
    """Local: build a zip in memory and stream it.
    Remote: stream a tar.gz produced by the remote box (one SSH exec)."""
    from servers import current_server
    target = _resolve(request.args.get("path", ""))
    fs = current_fs()
    if not fs.exists(target) or not fs.is_dir(target):
        abort(404)

    folder_name = target.rstrip("/").rsplit("/", 1)[-1] or "root"

    srv = current_server()
    if srv is not None:
        # Streaming tar.gz from the remote shell — much faster than SFTP-then-zip.
        import shlex
        # parent dir + folder so the archive contains the leaf folder
        parent = _parent_of(target) or "/"
        cmd = (f"cd {shlex.quote(parent)} && "
               f"tar --exclude='node_modules' --exclude='.git' --exclude='venv' "
               f"--exclude='__pycache__' --exclude='dist' --exclude='build' "
               f"-czf - {shlex.quote(folder_name)} 2>/dev/null")
        import ssh as ssh_helper
        client = ssh_helper.get_client(srv)
        stdin, stdout, stderr = client.exec_command(cmd)
        def gen():
            while True:
                chunk = stdout.read(64 * 1024)
                if not chunk: break
                yield chunk
        audit.log("file.zip_download_remote", "file", None, target, details={"server_id": srv.id})
        from flask import Response
        return Response(
            gen(),
            mimetype="application/gzip",
            headers={"Content-Disposition": f'attachment; filename="{folder_name}.tar.gz"'},
        )

    # Local zip
    p = Path(target)
    buf = io.BytesIO()
    file_count = 0; skipped = 0
    skip_names = {"node_modules", ".git", "venv", "__pycache__", ".cache", "dist", "build"}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, dirs, files in os.walk(p, topdown=True):
            dirs[:] = [d for d in dirs if d not in skip_names]
            for fname in files:
                abs_path = Path(root) / fname
                rel_path = abs_path.relative_to(p.parent)
                try:
                    zf.write(abs_path, rel_path); file_count += 1
                except (OSError, ValueError):
                    skipped += 1
    buf.seek(0)
    audit.log("file.zip_download", "file", None, target,
              details={"files": file_count, "skipped": skipped})
    return send_file(buf, as_attachment=True,
                     download_name=f"{folder_name}.zip",
                     mimetype="application/zip")


# ---------------------------------------------------------------------------
# Permissions (chmod)
# ---------------------------------------------------------------------------
@fm_bp.route("/files/chmod", methods=["POST"])
@requires_permission("files.edit")
def chmod():
    target = _resolve(request.form.get("path", ""))
    fs = current_fs()
    if not fs.exists(target):
        flash("Path no longer exists.", "danger")
        return redirect(url_for("fm.index"))

    parent_or_self = _parent_of(target) if fs.is_file(target) else target

    raw = (request.form.get("mode") or "").strip()
    if not raw:
        flash("No mode specified.", "danger")
        return redirect(url_for("fm.index", path=parent_or_self))

    try:
        mode = int(raw, 8)
    except ValueError:
        flash(f"Invalid mode '{raw}' — use octal like 755 or 644.", "danger")
        return redirect(url_for("fm.index", path=parent_or_self))
    if mode < 0 or mode > 0o7777:
        flash("Mode out of range.", "danger")
        return redirect(url_for("fm.index", path=parent_or_self))

    recursive = bool(request.form.get("recursive"))
    try:
        changed = fs.chmod(target, mode, recursive=recursive)
    except Exception as e:
        flash(f"chmod failed: {e}", "danger")
        return redirect(url_for("fm.index", path=parent_or_self))

    audit.log("file.chmod", "file", None, target,
              details={"mode": oct(mode), "recursive": recursive, "changed": changed, "fs": fs.name})
    flash(f"Changed permissions on {changed} item(s) to {oct(mode)[2:]}.", "success")
    return redirect(url_for("fm.index", path=parent_or_self))


@fm_bp.route("/files/search")
@requires_permission("files.view")
def search():
    """Recursive grep across a directory. Local: walk + Python regex.
    Remote: shell out to `grep -RHIn` over SSH (way faster than SFTP)."""
    import re as _re
    from servers import current_server
    root = _resolve(request.args.get("path", ""))
    q    = request.args.get("q", "")
    use_re    = request.args.get("regex") == "1"
    case_sens = request.args.get("case") == "1"
    max_results = max(1, min(int(request.args.get("max", 200) or 200), 1000))

    results = []
    truncated = False
    fs = current_fs()

    if not q or not fs.exists(root) or not fs.is_dir(root):
        return render_template("file_search.html",
            root=root, q=q, regex=use_re, case=case_sens,
            results=results, truncated=False, crumbs=_crumbs_str(root),
            default_root=_default_root_str())

    srv = current_server()
    if srv is not None:
        # Remote: shell out to grep.
        import shlex
        flags = "-RHIn"
        if not case_sens: flags += "i"
        if not use_re:    flags += "F"
        excludes = " ".join(f"--exclude-dir={shlex.quote(d)}"
                            for d in ("node_modules", ".git", "venv", "__pycache__", "dist", "build"))
        cmd = f"grep {flags} {excludes} -- {shlex.quote(q)} {shlex.quote(root)} 2>/dev/null | head -n {max_results}"
        try:
            import ssh as ssh_helper
            client = ssh_helper.get_client(srv)
            stdin, stdout, stderr = client.exec_command(cmd, timeout=20)
            for raw in stdout.read().decode("utf-8", errors="replace").splitlines():
                if not raw: continue
                # grep output: path:line:text
                parts = raw.split(":", 2)
                if len(parts) < 3: continue
                path, lineno, text = parts
                try: ln = int(lineno)
                except ValueError: continue
                results.append({"path": path, "rel": path[len(root):].lstrip("/"),
                                "line": ln, "text": text[:400]})
                if len(results) >= max_results:
                    truncated = True; break
        except Exception as e:
            return render_template("file_search.html",
                root=root, q=q, regex=use_re, case=case_sens,
                results=[], truncated=False, error=f"Remote grep failed: {e}",
                crumbs=_crumbs_str(root), default_root=_default_root_str())

        return render_template("file_search.html",
            root=root, q=q, regex=use_re, case=case_sens,
            results=results, truncated=truncated, files_scanned=None,
            crumbs=_crumbs_str(root), default_root=_default_root_str())

    # Local search (original implementation)
    flags = 0 if case_sens else _re.IGNORECASE
    try:
        pattern = _re.compile(q if use_re else _re.escape(q), flags)
    except _re.error as e:
        return render_template("file_search.html",
            root=root, q=q, regex=use_re, case=case_sens,
            results=results, truncated=False, error=f"Bad regex: {e}",
            crumbs=_crumbs_str(root), default_root=_default_root_str())

    rootp = Path(root)
    skip_dirs = {"node_modules", ".git", "venv", "__pycache__", ".cache", "dist", "build"}
    files_scanned = 0
    for dirpath, dirs, files in os.walk(rootp, topdown=True):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            full = Path(dirpath) / f
            try:
                if full.stat().st_size > 5 * 1024 * 1024: continue
                if not _looks_text(full): continue
                files_scanned += 1
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    for lineno, line in enumerate(fh, start=1):
                        if pattern.search(line):
                            results.append({
                                "path": str(full),
                                "rel":  str(full.relative_to(rootp)),
                                "line": lineno,
                                "text": line.rstrip("\n")[:400],
                            })
                            if len(results) >= max_results:
                                truncated = True; break
            except OSError:
                continue
            if truncated: break
        if truncated: break

    return render_template("file_search.html",
        root=root, q=q, regex=use_re, case=case_sens,
        results=results, truncated=truncated, files_scanned=files_scanned,
        crumbs=_crumbs_str(root), default_root=_default_root_str())


@fm_bp.route("/files/preview")
@requires_permission("files.view")
def preview():
    """Inline image / pdf preview without download header."""
    target = _resolve(request.args.get("path", ""))
    fs = current_fs()
    if not fs.exists(target) or not fs.is_file(target):
        abort(404)
    stream, fname = fs.open_send(target)
    return send_file(stream, mimetype=mimetypes.guess_type(fname)[0] or "application/octet-stream")
