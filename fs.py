"""Filesystem abstraction — local POSIX or remote SFTP (paramiko).

Pick the right driver per request via `current_fs()`. The file manager view
code only needs to know the interface (`listdir`, `stat`, `read_text`,
`write_text`, `delete`, `rename`, `mkdir`, `chmod`, `download_path`,
`upload_stream`, `walk_for_zip`, `looks_text`, `is_dir`, `is_file`).
"""

import io
import os
import shutil
import stat as stat_module
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class Stat:
    is_dir:  bool
    is_link: bool
    size:    int
    mtime:   datetime
    mode:    int


class LocalFS:
    name = "local"

    def listdir(self, path: str):
        p = Path(path)
        for child in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            try:
                st = child.stat()
            except OSError:
                continue
            yield child.name, str(child), Stat(
                is_dir=child.is_dir(), is_link=child.is_symlink(),
                size=st.st_size if child.is_file() else 0,
                mtime=datetime.fromtimestamp(st.st_mtime),
                mode=st.st_mode & 0o7777,
            )

    def stat(self, path: str) -> Stat:
        p = Path(path)
        st = p.stat()
        return Stat(
            is_dir=p.is_dir(), is_link=p.is_symlink(),
            size=st.st_size if p.is_file() else 0,
            mtime=datetime.fromtimestamp(st.st_mtime),
            mode=st.st_mode & 0o7777,
        )

    def exists(self, path: str) -> bool: return Path(path).exists()
    def is_dir(self, path: str) -> bool: return Path(path).is_dir()
    def is_file(self, path: str) -> bool: return Path(path).is_file()

    def read_bytes(self, path: str) -> bytes:
        with open(path, "rb") as f: return f.read()

    def read_text(self, path: str) -> str:
        return self.read_bytes(path).decode("utf-8", errors="replace")

    def write_text(self, path: str, content: str) -> None:
        with open(path, "w", encoding="utf-8") as f: f.write(content)

    def delete(self, path: str) -> None:
        p = Path(path)
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p)
        else:
            p.unlink()

    def rename(self, src: str, dst: str) -> None:
        Path(src).rename(dst)

    def mkdir(self, path: str) -> None:
        Path(path).mkdir(parents=False, exist_ok=False)

    def chmod(self, path: str, mode: int, recursive: bool = False) -> int:
        n = 0
        os.chmod(path, mode); n += 1
        if recursive and Path(path).is_dir():
            for root, dirs, files in os.walk(path):
                for d in dirs:
                    try: os.chmod(os.path.join(root, d), mode); n += 1
                    except OSError: pass
                for f in files:
                    try: os.chmod(os.path.join(root, f), mode); n += 1
                    except OSError: pass
        return n

    def upload_stream(self, dest_path: str, stream) -> None:
        with open(dest_path, "wb") as f:
            shutil.copyfileobj(stream, f)

    def looks_text(self, path: str, probe: int = 8192) -> bool:
        try:
            with open(path, "rb") as f: chunk = f.read(probe)
            if b"\x00" in chunk: return False
            chunk.decode("utf-8")
            return True
        except (UnicodeDecodeError, OSError):
            return False

    def open_send(self, path: str):
        """Return an open binary stream + filename for Flask's send_file."""
        return open(path, "rb"), os.path.basename(path)


class RemoteFS:
    """SFTP-backed filesystem."""
    name = "remote"

    def __init__(self, server):
        from ssh import get_client
        self.server = server
        self.client = get_client(server)
        self.sftp = self.client.open_sftp()
        try:
            # PuTTY / OpenSSH usually have /tmp; this gets us a session-stable cwd
            self.sftp.chdir(".")
        except Exception:
            pass

    # ---------- read helpers ----------
    def listdir(self, path: str):
        for a in sorted(self.sftp.listdir_attr(path),
                        key=lambda x: (not stat_module.S_ISDIR(x.st_mode), x.filename.lower())):
            full = path.rstrip("/") + "/" + a.filename if path != "/" else "/" + a.filename
            is_dir  = stat_module.S_ISDIR(a.st_mode)
            is_link = stat_module.S_ISLNK(a.st_mode)
            yield a.filename, full, Stat(
                is_dir=is_dir, is_link=is_link,
                size=a.st_size or 0 if not is_dir else 0,
                mtime=datetime.fromtimestamp(a.st_mtime or 0),
                mode=(a.st_mode or 0) & 0o7777,
            )

    def stat(self, path: str) -> Stat:
        a = self.sftp.stat(path)
        is_dir  = stat_module.S_ISDIR(a.st_mode)
        is_link = False    # plain stat() follows symlinks
        return Stat(
            is_dir=is_dir, is_link=is_link,
            size=a.st_size or 0,
            mtime=datetime.fromtimestamp(a.st_mtime or 0),
            mode=(a.st_mode or 0) & 0o7777,
        )

    def exists(self, path: str) -> bool:
        try: self.sftp.stat(path); return True
        except FileNotFoundError: return False
        except IOError: return False

    def is_dir(self, path: str) -> bool:
        try: return stat_module.S_ISDIR(self.sftp.stat(path).st_mode)
        except Exception: return False

    def is_file(self, path: str) -> bool:
        try:
            m = self.sftp.stat(path).st_mode
            return stat_module.S_ISREG(m)
        except Exception:
            return False

    def read_bytes(self, path: str) -> bytes:
        with self.sftp.open(path, "rb") as f: return f.read()

    def read_text(self, path: str) -> str:
        return self.read_bytes(path).decode("utf-8", errors="replace")

    def write_text(self, path: str, content: str) -> None:
        with self.sftp.open(path, "w") as f:
            f.write(content)

    def delete(self, path: str) -> None:
        if self.is_dir(path):
            self._rmtree(path)
        else:
            self.sftp.remove(path)

    def _rmtree(self, path: str) -> None:
        # Recursive remove via SFTP — no native call, so we walk manually.
        for name, full, st in list(self.listdir(path)):
            if st.is_dir:
                self._rmtree(full)
            else:
                self.sftp.remove(full)
        self.sftp.rmdir(path)

    def rename(self, src: str, dst: str) -> None:
        self.sftp.rename(src, dst)

    def mkdir(self, path: str) -> None:
        self.sftp.mkdir(path)

    def chmod(self, path: str, mode: int, recursive: bool = False) -> int:
        n = 0
        self.sftp.chmod(path, mode); n += 1
        if recursive and self.is_dir(path):
            for name, full, st in list(self.listdir(path)):
                n += self.chmod(full, mode, recursive=True)
        return n

    def upload_stream(self, dest_path: str, stream) -> None:
        # Read in chunks so we don't load huge files into RAM
        with self.sftp.open(dest_path, "wb") as f:
            f.set_pipelined(True)
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk: break
                f.write(chunk)

    _TEXT_PROBE = 8192
    def looks_text(self, path: str, probe: int = _TEXT_PROBE) -> bool:
        try:
            with self.sftp.open(path, "rb") as f: chunk = f.read(probe)
            if b"\x00" in chunk: return False
            chunk.decode("utf-8")
            return True
        except (UnicodeDecodeError, IOError):
            return False

    def open_send(self, path: str):
        """Download to a buffer (or temp file) for send_file."""
        buf = io.BytesIO()
        with self.sftp.open(path, "rb") as f:
            while True:
                chunk = f.read(64 * 1024)
                if not chunk: break
                buf.write(chunk)
        buf.seek(0)
        return buf, path.rsplit("/", 1)[-1]


def current_fs():
    """Pick the right filesystem driver for this request."""
    from servers import current_server
    srv = current_server()
    if srv:
        return RemoteFS(srv)
    return LocalFS()
