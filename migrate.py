"""
Simple SQL migration runner.

Usage:
    python3 migrate.py up       # apply all pending migrations
    python3 migrate.py status   # show applied / pending

Migrations are .sql files in ./migrations/ named `<version>_<description>.sql`.
The version (everything before the first underscore) is what's tracked in the
schema_migrations table. Versions sort lexicographically, so use zero-padded
numbers like 001, 002, etc.
"""

import os
import re
import sys
from pathlib import Path

import pymysql

BASE_DIR = Path(__file__).resolve().parent
MIGRATIONS_DIR = BASE_DIR / "migrations"


def db_config():
    """Read DB settings from environment (same vars the Flask app uses)."""
    return dict(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "packworx_deploy"),
        autocommit=True,
        charset="utf8mb4",
    )


def list_migrations():
    """Return [(version, path), ...] sorted by version."""
    items = []
    for f in sorted(MIGRATIONS_DIR.glob("*.sql")):
        m = re.match(r"^(\d+)_", f.name)
        if not m:
            continue
        items.append((m.group(1), f))
    return items


def applied_versions(cur):
    try:
        cur.execute("SELECT version FROM schema_migrations")
        return {row[0] for row in cur.fetchall()}
    except pymysql.err.ProgrammingError:
        # table doesn't exist yet — first migration will create it
        return set()


def split_statements(sql):
    """Split a .sql file into individual statements.

    Strips standalone -- comment lines and inline -- comments before checking
    for a trailing semicolon (so `DEFAULT 60;  -- note` correctly terminates).
    Naive but adequate for our DDL.
    """
    import re as _re
    statements, buf = [], []
    for raw in sql.splitlines():
        # Strip an inline -- comment (but not inside a quoted string — none of our SQL has quoted dashes anyway).
        line = _re.sub(r"--.*$", "", raw).rstrip()
        if not line.strip():
            continue
        buf.append(line)
        if line.rstrip().endswith(";"):
            joined = "\n".join(buf).strip().rstrip(";").strip()
            if joined:
                statements.append(joined)
            buf = []
    if buf:
        joined = "\n".join(buf).strip()
        if joined:
            statements.append(joined)
    return statements


def cmd_up():
    conn = pymysql.connect(**db_config())
    try:
        with conn.cursor() as cur:
            applied = applied_versions(cur)
            pending = [(v, p) for v, p in list_migrations() if v not in applied]
            if not pending:
                print("[migrate] nothing to do (up to date)")
                return
            for version, path in pending:
                print(f"[migrate] applying {path.name}")
                for stmt in split_statements(path.read_text()):
                    cur.execute(stmt)
                cur.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s)",
                    (version,),
                )
                print(f"[migrate]   -> recorded {version}")
            print(f"[migrate] applied {len(pending)} migration(s)")
    finally:
        conn.close()


def cmd_status():
    conn = pymysql.connect(**db_config())
    try:
        with conn.cursor() as cur:
            applied = applied_versions(cur)
            for version, path in list_migrations():
                tag = "[applied]" if version in applied else "[pending]"
                print(f"  {tag} {version}  {path.name}")
    finally:
        conn.close()


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "up"
    if action == "up":
        cmd_up()
    elif action == "status":
        cmd_status()
    else:
        print(f"unknown action: {action}", file=sys.stderr)
        sys.exit(2)
