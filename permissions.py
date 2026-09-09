"""Permission keys + helpers.

Everything is defined in code (not in the DB) so adding a new menu item
is one line here + one `has_permission(...)` check in a template. Roles in
the DB just map to these keys.

is_admin is the superuser bypass — admins always pass every check.
"""

from functools import wraps

from flask import abort
from flask_login import current_user, login_required

# (key, label, category) — keep in display order; category drives grouping in the UI.
PERMISSIONS = [
    # Deployments
    ("deploys.view",        "View deploys + dashboard",         "Deploys"),
    ("deploys.test_build",  "Trigger test / manual builds",     "Deploys"),
    ("deploys.run_awaiting","Approve & run awaiting deploys",   "Deploys"),
    ("deploys.rollback",    "Roll back to an earlier build",    "Deploys"),
    ("deploys.delete",      "Delete deploy records",            "Deploys"),

    # Repos + branches
    ("repos.view",          "View repos and branches",          "Projects"),
    ("repos.create",        "Add new repos",                    "Projects"),
    ("repos.edit",          "Edit repo settings (recipients, display name, server)", "Projects"),
    ("repos.delete",        "Delete repos",                     "Projects"),
    ("branches.edit",       "Edit branches (commands, env vars, schedule, etc.)", "Projects"),
    ("branches.delete",     "Delete branches",                  "Projects"),
    ("mirrors.view",        "View mirror targets + push history", "Projects"),
    ("mirrors.push",        "Push a branch to a mirror repository", "Projects"),
    ("mirrors.manage",      "Add / edit / delete mirror targets", "Projects"),

    # Admin / config
    ("users.view",          "View users",                       "Admin"),
    ("users.manage",        "Create / edit / delete users + roles", "Admin"),
    ("audit.view",          "View audit log",                   "Admin"),
    ("settings.edit",       "Edit app settings (SMTP, branding, webhook secret)", "Admin"),

    # Operations
    ("monitor.view",        "View server monitor + history",    "Operations"),
    ("services.control",    "Start / stop / restart systemd services", "Operations"),
    ("files.view",          "Browse the file manager",          "Operations"),
    ("files.edit",          "Edit / delete / upload files",     "Operations"),
    ("terminal.use",        "Run terminal commands (one-shot)", "Operations"),
    ("terminal.shell",      "Open an interactive shell (PTY)",  "Operations"),

    # Multi-server
    ("servers.use",         "Switch between configured servers",        "Servers"),
    ("servers.manage",      "Add / edit / delete remote SSH servers",   "Servers"),

    # Account
    ("tokens.manage",       "Manage own API tokens",            "Account"),
]

# Easy lookups
PERMISSION_KEYS = [p[0] for p in PERMISSIONS]
PERMISSION_LABELS = {k: lbl for (k, lbl, _) in PERMISSIONS}


def grouped_permissions():
    """Return [(category, [(key, label), ...]), ...] preserving the order above."""
    by_cat = {}
    order = []
    for k, lbl, cat in PERMISSIONS:
        if cat not in by_cat:
            by_cat[cat] = []
            order.append(cat)
        by_cat[cat].append((k, lbl))
    return [(c, by_cat[c]) for c in order]


def has_permission(user, key: str) -> bool:
    """True if `user` may perform the action identified by `key`. Admins bypass."""
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if getattr(user, "is_admin", False):
        return True
    role = getattr(user, "role", None)
    if not role:
        return False
    # `permission_keys` is a relationship that returns a list of strings (see Role model)
    return key in (rp.permission_key for rp in role.permissions)


def requires_permission(key):
    """Decorator: route requires the given permission key."""
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if not has_permission(current_user, key):
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator
