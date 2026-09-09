"""SQLAlchemy models for the deploy admin app."""

from datetime import datetime

import bcrypt
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import JSON

db = SQLAlchemy()


# Junction table for User <-> Repo permissions. Admins ignore this and see everything.
user_repos = db.Table(
    "user_repos",
    db.Column("user_id", db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    db.Column("repo_id", db.Integer, db.ForeignKey("repos.id", ondelete="CASCADE"), primary_key=True),
    db.Column("granted_at", db.DateTime, default=datetime.utcnow),
)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id                  = db.Column(db.Integer, primary_key=True)
    username            = db.Column(db.String(64), unique=True, nullable=False)
    email               = db.Column(db.String(255), unique=True, nullable=True)
    password_hash       = db.Column(db.String(255), nullable=True)
    is_active           = db.Column(db.Boolean, nullable=False, default=True)
    is_admin            = db.Column(db.Boolean, nullable=False, default=False)
    last_login_at       = db.Column(db.DateTime, nullable=True)
    reset_token         = db.Column(db.String(64), unique=True, nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)
    totp_secret         = db.Column(db.String(64), nullable=True)
    totp_enabled        = db.Column(db.Boolean, nullable=False, default=False)
    theme               = db.Column(db.String(16), nullable=False, default="auto")
    role_id             = db.Column(db.Integer, db.ForeignKey("roles.id", ondelete="SET NULL"), nullable=True)
    created_at          = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at          = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    role = db.relationship("Role", backref="users")

    # Repos this non-admin user is allowed to access. Admins ignore this list.
    repos = db.relationship("Repo", secondary=user_repos, lazy="joined", backref="users")

    def set_password(self, plaintext: str):
        self.password_hash = bcrypt.hashpw(
            plaintext.encode(), bcrypt.gensalt()
        ).decode()

    def check_password(self, plaintext: str) -> bool:
        if not self.password_hash:
            return False
        try:
            return bcrypt.checkpw(plaintext.encode(), self.password_hash.encode())
        except ValueError:
            return False

    @property
    def needs_password_setup(self) -> bool:
        return not self.password_hash

    def can_access_repo(self, repo) -> bool:
        if self.is_admin:
            return True
        return repo in self.repos

    def accessible_repos(self):
        """Query for repos this user can see. Admins see everything."""
        if self.is_admin:
            return Repo.query
        return Repo.query.join(user_repos).filter(user_repos.c.user_id == self.id)

    def has_permission(self, key: str) -> bool:
        """True if this user holds the named permission. Admins always do."""
        if self.is_admin:
            return True
        if not self.role_id or not self.role:
            return False
        return key in {rp.permission_key for rp in self.role.permissions}

    @property
    def permission_keys(self) -> set[str]:
        if self.is_admin:
            from permissions import PERMISSION_KEYS
            return set(PERMISSION_KEYS)
        if not self.role:
            return set()
        return {rp.permission_key for rp in self.role.permissions}


class Repo(db.Model):
    __tablename__ = "repos"
    id           = db.Column(db.Integer, primary_key=True)
    name         = db.Column(db.String(128), nullable=False)
    display_name = db.Column(db.String(128), nullable=True)
    owner        = db.Column(db.String(128), nullable=False)
    server_id    = db.Column(db.Integer, db.ForeignKey("servers.id", ondelete="SET NULL"), nullable=True)
    recipients   = db.Column(JSON, nullable=True)        # list[str]
    is_active    = db.Column(db.Boolean, nullable=False, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    branches = db.relationship(
        "Branch", backref="repo", cascade="all, delete-orphan", lazy="joined",
    )
    server = db.relationship("Server", foreign_keys=[server_id], lazy="joined")

    __table_args__ = (
        db.UniqueConstraint("owner", "name", name="uk_owner_name"),
    )


class Branch(db.Model):
    __tablename__ = "branches"
    id          = db.Column(db.Integer, primary_key=True)
    repo_id     = db.Column(db.Integer, db.ForeignKey("repos.id", ondelete="CASCADE"), nullable=False)
    name        = db.Column(db.String(128), nullable=False)
    path        = db.Column(db.String(512), nullable=False)
    commands         = db.Column(JSON, nullable=True)
    recipients       = db.Column(JSON, nullable=True)
    auto_deploy      = db.Column(db.Boolean, nullable=False, default=True)
    health_check_url = db.Column(db.String(512), nullable=True)
    schedule_cron    = db.Column(db.String(64), nullable=True)
    env_vars         = db.Column(JSON, nullable=True)              # dict[str, str]
    is_active        = db.Column(db.Boolean, nullable=False, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("repo_id", "name", name="uk_repo_branch"),
    )

    mirrors = db.relationship(
        "GitMirror", backref="branch", cascade="all, delete-orphan", lazy="selectin",
    )


class GitMirror(db.Model):
    """A second git remote a branch's code can be pushed to.

    Pushes are snapshots: the working tree minus `exclude_patterns` is copied
    into a cached clone of the target and committed as a single commit. History
    is deliberately not mirrored — excluded files still live in the source
    repo's earlier commits, so pushing real history would leak them.
    """

    __tablename__ = "git_mirrors"
    id               = db.Column(db.Integer, primary_key=True)
    branch_id        = db.Column(db.Integer, db.ForeignKey("branches.id", ondelete="CASCADE"), nullable=False)
    name             = db.Column(db.String(128), nullable=False, default="mirror")
    remote_url       = db.Column(db.String(512), nullable=False)
    target_branch    = db.Column(db.String(128), nullable=False, default="main")
    ssh_key_path     = db.Column(db.String(512), nullable=True)
    exclude_patterns = db.Column(JSON, nullable=True)          # list[str], rsync-style
    commit_template  = db.Column(db.String(255), nullable=True)
    push_on_deploy   = db.Column(db.Boolean, nullable=False, default=False)
    force_push       = db.Column(db.Boolean, nullable=False, default=False)
    is_active        = db.Column(db.Boolean, nullable=False, default=True)
    last_push_at     = db.Column(db.DateTime, nullable=True)
    last_status      = db.Column(db.String(16), nullable=True)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at       = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("branch_id", "name", name="uk_branch_mirror"),
    )

    @property
    def short_host(self) -> str:
        """'ssh.dev.azure.com/packworkx' — enough to recognise the target at a glance."""
        url = self.remote_url or ""
        if url.startswith("git@"):
            url = url.split("git@", 1)[1]
        for prefix in ("https://", "http://", "ssh://"):
            if url.startswith(prefix):
                url = url[len(prefix):]
        return url.replace(":", "/", 1)


class MirrorPush(db.Model):
    __tablename__ = "mirror_pushes"
    id             = db.Column(db.BigInteger, primary_key=True)
    mirror_id      = db.Column(db.Integer, db.ForeignKey("git_mirrors.id", ondelete="SET NULL"), nullable=True)
    branch_id      = db.Column(db.Integer, nullable=True)
    mirror_label   = db.Column(db.String(255), nullable=False)
    remote_url     = db.Column(db.String(512), nullable=False)
    target_branch  = db.Column(db.String(128), nullable=False)
    source_sha     = db.Column(db.String(64), nullable=True)
    pushed_sha     = db.Column(db.String(64), nullable=True)
    status         = db.Column(db.Enum("running", "success", "failed", "no_changes"),
                               nullable=False, default="running")
    triggered_by   = db.Column(db.String(128), nullable=True)
    trigger_type   = db.Column(db.String(24), nullable=False, default="manual")
    files_changed  = db.Column(db.Integer, nullable=True)
    files_excluded = db.Column(db.Integer, nullable=True)
    error          = db.Column(db.Text, nullable=True)
    log            = db.Column(db.Text, nullable=True)
    started_at     = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at    = db.Column(db.DateTime, nullable=True)

    mirror = db.relationship("GitMirror", backref="pushes")


class AppSettings(db.Model):
    """Single-row settings table. Always row id=1."""
    __tablename__ = "app_settings"
    id              = db.Column(db.Integer, primary_key=True, default=1)
    smtp_host         = db.Column(db.String(255), nullable=True)
    smtp_port         = db.Column(db.Integer, nullable=True)
    smtp_user         = db.Column(db.String(255), nullable=True)
    smtp_password     = db.Column(db.String(255), nullable=True)
    smtp_use_tls      = db.Column(db.Boolean, nullable=False, default=True)
    mail_from         = db.Column(db.String(255), nullable=True)
    mail_from_name    = db.Column(db.String(255), nullable=True)
    webhook_secret     = db.Column(db.String(255), nullable=True)
    slack_webhook_url  = db.Column(db.String(512), nullable=True)
    alerts_enabled     = db.Column(db.Boolean, nullable=False, default=False)
    cpu_threshold      = db.Column(db.Float, nullable=True)
    mem_threshold      = db.Column(db.Float, nullable=True)
    disk_threshold     = db.Column(db.Float, nullable=True)
    alert_min_seconds  = db.Column(db.Integer, nullable=False, default=60)
    company_name      = db.Column(db.String(128), nullable=True)
    company_logo_path = db.Column(db.String(512), nullable=True)
    updated_at        = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by        = db.Column(db.String(64), nullable=True)

    @classmethod
    def get(cls) -> "AppSettings":
        """Always return the singleton row, creating it if missing."""
        row = cls.query.get(1)
        if not row:
            row = cls(id=1)
            db.session.add(row)
            db.session.commit()
        return row


class Server(db.Model):
    """A remote server reachable over SSH. The 'local' option (no server
    selected) is implicit — represented as `None` everywhere we ask for the
    current server.
    """
    __tablename__ = "servers"
    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(128), unique=True, nullable=False)
    host            = db.Column(db.String(255), nullable=False)
    port            = db.Column(db.Integer, nullable=False, default=22)
    username        = db.Column(db.String(64), nullable=False)
    auth_type       = db.Column(db.Enum("password", "key"), nullable=False, default="password")
    password        = db.Column(db.Text, nullable=True)
    private_key     = db.Column(db.Text, nullable=True)
    key_passphrase  = db.Column(db.String(512), nullable=True)
    description     = db.Column(db.String(512), nullable=True)
    last_check_at   = db.Column(db.DateTime, nullable=True)
    last_check_ok   = db.Column(db.Boolean, nullable=True)
    last_check_msg  = db.Column(db.String(1024), nullable=True)
    created_by      = db.Column(db.String(64), nullable=True)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at      = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def label(self) -> str:
        return f"{self.username}@{self.host}:{self.port}"


class Role(db.Model):
    __tablename__ = "roles"
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    is_system   = db.Column(db.Boolean, nullable=False, default=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    permissions = db.relationship(
        "RolePermission", backref="role", cascade="all, delete-orphan", lazy="joined",
    )

    @property
    def permission_keys(self) -> set[str]:
        return {rp.permission_key for rp in self.permissions}


class RolePermission(db.Model):
    __tablename__ = "role_permissions"
    role_id        = db.Column(db.Integer, db.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_key = db.Column(db.String(64), primary_key=True)


class ApiToken(db.Model):
    """Bearer tokens for programmatic API access. We store SHA-256(token) only —
    the raw token is shown once at creation and never again."""
    __tablename__ = "api_tokens"
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name         = db.Column(db.String(128), nullable=False)
    token_hash   = db.Column(db.String(128), nullable=False, unique=True)
    token_prefix = db.Column(db.String(16), nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)
    last_used_ip = db.Column(db.String(45), nullable=True)
    revoked_at   = db.Column(db.DateTime, nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="api_tokens")

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None


class AuditLog(db.Model):
    __tablename__ = "audit_log"
    id           = db.Column(db.BigInteger, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username     = db.Column(db.String(64), nullable=True)     # snapshot — survives user deletion
    action       = db.Column(db.String(64), nullable=False)
    target_type  = db.Column(db.String(32), nullable=True)
    target_id    = db.Column(db.BigInteger, nullable=True)
    target_label = db.Column(db.String(255), nullable=True)
    details      = db.Column(JSON, nullable=True)
    ip_address   = db.Column(db.String(45), nullable=True)
    user_agent   = db.Column(db.String(255), nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User")


class ServerMetric(db.Model):
    __tablename__ = "server_metrics"
    id               = db.Column(db.BigInteger, primary_key=True)
    sampled_at       = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_pct          = db.Column(db.Float, nullable=True)
    mem_used_bytes   = db.Column(db.BigInteger, nullable=True)
    mem_total_bytes  = db.Column(db.BigInteger, nullable=True)
    mem_pct          = db.Column(db.Float, nullable=True)
    disk_used_bytes  = db.Column(db.BigInteger, nullable=True)
    disk_total_bytes = db.Column(db.BigInteger, nullable=True)
    disk_pct         = db.Column(db.Float, nullable=True)
    load_1m          = db.Column(db.Float, nullable=True)


class ServerAlert(db.Model):
    __tablename__ = "server_alerts"
    id           = db.Column(db.BigInteger, primary_key=True)
    metric       = db.Column(db.String(16), nullable=False)
    threshold    = db.Column(db.Float, nullable=False)
    peak_value   = db.Column(db.Float, nullable=True)
    started_at   = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at  = db.Column(db.DateTime, nullable=True)
    notified_at  = db.Column(db.DateTime, nullable=True)
    notes        = db.Column(db.Text, nullable=True)


class TerminalRun(db.Model):
    __tablename__ = "terminal_runs"
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username    = db.Column(db.String(64), nullable=True)
    command     = db.Column(db.String(2048), nullable=False)
    cwd         = db.Column(db.String(512), nullable=True)
    pid         = db.Column(db.Integer, nullable=True)
    exit_code   = db.Column(db.Integer, nullable=True)
    status      = db.Column(db.Enum("running", "done", "failed", "killed", "timeout"),
                            nullable=False, default="running")
    started_at  = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)


class TerminalSnippet(db.Model):
    __tablename__ = "terminal_snippets"
    id         = db.Column(db.Integer, primary_key=True)
    label      = db.Column(db.String(128), nullable=False)
    command    = db.Column(db.String(2048), nullable=False)
    cwd        = db.Column(db.String(512), nullable=True)
    created_by = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Deploy(db.Model):
    __tablename__ = "deploys"
    id            = db.Column(db.BigInteger, primary_key=True)
    repo_id       = db.Column(db.Integer, db.ForeignKey("repos.id", ondelete="SET NULL"), nullable=True)
    branch_id     = db.Column(db.Integer, db.ForeignKey("branches.id", ondelete="SET NULL"), nullable=True)
    repo_name     = db.Column(db.String(128), nullable=False)
    branch_name   = db.Column(db.String(128), nullable=False)
    build_number  = db.Column(db.Integer, nullable=True)
    pusher        = db.Column(db.String(128), nullable=True)
    commit_sha    = db.Column(db.String(64), nullable=True)
    commit_msg    = db.Column(db.String(512), nullable=True)
    old_sha       = db.Column(db.String(64), nullable=True)
    target_sha    = db.Column(db.String(64), nullable=True)   # rollback: reset to this sha instead of branch HEAD
    status          = db.Column(db.Enum("pending", "success", "failed", "awaiting"), nullable=False, default="pending")
    silent          = db.Column(db.Boolean, nullable=False, default=False)
    current_command = db.Column(db.String(1024), nullable=True)
    error           = db.Column(db.Text, nullable=True)
    log           = db.Column(db.Text, nullable=True)
    started_at    = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at   = db.Column(db.DateTime, nullable=True)
