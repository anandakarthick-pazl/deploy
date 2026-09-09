-- Initial schema for the deploy admin dashboard.
-- Apply with: python3 migrate.py up

-- Tracks which migrations have run.
CREATE TABLE IF NOT EXISTS schema_migrations (
    version       VARCHAR(32) NOT NULL PRIMARY KEY,
    applied_at    DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Admin users for the dashboard. Password may be NULL on first-time setup —
-- the login flow forces a password set on first successful auth.
CREATE TABLE IF NOT EXISTS users (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(64)  NOT NULL,
    password_hash   VARCHAR(255) NULL,
    is_active       TINYINT(1)   NOT NULL DEFAULT 1,
    last_login_at   DATETIME     NULL,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- GitHub repos we deploy. `recipients` is a JSON array of email addresses
-- that gets emailed on each deploy under this repo (unless a branch overrides).
CREATE TABLE IF NOT EXISTS repos (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(128) NOT NULL,
    owner           VARCHAR(128) NOT NULL,
    recipients      JSON         NULL,
    is_active       TINYINT(1)   NOT NULL DEFAULT 1,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_owner_name (owner, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Per-branch deploy targets. `commands` is a JSON array of shell commands to run
-- after `git pull`. `recipients` (JSON array) overrides the repo-level list if set.
CREATE TABLE IF NOT EXISTS branches (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    repo_id         INT UNSIGNED NOT NULL,
    name            VARCHAR(128) NOT NULL,
    path            VARCHAR(512) NOT NULL,
    commands        JSON         NULL,
    recipients      JSON         NULL,
    is_active       TINYINT(1)   NOT NULL DEFAULT 1,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_repo_branch (repo_id, name),
    CONSTRAINT fk_branches_repo FOREIGN KEY (repo_id) REFERENCES repos(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Audit log of every deploy attempt. `log` keeps the trailing N chars of
-- command output for the history view.
CREATE TABLE IF NOT EXISTS deploys (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    repo_id         INT UNSIGNED NULL,
    branch_id       INT UNSIGNED NULL,
    repo_name       VARCHAR(128) NOT NULL,
    branch_name     VARCHAR(128) NOT NULL,
    pusher          VARCHAR(128) NULL,
    commit_sha      VARCHAR(64)  NULL,
    commit_msg      VARCHAR(512) NULL,
    old_sha         VARCHAR(64)  NULL,
    status          ENUM('pending','success','failed') NOT NULL DEFAULT 'pending',
    error           TEXT         NULL,
    log             MEDIUMTEXT   NULL,
    started_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at     DATETIME     NULL,
    KEY idx_repo_branch_time (repo_name, branch_name, started_at),
    KEY idx_started_at (started_at),
    CONSTRAINT fk_deploys_repo   FOREIGN KEY (repo_id)   REFERENCES repos(id)    ON DELETE SET NULL,
    CONSTRAINT fk_deploys_branch FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
