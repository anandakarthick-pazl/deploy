-- API bearer tokens (programmatic deploy triggers, CI integration, etc.)
CREATE TABLE IF NOT EXISTS api_tokens (
    id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id       INT UNSIGNED NOT NULL,
    name          VARCHAR(128) NOT NULL,
    token_hash    VARCHAR(128) NOT NULL,           -- sha256 of the token; raw value shown once at creation
    token_prefix  VARCHAR(16)  NOT NULL,           -- first 8 chars for UI display
    last_used_at  DATETIME     NULL,
    last_used_ip  VARCHAR(45)  NULL,
    revoked_at    DATETIME     NULL,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_token_hash (token_hash),
    KEY idx_user (user_id),
    CONSTRAINT fk_api_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Audit log: who did what, with optional target + details
CREATE TABLE IF NOT EXISTS audit_log (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id      INT UNSIGNED NULL,                  -- null = system / unauthenticated
    username     VARCHAR(64)  NULL,                  -- snapshot (survives user deletion)
    action       VARCHAR(64)  NOT NULL,              -- e.g. "repo.create", "deploy.rollback"
    target_type  VARCHAR(32)  NULL,                  -- "repo" | "branch" | "user" | "settings" | "deploy"
    target_id    BIGINT UNSIGNED NULL,
    target_label VARCHAR(255) NULL,                  -- human-readable label
    details      JSON         NULL,
    ip_address   VARCHAR(45)  NULL,
    user_agent   VARCHAR(255) NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_user      (user_id, created_at),
    KEY idx_action    (action,  created_at),
    KEY idx_target    (target_type, target_id),
    KEY idx_created   (created_at),
    CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Per-branch environment variables (exported into the shell before commands run)
ALTER TABLE branches
    ADD COLUMN env_vars JSON NULL AFTER schedule_cron;

-- 2FA (TOTP) — optional second factor
ALTER TABLE users
    ADD COLUMN totp_secret  VARCHAR(64) NULL,
    ADD COLUMN totp_enabled TINYINT(1)  NOT NULL DEFAULT 0;

-- User UI preferences
ALTER TABLE users
    ADD COLUMN theme VARCHAR(16) NOT NULL DEFAULT 'auto';
