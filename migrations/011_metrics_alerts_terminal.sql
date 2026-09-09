-- Historical CPU/memory/disk samples (one row per minute via APScheduler).
CREATE TABLE IF NOT EXISTS server_metrics (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sampled_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cpu_pct         FLOAT         NULL,
    mem_used_bytes  BIGINT        NULL,
    mem_total_bytes BIGINT        NULL,
    mem_pct         FLOAT         NULL,
    disk_used_bytes BIGINT        NULL,
    disk_total_bytes BIGINT       NULL,
    disk_pct        FLOAT         NULL,
    load_1m         FLOAT         NULL,
    KEY idx_sampled_at (sampled_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Active / historical threshold alerts (CPU, memory, disk).
CREATE TABLE IF NOT EXISTS server_alerts (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    metric        VARCHAR(16)  NOT NULL,        -- 'cpu' | 'mem' | 'disk'
    threshold     FLOAT        NOT NULL,
    peak_value    FLOAT        NULL,
    started_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at   DATETIME     NULL,
    notified_at   DATETIME     NULL,
    notes         TEXT         NULL,
    KEY idx_metric_open (metric, resolved_at),
    KEY idx_started (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE app_settings
    ADD COLUMN alerts_enabled    TINYINT(1) NOT NULL DEFAULT 0,
    ADD COLUMN cpu_threshold     FLOAT NULL,
    ADD COLUMN mem_threshold     FLOAT NULL,
    ADD COLUMN disk_threshold    FLOAT NULL,
    ADD COLUMN alert_min_seconds INT  NOT NULL DEFAULT 60;

-- Terminal command runs (admin-only feature). Logs land in a file under
-- /var/log/packwork-deploy/terminal/<id>.log; the table tracks metadata.
CREATE TABLE IF NOT EXISTS terminal_runs (
    id           INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id      INT UNSIGNED NULL,
    username     VARCHAR(64)  NULL,
    command      VARCHAR(2048) NOT NULL,
    cwd          VARCHAR(512) NULL,
    pid          INT          NULL,
    exit_code    INT          NULL,
    status       ENUM('running','done','failed','killed','timeout') NOT NULL DEFAULT 'running',
    started_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at  DATETIME     NULL,
    KEY idx_user_time (user_id, started_at),
    CONSTRAINT fk_terminal_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Saved command snippets (reusable shortcuts in the terminal UI).
CREATE TABLE IF NOT EXISTS terminal_snippets (
    id           INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    label        VARCHAR(128) NOT NULL,
    command      VARCHAR(2048) NOT NULL,
    cwd          VARCHAR(512) NULL,
    created_by   VARCHAR(64)  NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_label (label)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
