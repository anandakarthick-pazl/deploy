-- App-wide settings (currently just SMTP). Single-row table — id is always 1.

CREATE TABLE IF NOT EXISTS app_settings (
    id              TINYINT UNSIGNED NOT NULL DEFAULT 1 PRIMARY KEY,
    smtp_host       VARCHAR(255) NULL,
    smtp_port       INT          NULL,
    smtp_user       VARCHAR(255) NULL,
    smtp_password   VARCHAR(255) NULL,
    smtp_use_tls    TINYINT(1)   NOT NULL DEFAULT 1,
    mail_from       VARCHAR(255) NULL,
    mail_from_name  VARCHAR(255) NULL,
    updated_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by      VARCHAR(64)  NULL,
    CONSTRAINT chk_singleton CHECK (id = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed an empty row so we always have one to update.
INSERT IGNORE INTO app_settings (id) VALUES (1);
