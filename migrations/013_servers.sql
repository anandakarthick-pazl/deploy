-- Remote servers we can SSH into for terminal / file / monitor operations.
CREATE TABLE IF NOT EXISTS servers (
    id               INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name             VARCHAR(128) NOT NULL,
    host             VARCHAR(255) NOT NULL,
    port             INT          NOT NULL DEFAULT 22,
    username         VARCHAR(64)  NOT NULL,
    auth_type        ENUM('password','key') NOT NULL DEFAULT 'password',
    password         TEXT         NULL,        -- stored as-is (admin-managed); rotate via UI
    private_key      MEDIUMTEXT   NULL,        -- raw PEM/PPK contents
    key_passphrase   VARCHAR(512) NULL,
    description      VARCHAR(512) NULL,
    last_check_at    DATETIME     NULL,
    last_check_ok    TINYINT(1)   NULL,
    last_check_msg   VARCHAR(1024) NULL,
    created_by       VARCHAR(64)  NULL,
    created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_server_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
