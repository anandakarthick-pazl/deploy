-- Repair for half-applied migration 012_roles_permissions.
-- The `roles` table was dropped (with FK checks off), leaving role_permissions
-- (47 rows) and users.role_id pointing at a missing parent -> 500 on /roles,/users.
-- schema_migrations still records 012 as applied, so migrate.py won't recreate it.
--
-- This recreates the table (matching 012 / models.Role) and restores rows 1-4.
-- Permissions were preserved in role_permissions; only names/descriptions were lost,
-- so they are inferred from each role's permission set and can be renamed in the UI.

CREATE TABLE IF NOT EXISTS roles (
    id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(64)  NOT NULL,
    description   VARCHAR(255) NULL,
    is_system     TINYINT(1)   NOT NULL DEFAULT 0,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_role_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO roles (id, name, description, is_system) VALUES
    (1, 'Admin',     'Full administrative access (recovered role — verify name)',            1),
    (2, 'Manager',   'Deploy, servers, files and token management (recovered role — verify name)', 0),
    (3, 'Developer', 'Branch edits, test builds and read access (recovered role — verify name)',   0),
    (4, 'Viewer',    'Read-only deploy/monitor/repo access plus tokens (recovered role — verify name)', 0);
