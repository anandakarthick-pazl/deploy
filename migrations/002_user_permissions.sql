-- Add user role + per-repo permissions.

ALTER TABLE users
    ADD COLUMN is_admin TINYINT(1) NOT NULL DEFAULT 0 AFTER is_active;

-- Junction: which user can see/manage which repo. Admins ignore this and see everything.
CREATE TABLE IF NOT EXISTS user_repos (
    user_id     INT UNSIGNED NOT NULL,
    repo_id     INT UNSIGNED NOT NULL,
    granted_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, repo_id),
    CONSTRAINT fk_user_repos_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_repos_repo FOREIGN KEY (repo_id) REFERENCES repos(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Promote the bootstrap 'admin' user so the dashboard isn't suddenly inaccessible.
UPDATE users SET is_admin = 1 WHERE username = 'admin';
