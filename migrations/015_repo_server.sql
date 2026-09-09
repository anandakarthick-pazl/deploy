-- Optional remote server for a repo. NULL = deploy on the local box (default).
ALTER TABLE repos
    ADD COLUMN server_id INT UNSIGNED NULL AFTER display_name,
    ADD KEY idx_repos_server (server_id),
    ADD CONSTRAINT fk_repos_server FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE SET NULL;
