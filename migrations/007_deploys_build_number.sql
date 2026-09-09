-- Sequential build number scoped to (repo, branch). Lets emails show
-- "[repo/branch] #N Deployed successfully" instead of just the commit sha.

ALTER TABLE deploys
    ADD COLUMN build_number INT UNSIGNED NULL AFTER branch_name;

-- Backfill existing rows: assign sequential numbers per (repo, branch) by
-- chronological order. Requires MariaDB 10.2+ / MySQL 8 (window functions).
UPDATE deploys AS d
JOIN (
    SELECT id,
           ROW_NUMBER() OVER (PARTITION BY repo_name, branch_name
                              ORDER BY started_at, id) AS rn
    FROM deploys
) AS ranked ON d.id = ranked.id
SET d.build_number = ranked.rn;

-- Enforce uniqueness so concurrent inserts can never end up with the same number.
ALTER TABLE deploys
    ADD UNIQUE KEY uk_repo_branch_build (repo_name, branch_name, build_number);
