-- Per-branch auto-deploy switch. When 0, pushes create an 'awaiting' deploy
-- record that must be approved manually from the dashboard.

ALTER TABLE branches
    ADD COLUMN auto_deploy TINYINT(1) NOT NULL DEFAULT 1 AFTER recipients;

-- Add 'awaiting' to the deploys.status enum.
ALTER TABLE deploys
    MODIFY COLUMN status ENUM('pending','success','failed','awaiting')
        NOT NULL DEFAULT 'pending';
