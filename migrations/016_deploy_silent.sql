-- Per-deploy "silent" flag: when set, the worker suppresses the success/failure
-- email and the Slack post. Used by the "Test build (silent)" UI button so
-- ad-hoc test runs don't spam the configured recipients.
ALTER TABLE deploys
    ADD COLUMN silent TINYINT(1) NOT NULL DEFAULT 0 AFTER status;
