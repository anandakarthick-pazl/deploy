-- Rollback: lets a Deploy row record "reset to this specific commit instead of HEAD"
ALTER TABLE deploys
    ADD COLUMN target_sha VARCHAR(64) NULL AFTER old_sha;

-- Health check URL hit after commands succeed. Non-2xx flips the deploy to failed.
ALTER TABLE branches
    ADD COLUMN health_check_url VARCHAR(512) NULL AFTER auto_deploy;

-- Cron expression. NULL means no schedule. Parsed by APScheduler's CronTrigger.from_crontab.
ALTER TABLE branches
    ADD COLUMN schedule_cron VARCHAR(64) NULL AFTER health_check_url;

-- Outgoing Slack webhook URL. NULL disables Slack notifications.
ALTER TABLE app_settings
    ADD COLUMN slack_webhook_url VARCHAR(512) NULL AFTER webhook_secret;
