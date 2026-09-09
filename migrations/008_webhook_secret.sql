-- Webhook signing secret editable from the Settings page. NULL means "use the
-- env WEBHOOK_SECRET" (backwards-compatible).

ALTER TABLE app_settings
    ADD COLUMN webhook_secret VARCHAR(255) NULL AFTER mail_from_name;
