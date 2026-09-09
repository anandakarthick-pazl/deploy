-- User email + password reset tokens.

ALTER TABLE users
    ADD COLUMN email VARCHAR(255) NULL AFTER username,
    ADD UNIQUE KEY uk_email (email),
    ADD COLUMN reset_token VARCHAR(64) NULL,
    ADD COLUMN reset_token_expires DATETIME NULL,
    ADD UNIQUE KEY uk_reset_token (reset_token);

-- Company branding on the dashboard + login page.
ALTER TABLE app_settings
    ADD COLUMN company_name VARCHAR(128) NULL,
    ADD COLUMN company_logo_path VARCHAR(512) NULL;
