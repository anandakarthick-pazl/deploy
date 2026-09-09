-- Track which command is running RIGHT NOW for the live log view.

ALTER TABLE deploys
    ADD COLUMN current_command VARCHAR(1024) NULL AFTER status;
