-- Optional, user-chosen label shown in the sidebar instead of the raw repo name.
ALTER TABLE repos
    ADD COLUMN display_name VARCHAR(128) NULL AFTER name;
