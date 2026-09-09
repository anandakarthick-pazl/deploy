-- Push a branch's code to a second git remote (e.g. Azure DevOps), with an
-- exclude list so selected files never leave the primary repo.
--
-- A mirror is a *snapshot* push, not a history mirror: the working tree is
-- copied minus the excluded paths and committed as one commit on the target.
-- Real history cannot be mirrored while excluding files, because the excluded
-- content still exists in the source repo's past commits.

CREATE TABLE IF NOT EXISTS `git_mirrors` (
  `id`               int(10) unsigned NOT NULL AUTO_INCREMENT,
  `branch_id`        int(10) unsigned NOT NULL,
  `name`             varchar(128) NOT NULL DEFAULT 'mirror',
  `remote_url`       varchar(512) NOT NULL,
  `target_branch`    varchar(128) NOT NULL DEFAULT 'main',
  `ssh_key_path`     varchar(512) DEFAULT NULL,
  `exclude_patterns` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL
                     CHECK (json_valid(`exclude_patterns`)),
  `commit_template`  varchar(255) DEFAULT NULL,
  `push_on_deploy`   tinyint(1) NOT NULL DEFAULT 0,
  `force_push`       tinyint(1) NOT NULL DEFAULT 0,
  `is_active`        tinyint(1) NOT NULL DEFAULT 1,
  `last_push_at`     datetime DEFAULT NULL,
  `last_status`      varchar(16) DEFAULT NULL,
  `created_at`       datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at`       datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_branch_mirror` (`branch_id`,`name`),
  KEY `idx_mirror_branch` (`branch_id`),
  CONSTRAINT `fk_mirrors_branch` FOREIGN KEY (`branch_id`)
      REFERENCES `branches` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `mirror_pushes` (
  `id`             bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `mirror_id`      int(10) unsigned DEFAULT NULL,
  `branch_id`      int(10) unsigned DEFAULT NULL,
  `mirror_label`   varchar(255) NOT NULL,
  `remote_url`     varchar(512) NOT NULL,
  `target_branch`  varchar(128) NOT NULL,
  `source_sha`     varchar(64) DEFAULT NULL,
  `pushed_sha`     varchar(64) DEFAULT NULL,
  `status`         enum('running','success','failed','no_changes') NOT NULL DEFAULT 'running',
  `triggered_by`   varchar(128) DEFAULT NULL,
  `trigger_type`   varchar(24) NOT NULL DEFAULT 'manual',
  `files_changed`  int(10) unsigned DEFAULT NULL,
  `files_excluded` int(10) unsigned DEFAULT NULL,
  `error`          text DEFAULT NULL,
  `log`            mediumtext DEFAULT NULL,
  `started_at`     datetime NOT NULL DEFAULT current_timestamp(),
  `finished_at`    datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_push_mirror` (`mirror_id`),
  KEY `idx_push_started` (`started_at`),
  CONSTRAINT `fk_pushes_mirror` FOREIGN KEY (`mirror_id`)
      REFERENCES `git_mirrors` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
