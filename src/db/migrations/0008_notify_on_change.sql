-- Per-user opt-in to suppress scan.completed webhook when a cron rescan
-- produces an identical result vs. the previous scan (same grade + same
-- per-protocol statuses). DEFAULT 0 = off; existing behavior (notify every
-- cron scan) is preserved unless the user explicitly enables this setting.
ALTER TABLE users ADD COLUMN notify_on_change_only INTEGER NOT NULL DEFAULT 0;
