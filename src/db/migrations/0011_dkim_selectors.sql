-- Per-domain custom DKIM selectors for cron rescans (issue #755).
-- Additive, backfill-free: NULL on all 337 existing rows preserves today's
-- behaviour (built-in COMMON_SELECTORS only) until an owner sets a value via
-- the add-domain form.
ALTER TABLE domains ADD COLUMN dkim_selectors TEXT;
