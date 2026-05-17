-- Users table
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  email_domain TEXT NOT NULL,
  stripe_customer_id TEXT,
  email_alerts_enabled INTEGER NOT NULL DEFAULT 1,
  notify_on_change_only INTEGER NOT NULL DEFAULT 0,
  api_key_retirement_acknowledged_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Monitored domains
CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain TEXT NOT NULL,
  is_free INTEGER NOT NULL DEFAULT 0,
  scan_frequency TEXT NOT NULL DEFAULT 'monthly',
  last_scanned_at INTEGER,
  last_grade TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE(user_id, domain)
);

-- Scan history snapshots
CREATE TABLE IF NOT EXISTS scan_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  grade TEXT NOT NULL,
  score_factors TEXT,
  protocol_results TEXT,
  scanned_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Alert log
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  alert_type TEXT NOT NULL,
  previous_value TEXT,
  new_value TEXT,
  notified_via TEXT,
  acknowledged_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Webhook configurations
CREATE TABLE IF NOT EXISTS webhooks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  secret TEXT,
  format TEXT NOT NULL DEFAULT 'raw',
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Stripe subscription state (Phase 3 M2)
CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  stripe_subscription_id TEXT NOT NULL UNIQUE,
  stripe_price_id TEXT NOT NULL,
  status TEXT NOT NULL,
  current_period_end INTEGER,
  cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Idempotency ledger for Stripe webhook events
CREATE TABLE IF NOT EXISTS stripe_events (
  event_id TEXT PRIMARY KEY,
  received_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Hashed API keys (Phase 3 M3). Bearer tokens authenticate against the `hash`
-- column; raw values are shown once at generation time and never stored.
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT,
  prefix TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  last_used_at INTEGER,
  revoked_at INTEGER
);

-- Outbound webhook delivery audit log
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  webhook_id INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  url TEXT NOT NULL,
  status_code INTEGER,
  ok INTEGER NOT NULL,
  error TEXT,
  request_body_sha256 TEXT NOT NULL,
  attempted_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_domains_user_id ON domains(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_domain_id ON scan_history(domain_id);
CREATE INDEX IF NOT EXISTS idx_alerts_domain_id ON alerts(domain_id);
CREATE INDEX IF NOT EXISTS idx_alerts_unacked
  ON alerts(domain_id, created_at)
  WHERE acknowledged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_domains_last_scanned ON domains(last_scanned_at);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_user_time
  ON webhook_deliveries (user_id, attempted_at DESC);
