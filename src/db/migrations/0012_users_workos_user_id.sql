-- Track the WorkOS user id separately from users.id (#913). users.id is the
-- WorkOS id of the environment the account was created in; after a WorkOS
-- staging -> production cutover returning users keep their users.id (matched
-- by email) but get a new WorkOS id. NULL means "same as users.id".
ALTER TABLE users ADD COLUMN workos_user_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_workos_user_id
  ON users(workos_user_id) WHERE workos_user_id IS NOT NULL;
