# Database migrations — dmarcheck

- Migrations live in `src/db/migrations/`, named `NNNN_description.sql` with a monotonically-increasing 4-digit prefix. Pick the next prefix by listing the directory — never reuse one (PR #154 collided on `0003_` and had to be renamed).
- Every schema change updates **both** `src/db/schema.sql` (fresh-DB shape) and a new migration file (delta against prod). The migration is what runs against the live D1; `schema.sql` is what self-hosters apply on first install.
- **Additive-only**: new tables, new nullable or defaulted columns, new indexes. Column drops, renames, and type changes go through a two-PR expand/contract because `.github/workflows/migrate.yml` and the Cloudflare Git auto-deploy run in parallel — there is no ordering guarantee between schema change and code change.
- Migrations apply automatically: `.github/workflows/migrate.yml` runs `wrangler d1 migrations apply dmarcheck-db --remote` after CI passes on `main`. **Do not** run `npx wrangler d1 execute --file=...` by hand anymore.
- Wrangler tracks applied migrations in the `d1_migrations` table. If a migration is added, applied manually, and then automation tries to replay it, `ALTER TABLE ADD COLUMN` will fail. If you ever apply one out of band, also `INSERT INTO d1_migrations (name) VALUES ('NNNN_description.sql')` so the workflow skips it.
