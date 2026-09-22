# Staging

Staging is a second Worker, `dmarcheck-staging`, deployed from
`wrangler.staging.toml` by the manual **Deploy staging** workflow. It exists
to rehearse a change — especially a migration — against real Cloudflare
bindings before it reaches `dmarc.mx`.

## Deploying

Actions → **Deploy staging** → Run workflow. Inputs:

- `ref` — branch, tag or commit to deploy (default `main`).
- `migrate` — apply pending D1 migrations to `dmarcheck-db-staging` first
  (default on). Turn it off only to redeploy code against an unchanged
  schema.
- `bootstrap` — load `src/db/schema.sql` and record the existing migration
  series as applied (default off). Needed **once**, on an empty database.

## Bootstrapping an empty database

The migration series starts at `0002`. The base tables live in
`src/db/schema.sql`, applied out-of-band when production was created;
`migrate.yml` documents the same one-time bootstrap for production. So
`migrations apply` against an empty database fails on the first
`ALTER TABLE`, which is what the first staging deploy did: wrangler created
`d1_migrations`, migration `0002` failed, and no row was recorded, leaving
the database with no application tables.

Run **Deploy staging** once with `bootstrap: true`. It loads the schema, then
inserts one `d1_migrations` row per migration file, reproducing production's
tracking state exactly — production's table holds the same nine filenames.
After that the normal `migrate` step is a no-op and every future migration
reaches staging first, which is the point of the environment.

It refuses to run if a `users` table already exists. Re-running `schema.sql`
would be harmless, since every `CREATE` is `IF NOT EXISTS`, but re-seeding
`d1_migrations` would mask genuinely pending migrations — worse than a failed
deploy.

The workflow refuses to run if the staging KV namespace id is still the
committed placeholder, if the config has drifted into naming a production
resource, or if bindings have diverged from production without an exemption.

## How staging deliberately differs from production

| | production | staging | why |
|---|---|---|---|
| hostname | `dmarc.mx` custom domain | `staging.dmarc.mx` custom domain, plus the `workers.dev` subdomain | each hostname has its own Access application, so `ACCESS_AUD` differs |
| cron | `17 6 * * *` | none | a timer here would rescan the same 361 real domains twice a night for no signal |
| `EMAIL` binding | present | absent | staging must never mail real subscribers; `dispatchPendingAlerts()` records `skipped:no_binding` instead |
| traces | on, 1% | off | synthetic traffic, and traces are the path that would leak a DNSBL key |

Every other binding must match. `scripts/binding-parity/check.ts` runs in CI
and fails when they do not; the four deliberate differences above are
recorded in `scripts/binding-parity/exemptions.json`.

## Why not `[env.staging]`

Because a named environment does not inherit most top-level configuration.
Adding one `[env.*]` block on 2026-04-26 detached `dmarc.mx` from its zone
(PRs #203 → #206), and `wrangler.toml` now carries four warnings against
repeating it. A standalone config costs duplication, which the parity check
polices, and cannot affect a production deploy because production never
reads the file.

## Owner-only setup still outstanding

1. `wrangler kv namespace create INBOX_TOKENS_STAGING`, then commit the
   returned id over `REPLACE_WITH_STAGING_NAMESPACE_ID`.
2. The `staging.dmarc.mx` custom domain and its Access application (done 2026-09-22; sign in with a one-time PIN).
3. Nothing else: the workflow reuses the existing `CLOUDFLARE_API_TOKEN`,
   `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_D1_TOKEN` repository secrets.
