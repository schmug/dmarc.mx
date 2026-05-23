# AGENTS.md — dmarcheck

DNS email security analyzer (DMARC, SPF, DKIM, BIMI, MTA-STS).
Cloudflare Worker serving dual output: JSON API + interactive HTML report.
Live at dmarc.mx | Repo: github.com/schmug/dmarcheck

## Stack

- Hono framework on Cloudflare Workers
- TypeScript with `nodejs_compat` flag for `node:dns`
- Vitest for testing
- No build step for HTML — template literal strings in src/views/

## Commands

- `npm run dev` — local dev on port 8790
- `npm test` — vitest
- `npm run lint` — biome check (lint + format check)
- `npm run lint:fix` — biome auto-fix
- `npm run typecheck` — tsc --noEmit
- `npm run deploy` — wrangler deploy (use only if Git integration is disabled)
- Deployment is automatic via Cloudflare Git integration on push to main
- **Do NOT run `npm run deploy` after pushing** — it collides with the Git integration auto-deploy and causes intermittent stale deploys

## Architecture

- `src/index.ts` — Hono routes, content negotiation, rate limiting middleware
- `src/dns/client.ts` — DNS abstraction over node:dns (NXDOMAIN returns null)
- `src/analyzers/` — One module per protocol (dmarc, spf, dkim, bimi, mta-sts)
- `src/orchestrator.ts` — Runs all analyzers in parallel via Promise.allSettled
- `src/shared/scoring.ts` — Grade computation (F if no DMARC or p=none)
- `src/cache.ts` — SSE result caching
- `src/csv.ts` — CSV export for scan results
- `src/api/catalog.ts` + `src/api/openapi.ts` — Agent discovery (RFC 9727 linkset at `/.well-known/api-catalog`, OpenAPI 3.1 at `/openapi.json`)
- `src/views/` — HTML generation via template literals (styles.ts, scripts.ts, components.ts, html.ts, favicon.ts)
  - `components.ts` — `generateCreature(size, mood, partyHat?)` helper and `gradeToMood()` mapping
  - `markdown.ts` — markdown renderings served when `Accept: text/markdown` (landing, /check report, /scoring, /learn, /docs/api)
- `src/rate-limit.ts` — Cache API-based rate limiter (10 req/IP/60s)

## Agent discovery

- `/.well-known/api-catalog` — RFC 9727 linkset (`application/linkset+json`) pointing to OpenAPI + docs + health
- `/.well-known/agent-skills/index.json` — Cloudflare Agent Skills Discovery RFC v0.2.0 index. Lists `scan_domain` in three formats (markdown SKILL.md, OpenAPI, and MCP) with sha256 digests computed lazily over the served bytes
- `/.well-known/agent-skills/scan-domain/SKILL.md` — prose description of the `scan_domain` skill, served as `text/markdown`
- `/.well-known/mcp/server-card.json` — SEP-1649 MCP server card (pointing to the tool caller endpoint at `/mcp`)
- `/openapi.json` — OpenAPI 3.1 service description (`application/openapi+json`)
- `/docs/api` — Human-readable API reference (HTML, or markdown with `Accept: text/markdown`)
- Every HTML page ships a `Link` header advertising five relations (`api-catalog`, `https://agentskills.io/rel/index`, `service-desc`, `service-doc`, `status`)
- Content negotiation: `Accept: text/markdown` (or `?format=md`) on `/`, `/check`, `/scoring`, `/learn`, `/docs/api` returns a markdown rendering (noindexed)
- The client JS bundle registers a WebMCP `scan_domain` tool via `navigator.modelContext.provideContext()` when that API is available — silent no-op in browsers without WebMCP
- **Intentionally not published**: `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`. We are not an OAuth/OIDC issuer (WorkOS AuthKit is — we're the relying party), and our protected APIs use dmarcheck-minted bearer API keys (not OAuth-issued tokens, so RFC 9728 doesn't fit).

## Conventions

- Each analyzer is a standalone async function returning a typed result
- DNS errors (NXDOMAIN/NODATA) return null, not exceptions
- Status is `"pass"` | `"warn"` | `"fail"` for scored protocols, `"info"` for informational (MX)
- HTML is generated server-side as template literal strings, no JSX or build step
- Client-side JS is minimal (expand/collapse, tooltips) — inline script tag
- Dark/light theme with OS-aware switching and manual toggle; orange accent (#f97316)

## Brand / DMarcus

- **DMarcus** is the site mascot — an orange `@` character with googly eyes and three legs (pun on DMARC)
- Rendered by `generateCreature(size, mood, partyHat?)` in `src/views/components.ts`
- **Moods** map to scan grades via `gradeToMood()`: celebrating (A+/A), content (B), worried (C), scared (D), panicked (F)
- **Party hat** variant with dance animation for S (perfect) grade
- **Sizes:** lg (landing page logo), md (grade reactions, footer), sm (nav links)
- Appears in landing page, report header, loading state, error page, and nav
- **Easter egg:** idle-triggered (60s) creature walks around eating page elements, panics on interaction; respects `prefers-reduced-motion`
- Name appears in footer ("Guarded by DMarcus"), loading text, aria labels, and README
- **Social preview / OG image:** `scripts/generate-icons.mjs` rasterizes the OG SVG into `OG_IMAGE_PNG_BASE64` (served at `/og-image.png`, referenced by `og:image` / `twitter:image`) and writes `docs/github-social-preview.png` (1280×640). When the OG design changes, re-run the script, paste the new base64 into `src/views/favicon.ts`, commit the regenerated PNG, and re-upload it at GitHub → Settings → General → Social preview (that field has no API).

## Quality Gates

- Biome handles linting and formatting (`biome.json`)
- Codex hooks auto-format on edit and run tests + typecheck before commits
- Run `npm run lint` to check, `npm run lint:fix` to auto-fix

## Security

- **Runners:** All CI runs on GitHub-hosted `ubuntu-latest`. Do not reintroduce `self-hosted` — this is a public repo with `pull_request` triggers and self-hosted runners are a known RCE-on-runner pattern.
- **Action pinning:** All actions in `.github/workflows/*` are pinned by full commit SHA with a `# v<version>` comment. Dependabot (`.github/dependabot.yml`) keeps them up to date weekly.
- **Workflow permissions:** Every workflow declares an explicit top-level `permissions:` block (default `contents: read`). Elevate at the job level only where needed (e.g., `release.yml` for tag push).
- **Branch protection:** `main` requires the `check` status from CI to pass before merging, blocks force pushes and deletions, and requires a PR.
- **Secret scanning:** Secret scanning, push protection, non-provider patterns, and validity checks are all enabled in repo settings. Never commit `.env`, tokens, or wrangler secrets.
- **Input validation:** User-supplied domains are restricted to `[a-z0-9.-]` in `normalizeDomain` (`src/index.ts`). DKIM selectors are restricted to `[A-Za-z0-9._-]` in `parseSelectors`. HTML output never interpolates raw user input into inline `<script>` blocks — use `data-*` attributes via `esc()` instead.
- **MTA-STS fetch redirect mode:** `src/analyzers/mta-sts.ts` uses `redirect: "manual"` for the policy fetch. Do NOT change it to `"error"` — that throws in the Cloudflare Workers fetch runtime and breaks every scan (regressed twice via PRs #58 and #92). `"manual"` is RFC 8461 §3.3-compliant: redirects yield an opaque-redirect `Response` rejected by the existing `resp.type === "opaqueredirect"` / `!resp.ok` guards.
- **Reporting:** See `SECURITY.md` for the private disclosure process.

## Database migrations

- Migrations live in `src/db/migrations/`, named `NNNN_description.sql` with a monotonically-increasing 4-digit prefix. Pick the next prefix by listing the directory — never reuse one (PR #154 collided on `0003_` and had to be renamed).
- Every schema change updates **both** `src/db/schema.sql` (fresh-DB shape) and a new migration file (delta against prod). The migration is what runs against the live D1; `schema.sql` is what self-hosters apply on first install.
- **Additive-only**: new tables, new nullable or defaulted columns, new indexes. Column drops, renames, and type changes go through a two-PR expand/contract because `.github/workflows/migrate.yml` and the Cloudflare Git auto-deploy run in parallel — there is no ordering guarantee between schema change and code change.
- Migrations apply automatically: `.github/workflows/migrate.yml` runs `wrangler d1 migrations apply dmarcheck-db --remote` after CI passes on `main`. **Do not** run `npx wrangler d1 execute --file=...` by hand anymore.
- Wrangler tracks applied migrations in the `d1_migrations` table. If a migration is added, applied manually, and then automation tries to replay it, `ALTER TABLE ADD COLUMN` will fail. If you ever apply one out of band, also `INSERT INTO d1_migrations (name) VALUES ('NNNN_description.sql')` so the workflow skips it.

## Testing

- Tests in `test/` directory
- Mock DNS client for unit tests (`vi.mock`)
- Test scoring boundaries and analyzer parsing

## Releases

- Automated via GitHub Actions on push to main (after CI passes)
- CalVer versioning: vYYYY.M.serial (e.g., v2026.4.1)
- Changelog generated from commit history by git-cliff (`cliff.toml`)
- GitHub Releases page is the project changelog
- Tags are created automatically; do not create manual tags

## GitHub Issues

- After committing or merging work, check open issues (`gh issue list`) to see if any were resolved and should be closed
- When a commit addresses an issue, close it with a comment referencing the commit hash

## Documentation

- Keep `AGENTS.md` and `README.md` up to date when adding features, changing architecture, or modifying conventions
- `AGENTS.md` is for AI assistants and contributors; `README.md` is for users and self-hosters

## Cloudflare MCP

- Cloudflare MCP server (`@cloudflare/mcp-server-cloudflare`) is configured globally in `~/.Codex.json`
- Provides tools for managing Workers, DNS, KV, D1, R2, and more from Codex
- Account ID: `f0fc4ca5b74274f7ba892e6c9ec411a7`
