# CLAUDE.md — dmarcheck

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
- `src/dns/client.ts` — DNS abstraction over node:dns (NXDOMAIN returns null). `queryDnsbl` issues the reversed-IP DNSBL lookup; the query name embeds the Spamhaus DQS key, so it logs only a redacted form and never echoes the key in error messages (#587)
- `src/analyzers/` — One module per protocol (dmarc, spf, dkim, bimi, mta-sts, mx, security-txt, tls-rpt, dnssec, dane, dnsbl)
- `src/analyzers/dnsbl.ts` — DNSBL / IP-reputation analyzer (Spamhaus DQS free tier, #587). **Optional and credential-gated**: runs only when `DNSBL_DQS_KEY` (threaded from `env` through `scan`/`scanStreaming`) is present, and degrades to a clean no-op (`status:"info"`, `enabled:false` — never a `fail` or throw) when absent, so self-host deploys and the test pool are unaffected. Derives sending IPs from existing scan data (SPF `ip4` literals + `a`/`a:` hosts resolved to A records, plus MX exchanges) and queries each against `<reversed-ip>.<DQS_KEY>.zen.dq.spamhaus.net`. **INFORMATIONAL ONLY** — the result never feeds `src/shared/scoring.ts`, so it cannot change the letter grade (a scoring change is a separate, CODEOWNERS-gated decision). Respects the DoS budget: per-scan fan-out is hard-capped (`MAX_DNSBL_HOSTNAMES`/`MAX_DNSBL_IPS`) so it can't scale with attacker-controlled SPF/MX size, and every lookup draws from the shared `ScanBudget`. A `DnsLookupError` (SERVFAIL/timeout) or a `127.255.255.x` DQS return code surfaces as "could not verify," never a false "clean"
- `src/orchestrator.ts` — Runs all analyzers in parallel and isolates each one: a single analyzer rejection surfaces as a synthetic `status: "fail"` result (with an `analyzer_error` validation; `lookup_error.code` on the types that carry it) instead of aborting the whole scan. Implemented via a per-analyzer `settle` wrapper so one failure never takes down its siblings, for both `scan` and `scanStreaming` (#378). Both entrypoints also enforce two DoS backstops (GHSA-f828-8wf8-vqp2): a single overall deadline (one `AbortController` + `setTimeout`; each settled analyzer is raced against it via `raceDeadline`, degrading to its synthetic fallback on a breach) and one shared per-scan DNS-query budget (`ScanBudget`, threaded into every analyzer's DNS calls), so neither total outbound queries nor wall-clock can scale with attacker input. Limits come from `src/dns/scan-budget.ts` (`DEFAULT_SCAN_LIMITS`); both are overridable via the optional `limits` parameter (used by tests). A breach degrades gracefully — partial results with a note, never a throw — and `scanStreaming` still streams every protocol exactly once.
- `src/dns/scan-budget.ts` — `ScanBudget` (shared per-scan DNS-query pool + deadline-`AbortSignal`) and `DEFAULT_SCAN_LIMITS` (`maxDnsQueries`, `deadlineMs`). `queryTxt`/`queryMx`/`queryDoh` call `budget?.consume()` before any outbound query; exhaustion/deadline throw `ScanBudgetError`/`ScanDeadlineError` (both subclass `DnsLookupError`, so analyzers surface them as "could not verify" rather than a false "not configured"). `DnsLookupError` itself lives in `src/dns/errors.ts` (re-exported from `client.ts`) so the budget can subclass it without depending on the DNS client, which tests frequently mock.
- `src/shared/scoring.ts` — Grade computation (F if no DMARC or p=none). Knobs are configurable per-deploy via the `SCORING_CONFIG` env var (`src/shared/scoring-config.ts` parses/validates it; absent/invalid → shipped defaults, so hosted dmarc.mx is unaffected). `computeGrade`/`computeGradeBreakdown` take an optional `Partial<ScoringConfig>`; `scan`/`scanStreaming` require it (compile-time enforcement that every call site threads the active config)
- `src/shared/learn-anchors.ts` — Single source of truth for validation→learn-page "How to fix" deep links (#524): analyzers set the optional `Validation.learnAnchor`, `src/views/learn.ts` renders the matching `id=` attributes from the same constants, and `test/learn-anchors.test.ts` asserts both sides so anchor ids can't drift
- `src/cache.ts` — SSE result caching
- `src/inbox/` — Inbound test-email scanning (#417, first vertical slice). `tokens.ts` mints/validates 128-bit lowercase-hex capability tokens and builds/parses the **`inbox+<token>@dmarc.mx`** subaddress (`INBOX_DOMAIN`/`INBOX_LOCAL_PART` constants), strict-charset-validating `message.to` before it touches a KV key. `store.ts` is the KV layer (`INBOX_TOKENS` namespace, 30-min `expirationTtl`): `putPending`→`putVerdict` lifecycle, a per-identity live-token cap (`reserveLiveToken`, hashed identity index), `parseVerdict` (reads the verdict from `Authentication-Results`/`Received-SPF`/`DKIM-Signature` headers — no MIME body parse), the `email()` Worker entry (`handleInboundEmail`: no-op for unknown/expired/non-`inbox+` addresses, never throws), and `streamInboxResult` (the SSE poll loop). Routes live in `src/index.ts`: `GET /check/email` (issuance, rate-limited + live-token-capped) and `GET /api/check/email/stream` (SSE). The `email()` handler is added to the `handler` object inside the `Sentry.withSentry` wrapper. **Owner/zone step (not committable):** `dmarc.mx` has a single zone-wide catch-all owned by PhishSOC and Cloudflare allows only one per zone, so routing uses **subaddressing**: create one Email Routing rule `inbox@dmarc.mx` → "Send to a Worker" → dmarcheck and enable Subaddressing. A specific rule outranks the catch-all and `inbox+<token>@dmarc.mx` falls back to it, so only `inbox+*` reaches the Worker while everything else still flows to PhishSOC — one rule covers unlimited dynamic tokens (no per-token rules, no 200-rule limit). This is the repo's first KV namespace — the SSE scan cache (`src/cache.ts`) uses the Cache API, not KV. Deferred to follow-ups: cryptographic DKIM re-verification, MIME body parsing.
- `src/csv.ts` — CSV export for scan results
- `src/api/catalog.ts` + `src/api/openapi.ts` — Agent discovery (RFC 9727 linkset at `/.well-known/api-catalog`, OpenAPI 3.1 at `/openapi.json`)
- `src/views/` — HTML generation via template literals (styles.ts, scripts.ts, components.ts, html.ts, favicon.ts)
  - `components.ts` — `generateCreature(size, mood, partyHat?)` helper and `gradeToMood()` mapping
  - `markdown.ts` — markdown renderings served when `Accept: text/markdown` (landing, /check report, /scoring, /learn, /docs/api)
- `src/rate-limit.ts` — per-identity rate limiter (free 10/60s, pro 60/3600s). Primary path is an atomic Durable Object counter (`src/rate-limit-do.ts` `RateLimiterDO`, bound as `RATE_LIMITER`); its single-threaded RPC serializes increments so a concurrent burst under one identity can't exceed the ceiling (GHSA-v7qc-7qh8-h69g — replaced a non-atomic Cache-API read-modify-write). `checkRateLimit(identity, config, namespace?)` falls back to the in-memory limiter when the binding is absent (self-host deploys, Node test pool)
- `src/account/deletion.ts` — `deleteAccount(env, {id, email})` orchestrates self-serve account deletion (#550). Fixed order, each step degrading gracefully when its binding/secret is absent: **(1)** cancel an active Stripe subscription (`cancelSubscription`, `DELETE /v1/subscriptions/{id}`) — THROWS on failure so the caller aborts before any local delete (never orphan an active sub); **(2)** `deleteUser(db, session.sub)` — one cascading `DELETE FROM users` (domains→scan_history/alerts, api_keys, webhooks→webhook_deliveries, subscriptions); **(3)** `deleteWorkosUser` (`src/auth/workos.ts`, WorkOS Management API, needs `WORKOS_API_KEY`) — on failure logs + flags for retry, never rolls back the local delete; **(4)** best-effort confirmation email. The destructive flow lives behind `/dashboard/account/*`: a POST starts a step-up re-auth (`prompt=login`, delete intent in OAuth `state`), `/auth/callback` mints a short-lived single-use `delete_proof` (`src/auth/reauth.ts`) into an HttpOnly cookie when the re-authed identity matches `session.sub`, the confirm page + execute POST require that proof AND a typed confirmation (account email or literal `DELETE`). Target is ALWAYS `session.sub` — no user id is read from request input (IDOR guard).

## Agent discovery

- `/.well-known/api-catalog` — RFC 9727 linkset (`application/linkset+json`) pointing to OpenAPI + docs + health
- `/.well-known/agent-skills/index.json` — Cloudflare Agent Skills Discovery RFC v0.2.0 index. Lists `scan_domain` in two formats (markdown SKILL.md + OpenAPI) with sha256 digests computed lazily over the served bytes
- `/.well-known/agent-skills/scan-domain/SKILL.md` — prose description of the `scan_domain` skill, served as `text/markdown`
- `/.well-known/agent.json` — DNS-AID agent metadata contract (`application/json`), tracking IETF draft `draft-mozleywilliams-dnsop-dnsaid`. The DNS-layer equivalent of the surfaces above: `aid_version` (marks the doc DNS-AID-native vs. a Google A2A card), `identity`, `connection` (mcp / streamable-http → `/mcp`), `auth` (`none` — `scan_domain` is public + rate-limited), `capabilities.actions` describing `scan_domain` (`intent: query`, `semantics: read`). Built in `src/api/catalog.ts` (`buildAgentCard` / `AGENT_CARD_JSON`) off the same `CANONICAL_ORIGIN`. This is the **HTTP-layer half only** (#405); the matching DNS SVCB/TXT zone records (`_scan._mcp._agents.dmarc.mx`, `_index._agents.dmarc.mx`) are owner zone-admin work tracked in #461, and we do **not** grade `_agents` records as an analyzed protocol
- `/openapi.json` — OpenAPI 3.1 service description (`application/openapi+json`)
- `/docs/api` — Human-readable API reference (HTML, or markdown with `Accept: text/markdown`)
- Every HTML page ships a `Link` header advertising six relations (`api-catalog`, `https://agentskills.io/rel/index`, `https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid` → agent.json, `service-desc`, `service-doc`, `status`)
- Content negotiation: `Accept: text/markdown` (or `?format=md`) on `/`, `/check`, `/scoring`, `/learn`, `/docs/api` returns a markdown rendering (noindexed)
- The client JS bundle registers a WebMCP `scan_domain` tool via `navigator.modelContext.provideContext()` when that API is available — silent no-op in browsers without WebMCP
- **Intentionally not published**: `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/.well-known/mcp/server-card.json`. We are not an OAuth/OIDC issuer (WorkOS AuthKit is — we're the relying party), our protected APIs use dmarcheck-minted bearer API keys (not OAuth-issued tokens, so RFC 9728 doesn't fit), and we don't yet run a remote MCP server. Tracked: [#181](https://github.com/schmug/dmarcheck/issues/181) for the MCP server.

## Conventions

- Each analyzer is a standalone async function returning a typed result
- DNS record absence (NXDOMAIN/NODATA) returns null, not exceptions; resolver errors (SERVFAIL/timeout) throw `DnsLookupError` so callers surface them as `warn` + `lookup_error` instead of false "not configured"
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
- Claude Code hooks auto-format on edit and run tests + typecheck before commits
- Run `npm run lint` to check, `npm run lint:fix` to auto-fix

## Security

- **Runners:** All CI runs on GitHub-hosted `ubuntu-latest`. Do not reintroduce `self-hosted` — this is a public repo with `pull_request` triggers and self-hosted runners are a known RCE-on-runner pattern.
- **Action pinning:** All actions in `.github/workflows/*` are pinned by full commit SHA with a `# v<version>` comment. Dependabot (`.github/dependabot.yml`) keeps them up to date weekly.
- **Workflow permissions:** Every workflow declares an explicit top-level `permissions:` block (default `contents: read`). Elevate at the job level only where needed (e.g., `release.yml` for tag push).
- **Branch protection:** `main` is governed by the `main-protection` repository ruleset: requires a PR, requires the `check` status check, and blocks deletions and non-fast-forward pushes. CodeQL (`Analyze (actions)`, `Analyze (javascript-typescript)`) still runs on every PR but must **NOT** be re-added as a required status check — requiring those contexts deadlocked all merges (the "ruleset merge trap"); they were deliberately removed. `required_approving_review_count` is **0** by design — autonomous Claude Code routines (see the `claude-routines` repo) open and auto-merge PRs unattended. The human-review gate is **path-scoped**, not blanket: `require_code_owner_review` is on, so any PR touching a path in `.github/CODEOWNERS` (CI, lockfiles, security invariants, input validation, redirect posture, rate limiting, DB migrations, analyzer modules, orchestration, scoring) requires a code-owner approval before merge. This hybrid keeps routine PRs autonomous while forcing a human on the security-sensitive minority. **CODEOWNERS scope decision (issue #300):** `src/analyzers/**`, `src/orchestrator.ts`, and `src/shared/scoring.ts` are intentionally gated — a malicious-issue-driven PR adding a new analyzer or modifying orchestration/scoring could exfiltrate DNS data or manipulate grades without this gate. The ruleset's `bypass_actors` list is **empty** (verified 2026-06-25), so the gate is enforced for **every** identity, admin included — there is no admin bypass, and enforcement is already live (not pending #299). `gh pr merge --admin` does **not** override a ruleset's `require_code_owner_review` (the admin-override path only beats classic branch protection, not rulesets), so a gated PR can be merged **only** after a genuine code-owner approving review submitted through the GitHub UI. GitHub forbids self-approval, so the autonomous bot (#299) must run as an identity **distinct from the code owner** — it can neither self-approve nor admin-bypass a gated PR; a separate code owner has to approve it. Note `dismiss_stale_reviews_on_push: true`: any force-push (e.g. a Dependabot rebase to clear a lockfile conflict) dismisses an existing approval, so the PR must be re-approved before it can merge.
- **Secret scanning:** Secret scanning, push protection, non-provider patterns, and validity checks are all enabled in repo settings. Never commit `.env`, tokens, or wrangler secrets.
- **Input validation:** User-supplied domains are restricted to `[a-z0-9.-]` in `normalizeDomain` (`src/index.ts`). DKIM selectors are restricted to `[A-Za-z0-9._-]` in `parseSelectors`. HTML output never interpolates raw user input into inline `<script>` blocks — use `data-*` attributes via `esc()` instead.
- **Account deletion (#550, T1/T4/T12):** the deletion target is ALWAYS `session.sub` — `deleteUser`/`deleteAccount` never read a user id from request body/query/path (a `user_id`-accepting delete would be a cross-tenant account-nuke primitive). Honored only after BOTH a step-up re-auth (fresh WorkOS `prompt=login`; delete intent in OAuth `state`; a short-lived single-use `delete_proof` HMAC cookie minted in `/auth/callback` and bound to `session.sub`) AND a typed confirmation. `POST`-only (never `GET`); do NOT weaken the session cookie's `SameSite=Lax`. Operation order is load-bearing — Stripe cancel (abort on failure) → local hard-delete → WorkOS delete (flag-not-rollback on failure) → clear cookies → best-effort email; do not reorder or make the local delete depend on WorkOS/email success. A retained valid session JWT after the row is gone must stay graceful (logged-out / no data, never 500); `requireAuth` never reads the DB, so the tolerance lives in the handlers (`getUserById` null → redirect to `/auth/logout`).
- **Scan fan-out cap (DoS, GHSA-f828-8wf8-vqp2):** the orchestrator bounds every scan with one overall deadline AND one shared per-scan DNS-query budget (`ScanBudget` from `src/dns/scan-budget.ts`, threaded through every analyzer into `queryTxt`/`queryMx`/`queryDoh`). This is the umbrella over the per-analyzer caps (DKIM selectors, MTA-STS body, DMARC rua/ruf): combining a large selector list with a rua/ruf-stuffed `_dmarc` record on an attacker-controlled domain cannot drive total outbound DNS or wall-clock past the limits, all on one rate-limit token. Do NOT remove the budget threading or the deadline race when editing the orchestrator or analyzers; keep DNS query calls drawing from the shared pool. A breach degrades gracefully (partial results + a note), never throws. The DNSBL analyzer (`src/analyzers/dnsbl.ts`, #587) lives under this umbrella too: its per-scan IP fan-out is hard-capped (`MAX_DNSBL_HOSTNAMES`/`MAX_DNSBL_IPS`) and every lookup draws from the same shared pool, so a huge SPF/MX set can't blow the budget — keep both caps and the budget threading.
- **DNSBL DQS key (#587):** the optional `DNSBL_DQS_KEY` secret enables the DNSBL/IP-reputation analyzer; absent → a clean no-op (never a `fail`/throw), so config-less self-hosts and the test pool are unaffected. The key is a deploy secret embedded ONLY in the outbound DQS query name — NEVER expose it in responses, logs, error messages, or cache keys. `queryDnsbl` (`src/dns/client.ts`) breadcrumbs only a redacted `<reversed-ip>.<key>.<zone>` form and throws generic error messages (the underlying fetch error can echo the request URL, which carries the key). DNSBL output is **informational only** — it must NOT change the letter grade (that would trip the `src/shared/scoring.ts` CODEOWNERS gate); keep it out of `scoring.ts`.
- **MTA-STS fetch redirect mode:** `src/analyzers/mta-sts.ts` uses `redirect: "manual"` for the policy fetch. Do NOT change it to `"error"` — that throws in the Cloudflare Workers fetch runtime and breaks every scan (regressed twice via PRs #58 and #92). `"manual"` is RFC 8461 §3.3-compliant: redirects yield an opaque-redirect `Response` rejected by the existing `resp.type === "opaqueredirect"` / `!resp.ok` guards.
- **security.txt fetch redirect mode:** `src/analyzers/security-txt.ts` deliberately uses `redirect: "follow"` (not `"manual"`) — RFC 9116 §3 does not forbid following redirects, and real-world deployments commonly redirect (e.g. gov.uk → www.gov.uk → vdp.cabinetoffice.gov.uk). MTA-STS's `manual` posture is a security requirement of RFC 8461 §3.3 specifically; security.txt has no equivalent rule, so the user-friendly choice is to follow.
- **DCO sign-off & squash-merge default:** `.github/workflows/dco.yml` enforces a `Signed-off-by:` trailer on every non-bot PR commit (OSPS LE-01.01). The commit that lands on `main` keeps those trailers because the repo's squash default is `squash_merge_commit_message = COMMIT_MESSAGES` (GitHub pre-fills the squash body with the concatenated commit messages). **Do not change that setting to `PR_BODY`** — it would move the sign-off requirement to the PR description and reopen the gap. Bots are identified by `[bot]` in their author name, the `github-actions` author name, or the `cursoragent@cursor.com` author email (Cursor's cloud agent authors as "Cursor Agent" with no `[bot]` suffix); all other commits — including those using GitHub's privacy noreply email (`12345678+alice@users.noreply.github.com`) — are subject to DCO enforcement (#434). **Branch updates must not create a merge commit:** `main` requires linear history (`required_linear_history` in the `main-protection` ruleset) and the plain merge-commit method is disabled at the repo level (`allow_merge_commit = false`; only squash + rebase remain). This is load-bearing for DCO — GitHub's "Update branch (merge)" button authors a merge commit under the clicker's identity (e.g. a `…@users.noreply.github.com` noreply) with no `Signed-off-by`, which DCO rightly fails (every authored commit is checked; merge commits are not exempt). Linear history removes that surface structurally rather than teaching DCO to skip merge commits — it also eliminates "evil merge" content that could otherwise bypass review. Update branches via **rebase**, never merge. Do NOT re-enable `allow_merge_commit` or drop `required_linear_history`. As defense-in-depth, the workflow itself also skips merge commits (≥2 parents) when validating sign-off trailers (#597) — but `required_linear_history` remains the primary, structural guard.
- **External advisory reference (Project CodeGuard):** AI agents working in this repo may consult [Project CodeGuard](https://github.com/cosai-oasis/project-codeguard) (COSAI / OASIS, CC BY 4.0) as a generation-time breadth nudge for generic OWASP / crypto / authz / cloud / supply-chain patterns. It is **advisory only**. dmarcheck's primary defense is **enforced**, not advisory: CODEOWNERS path-scoping on security-sensitive paths, the input-validation regexes, SHA-pinned actions, the `npm audit` CI gate, secret scanning, and DCO. CodeGuard supplements breadth where those don't reach (cloud/platform/API-security, supply-chain governance) — it does **not** replace any enforced gate (#486). Do **not** import or copy CodeGuard rule text into this repo: keeping it a pointer (not a copy) avoids the CC BY 4.0 attribution obligation; revisit only if we later choose to import text.
- **Reporting:** See `SECURITY.md` for the private disclosure process.

## Database migrations

Database migration rules: see [src/db/CLAUDE.md](src/db/CLAUDE.md)

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

- Keep `CLAUDE.md` and `README.md` up to date when adding features, changing architecture, or modifying conventions
- `CLAUDE.md` is for AI assistants and contributors; `README.md` is for users and self-hosters

## Cloudflare MCP

- Cloudflare MCP server (`@cloudflare/mcp-server-cloudflare`) is configured globally in `~/.claude.json`
- Provides tools for managing Workers, DNS, KV, D1, R2, and more from Claude Code
- Account ID: `f0fc4ca5b74274f7ba892e6c9ec411a7`
