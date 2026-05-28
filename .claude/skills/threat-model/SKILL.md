---
name: threat-model
description: >-
  Build a threat model for a target codebase and write THREAT_MODEL.md. Two
  modes: "bootstrap" derives a threat model from the code plus past
  vulnerabilities (git history, CVEs, issue tracker) with no owner present;
  "interview" walks an application owner through the four-question framework.
  Both write THREAT_MODEL.md in the shared schema (schema.md). Use when asked
  to "threat model", "build a threat model", "map the attack surface", or
  "what should we be worried about in this codebase". Read-only — never builds,
  runs, or fetches the target's live deployment. Adapted for dmarcheck (a
  TypeScript Cloudflare Worker) from anthropics/defending-code-reference-harness.
argument-hint: "[bootstrap|interview] <target-dir> [--vulns <file>] [--depth recon|full]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - AskUserQuestion
  - Bash(git:*)
  - Bash(gh api:*)
  - Bash(find:*)
  - Bash(ls:*)
---

# threat-model

A threat model answers **"what could go wrong with this system, who would do
it, and what should we do about it?"** independently of whether any specific
bug has been found yet. It is the map; vulnerability discovery is the metal
detector. A good threat model tells `/vuln-scan` where to look and tells
`/vuln-triage` which findings matter.

**Litmus test:** if patching one line of code makes an entry disappear, it was
a *vulnerability*, not a *threat*. A threat ("attacker exfiltrates another
tenant's scan history via a missing ownership check") still stands after every
known bug is fixed; a vulnerability ("`src/db/scans.ts:88` forgets the
`user_id` predicate") does not. This skill produces threats. Vulnerabilities
appear only as **evidence** that raises a threat's likelihood.

**Invocation:** `/threat-model [bootstrap|interview] <target-dir> [flags]`

---

## Step 0 — Safety preamble (always runs first)

This skill performs **static analysis only**. It reads source, git history,
and any vulnerability reports you supply, and writes one output file
(`<target-dir>/THREAT_MODEL.md`). It does **not** build, execute, fuzz, or
modify the target, and does **not** make network requests against the target's
live deployment (dmarc.mx or any other host).

Before proceeding, confirm and state in your first response:

1. The target directory exists and is a local checkout you can read.
2. You will not execute any code from the target directory.
3. If asked to "fetch CVEs", you will query only public advisory sources
   (GitHub Security Advisories via `gh api`, the project's own issue tracker)
   and never the target's live deployment.

The Bash tool is permitted **only** for `git` (history mining), `find`/`ls`
(layout), and `gh api` (public advisory lookup). The same restriction applies
to every subagent you spawn — pass it verbatim in each prompt.

---

## Step 1 — Route to a mode

Parse `$ARGUMENTS`:

| First token | Route to |
|---|---|
| `bootstrap` | Derive from code + history (below). The default for an existing codebase. |
| `interview` | Walk an owner through the four questions (below). |
| empty / other | Ask: **"Is someone who owns or built this system available to answer questions in this session?"** No → `bootstrap`. Yes → `interview` (or `bootstrap` first, then refine with them). |

Both modes write the same artifact (`THREAT_MODEL.md`, schema in `schema.md`)
so downstream consumers (`/vuln-scan`, `/vuln-triage`) don't need to know which
mode produced it. **Read `schema.md` immediately before you write the file.**

---

## Bootstrap mode (code + history)

Five stages: research swarm → synthesize sections 1-3 + vuln table →
generalize vulns into threat classes → STRIDE gap-fill → emit. Read-only and
language-agnostic.

### Inputs

- `<target-dir>` (required): local checkout.
- `--vulns <path>` (optional): past vulnerabilities — newline CVE/GHSA IDs, a
  CSV (`id,title,component,description`), a markdown pentest report, or a JSON
  array of `{id, description}`. If absent, the History miner + Advisory fetcher
  cover the same ground from git history and public advisories.
- `--depth recon|full` (optional, default `full`): `recon` runs stages 1-2
  only (fast context-building); still write all sections but leave sections 4,
  5, 8 as headers with a "run with --depth full to populate" note in section 6.

### Stage 1 — Research swarm

Gather everything needed for sections 1-3 and the vuln table, in parallel.
Spawn the agents below **in a single batch** with the Task tool
(`subagent_type: "general-purpose"`). Each gets a narrow brief, the absolute
path to `<target-dir>`, and the read-only restriction verbatim. On a small
target (<50 source files) or `--depth recon`, run the briefs yourself
sequentially instead.

| Agent | Brief | Returns |
|---|---|---|
| **Docs reader** | Read `README*`, `SECURITY.md`, `CHANGELOG*` / GitHub Releases, `CLAUDE.md` (and any `src/**/CLAUDE.md`), top-level `docs/`, and `package.json` / `wrangler.toml`. Summarize what the project is, who uses it, where it runs, and any security claims or invariants it documents. | Prose system description; list of self-documented security invariants. |
| **Surface mapper** | Grep the source for entry-point signatures (table below). For each hit name the surface, the `file:function`, and what crosses it. Bound it: skip `node_modules/`, generated code, test fixtures; cap ~5 hits per surface row. | Section 3 candidate rows: `{entry_point, description, trust_boundary, file_refs}`. |
| **Infra reader** | Read `wrangler.toml`, `.github/workflows/*`, `.github/dependabot.yml`, CODEOWNERS, and any binding/secret declarations (D1, KV, R2, secrets). Name (a) what identity/bindings the Worker runs with and what they reach, (b) any grant managed outside this tree, (c) CI trigger/permission posture. | Section 3 infra rows + section 4 candidate rows where the config itself is the finding. |
| **Asset finder** | Identify what the code protects or produces: sensitive data (API keys, session tokens, Stripe customer/subscription data, user emails, scan history), integrity of grades/results, service availability, and downstream consumers (API clients, agents). | Section 2 candidate rows: `{asset, description, sensitivity}`. |
| **History miner** | Derive 6-10 commit-message keywords for this stack (web service → `injection SSRF IDOR auth bypass redirect XSS escape secret signature verify`) on top of the base `CVE security vuln fix exploit`. Then `git -C <target-dir> log --all -i --grep='<base ∪ derived, \|-joined>' --oneline` and read the full message + diff of each hit. | Vuln rows: `{id (commit hash), title, component, class, vector}`. |
| **Advisory fetcher** | If `git -C <target-dir> remote get-url origin` is GitHub and `gh` is on PATH: `gh api /repos/{owner}/{repo}/security-advisories`. Else return "no public advisory source". | Vuln rows: `{id (CVE/GHSA), title, component, class, vector}`. |
| **Vuln-file parser** | Only if `--vulns <path>` was given. Parse into normalized rows. | Vuln rows: `{id, title, component, class, vector}`. |

**Surface-mapper grep targets** (pass this table; treat "Look for" as a seed,
extend with the framework's idioms — here Hono + Cloudflare Workers + D1):

| Surface | Look for |
|---|---|
| HTTP routes | Hono `app.get/post/...`, `.route(`, middleware registration, content negotiation |
| Auth / session | JWT verify, bearer/API-key checks, session cookies, `middleware.ts`, AuthKit/Access |
| Outbound fetch (SSRF) | `fetch(` to user-influenced hosts; MTA-STS / security-txt / DNS lookups; redirect mode |
| DB / query | D1 `.prepare(`, `.bind(`, raw SQL string building, per-user scoping predicates |
| Signature verify | Stripe webhook signature, HMAC (`shared/hmac.ts`), webhook delivery signing |
| HTML output | template-literal HTML in `src/views/`, `esc()` usage, `data-*` vs inline `<script>` |
| Input validation | `normalizeDomain`, `parseSelectors`, regex allowlists, query/path param parsing |
| Rate limit / cache | `rate-limit.ts`, Cache API keys, cache poisoning vectors |
| Secrets / config | `env.ts`, `wrangler.toml` vars/secrets, tokens in logs or error bodies |
| Supply chain | `package-lock.json`, pinned GitHub Actions SHAs, `curl \| sh` in scripts |

Collect each agent's structured return; synthesize in Stage 2.

### Stage 2 — Synthesize

This runs in the orchestrator (the join), not a subagent.

- **Section 1 — System context.** From the Docs reader + your glance at the
  tree: what it is, language, rough size, who deploys/embeds it, where it runs.
- **Section 2 — Assets.** Dedupe the Asset finder's rows, fill obvious gaps,
  assign `sensitivity`.
- **Section 3 — Entry points & trust boundaries.** Merge Surface mapper +
  Infra reader rows. Name each trust boundary ("unauth HTTP → application
  logic", "authenticated session → another user's data", "Worker → upstream DNS
  resolver"). For each, list which section-2 assets are reachable. **Every row
  here must get at least one threat in Stage 3 or 4** — the coverage invariant.
- **Vuln working table.** Concatenate History miner + Advisory fetcher +
  Vuln-file parser rows. Dedupe by `id`. For each, decide which section-3 entry
  point it traversed and confirm by reading the source. If a vuln's entry point
  isn't in section 3, the Surface mapper missed one — add it. This table stays
  in working notes; it becomes the `evidence` column in Stage 3.

### Stage 3 — Generalize: vulns → threats

- **Cluster** the vuln table by `(entry point, bug class, asset reached)`. Each
  cluster becomes **one** candidate threat. Apply the litmus test: would the
  threat statement still be true after every listed evidence item is patched?
  If not, zoom out.
- **Variant scan** (raises likelihood): grep for siblings — code paths with the
  same shape that weren't in the vuln list (other routes calling the same
  unsafe helper, other D1 queries missing the user predicate, other `fetch`
  calls without the redirect guard). More siblings → higher likelihood. Keep
  locations in working notes (they seed `/vuln-scan`); do **not** put
  `file:func` in the `evidence` cell — evidence is confirmed past vulns only.
- **Score** each cluster: `actor`, `impact`, `likelihood` (≥1 confirmed past
  vuln in this exact surface → at least `likely`; public exploit →
  `almost_certain`), `controls` (grep for mitigations: input validation, output
  escaping, parameterized D1 binds, auth middleware, redirect: manual, rate
  limiting), `status`. Also note one **class-level** `recommended_mitigation`
  per cluster (working notes → section 8). Write each cluster as a section-4 row.

### Stage 4 — Gap-fill (what past vulns can't show)

For **every section-3 entry point with no section-4 row yet**, walk STRIDE and
add the plausible ones:

| | Could an attacker… |
|---|---|
| Spoofing | …pretend to be a trusted source (forged webhook, spoofed JWT/session)? |
| Tampering | …modify data in transit or at rest (grade tampering, cache poisoning)? |
| Repudiation | …act without attributable logs? |
| Info disclosure | …read data they shouldn't (another tenant's scans, secrets in errors)? |
| DoS | …exhaust a resource (ReDoS, unbounded fan-out, expensive DNS)? |
| Elevation | …gain more privilege (free→paid, user→admin, anon→authed)? |

Also re-walk entry points that **do** have rows — is the existing threat the
only one live? Gap-fill threats have empty `evidence`; score likelihood from
technique prevalence and reachability. **The final section-4 table must contain
at least one empty-evidence row**, or this stage didn't run. Record ruled-out
threats in section 5 with reasons.

### Stage 5 — Emit

**Coverage check first:** every section-3 entry point must appear in at least
one section-4 `surface` cell (text match). Any gap means Stage 4 was
incomplete — fix it now. Then sort section 4 by (impact desc, likelihood desc)
and assign `id` = `T1, T2, …`.

Populate section 6 (open questions the code couldn't answer — deployment
context, intended actors, controls you couldn't verify) and section 8
(recommended class-level mitigations from Stage-3 notes: one row per control,
`threat_ids` it covers, `closes_class`, `effort`).

**Read `schema.md` now**, then write `<target-dir>/THREAT_MODEL.md` conforming
to it. Set section 7 provenance:

```
- mode: bootstrap
- date: <today>
- target: <target-dir> @ <git rev-parse --short HEAD or "not a git repo">
- inputs: <--vulns path, or "git-log + advisories mined">
- owner: unset
```

### Hand back

1. Path to the file.
2. Top 5 threats (id, threat, impact × likelihood).
3. Count of threats with evidence vs without (shows gap-fill ran).
4. Sibling locations from the variant scan, as leads for `/vuln-scan`.
5. Top 3 recommended mitigations (by closes_class, then effort asc).
6. Section-6 open questions, framed as "ask the owner".

---

## Interview mode (owner present)

Four-question framework, conversational, multi-turn via AskUserQuestion. Use
when the risk lives in business logic the code doesn't show, or for a design
review. Best paired *after* a bootstrap pass (`--seed THREAT_MODEL.md`) so the
owner refines a code-grounded draft instead of starting cold.

| Q | Question | Fills |
|---|---|---|
| Q1 | What are we working on? | section 1 context, section 2 assets, section 3 entry points |
| Q2 | What can go wrong? | section 4 threat rows (id, threat, actor, surface, asset) |
| Q3 | What are we going to do about it? | section 4 impact/likelihood/status/controls; section 5; section 8 |
| Q4 | Did we do a good job? | validate ranking, coverage check, section 6 open questions |

Ask one question at a time; record answers as a `context` dict echoed into the
output. Write the same `THREAT_MODEL.md` schema, provenance `mode: interview`,
owner = their name. After writing, print the path, top 5 threats, and any owner
statements you could not verify in code (these seed follow-up code review).

---

## Constraints

- **Never execute target code.** No `npm run`, no `wrangler`, no `fetch`
  against dmarc.mx, no builds. Static reasoning only.
- **Stay in `<target-dir>`.** Don't follow symlinks or `..` out of it.
- This skill produces **threats**, not verdicts on specific bugs. For
  candidate vulnerabilities, hand off to `/vuln-scan <target-dir>`.

## Provenance

Adapted from `anthropics/defending-code-reference-harness`
(`.claude/skills/threat-model/`). The C/C++/ASan pipeline and the
`checkpoint.py` resume machinery are dropped — for a ~80-file TS Worker the
swarm fits in one pass. The five-stage bootstrap, STRIDE gap-fill, litmus test,
and `schema.md` contract are preserved; the surface-mapper grep targets are
re-pointed at Hono / Cloudflare Workers / D1 idioms.
