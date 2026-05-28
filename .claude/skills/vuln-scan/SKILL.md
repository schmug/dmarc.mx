---
name: vuln-scan
description: >-
  Static source-code vulnerability scan for the dmarcheck TypeScript Cloudflare
  Worker. Reads a target directory (and THREAT_MODEL.md if present), spawns
  parallel review subagents per focus area, and writes VULN-FINDINGS.json +
  .md for /vuln-triage to consume. Read-only — no building, running, or
  network. Category menu is tuned for web/Worker bugs (SSRF, authz/IDOR, auth
  bypass, injection, XSS, signature verification, secrets, redirect posture),
  not C/C++ memory corruption. Use when asked to "scan for vulns", "review this
  code for security issues", "find bugs in <dir>", or as the step between
  /threat-model and /vuln-triage.
argument-hint: "<target-dir> [--focus <area>] [--single] [--extra <file>] [--no-score]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - Bash(rg:*)
  - Bash(grep:*)
  - Bash(ls:*)
  - Bash(wc:*)
  - Bash(head:*)
---

# /vuln-scan

Static vulnerability review of a source tree. Produces `VULN-FINDINGS.json`
(+ a human-readable `.md`) that `/vuln-triage` ingests directly.

**This skill does not execute code.** It reads source and reasons about it. No
`npm run`, no `wrangler`, no `fetch` against any host. There is no execution
oracle here — findings are *candidates*; `/vuln-triage` does the rigorous
verification and is where false positives get removed.

**Tool fallbacks.** Prefer the dedicated Glob and Grep tools. When they're
unavailable, fall back to the read-only Bash commands above: `rg --files
<scope>` / `ls -R` for enumeration, `rg -n` / `grep -rn` for search, `wc` /
`head` for sniffing. These are the ONLY permitted Bash commands; do not write
helper scripts or pipe target content into a shell interpreter.

## Arguments

- `<target-dir>` (required) — directory to scan (e.g. `src` or `.`).
- `--focus <area>` — scan only this focus area (repeatable). Skips recon.
- `--single` — no subagent fan-out; one sequential pass. For tiny targets or
  prompt debugging.
- `--extra <file>` — append the file's contents to the review brief (after the
  category list). Use for org-specific vuln classes or stack patterns.
- `--no-score` — skip the Step 3b confidence pass.

## Step 1 — Scope

1. Resolve `<target-dir>`. If it doesn't exist or has no source files, stop.
2. Look for `<target-dir>/THREAT_MODEL.md` **or** a `THREAT_MODEL.md` at the
   repo root. If present, parse section 3 "Entry points & trust boundaries"
   and section 4 "Threats" for focus areas and threat classes — this is the
   preferred scoping input.
3. If no THREAT_MODEL.md and no `--focus`: do a **quick recon** — list the
   source tree, read entry points and dispatch code (`src/index.ts`, route
   registration, middleware), and propose 3-10 focus areas using the pattern
   `<subsystem> (<dir/file>) — <key operations>`.
4. If `--focus` was given, use exactly those.

Tell the user the focus areas and the source-file count before fanning out.

## Step 2 — Fan out

Unless `--single`, spawn **one Task subagent per focus area** in parallel
(`subagent_type: "general-purpose"`). Cap at 10 concurrent. Each gets the
review brief below with its focus area filled in. On tiny targets (<15 source
files), fall through to `--single`.

### Review brief (per subagent)

```
You are conducting authorized static security review of source code for an
internet-facing TypeScript service running on Cloudflare Workers (Hono
framework, D1 database, KV/Cache API, outbound fetch + DNS). Your focus area:
**{focus_area}**. Other agents cover other areas; duplication is wasted effort.

TARGET: {target_dir}
TRUST BOUNDARY: {from THREAT_MODEL.md section 3, or "untrusted HTTP request →
application logic; authenticated session → another user's data"}

TASK: read the source in your focus area and identify candidate
vulnerabilities. This is static review — do NOT build, run, or probe anything.
Reason from the code.

REPORTING BAR: report anything with a plausible exploit path. Skip style
concerns and purely theoretical issues with no attack story — but if unsure
whether something is real, REPORT IT with a low confidence score rather than
dropping it. A downstream triage step does rigorous verification; your job is
to not miss things.

WHAT TO LOOK FOR (web / Cloudflare Worker classes — HIGH VALUE):

  AUTHENTICATION & AUTHORIZATION:
  - missing or incorrect ownership/tenant check (IDOR): a query, update, or
    delete reachable by an authenticated user that does NOT scope by the
    caller's user_id / org_id — cross-tenant read or write
  - auth bypass: JWT/session/bearer/API-key verification that can be skipped,
    forged, or downgraded; missing signature/expiry/issuer/audience checks;
    accepting unsigned/`alg:none`; comparing secrets non-constant-time
  - privilege escalation: free→paid feature gating that trusts client input;
    role checks that are advisory only
  - missing auth on a route that mutates or returns sensitive data

  SSRF & OUTBOUND REQUEST SAFETY:
  - attacker-controlled host/scheme in a server-side fetch (DNS lookups,
    MTA-STS / security-txt / well-known fetches built from the scanned domain)
  - redirect handling: a fetch that follows redirects (`redirect: "follow"` or
    default) where RFC/policy requires `redirect: "manual"` — note dmarcheck's
    MTA-STS invariant (must stay `manual`; do not regress to `error`/`follow`)
  - requests reaching internal/metadata addresses (169.254.169.254, .internal,
    localhost, RFC1918) without an allowlist

  INJECTION & OUTPUT SAFETY:
  - SQL injection: D1 query built by string concatenation/interpolation
    instead of `.prepare(...).bind(...)`; user input in a raw SQL fragment
  - XSS: user-influenced data (scanned domain, DNS record contents, query
    params, DB rows) interpolated into server-rendered HTML template literals
    WITHOUT esc(); raw user input inside an inline <script> block or data-URI;
    unescaped values in attributes/event handlers
  - header / response splitting, open redirect via unvalidated redirect target
  - regex built from user input; ReDoS in a regex applied to untrusted input

  CRYPTO, SECRETS & DATA EXPOSURE:
  - inbound webhook (Stripe, etc.) parsed/acted on BEFORE signature
    verification, or signature verified against attacker-suppliable data
  - HMAC / signature compare that is not constant-time; weak or missing nonce
  - secrets, API keys, tokens, or session ids logged or returned in error
    bodies / responses
  - PII (emails, customer ids) leaked across a trust boundary
  - tokens (unsubscribe, API key, reset) that are guessable, unscoped, or
    not invalidated

  LOGIC & STATE:
  - cache poisoning: a cache key that omits a security-relevant input, or
    serves one user's cached result to another
  - rate-limit bypass: limiter keyed on a spoofable header (e.g. raw
    X-Forwarded-For) or skippable path
  - TOCTOU on a security check; mass-assignment of privileged fields

  LOW VALUE — note briefly, keep looking:
  - missing defense-in-depth headers with no concrete exploit
  - error handling that returns a generic 500 (not a leak)

DO NOT REPORT (common false positives — skip even if technically present):
  - volumetric DoS / rate-limiting / resource-exhaustion — BUT ReDoS,
    algorithmic-complexity blowup, and unbounded fan-out driven by untrusted
    input ARE reportable
  - XSS where the value is passed through esc() / a framework auto-escape on
    every path to the sink
  - SSRF where the attacker controls only the path, not the host or scheme
  - findings in test files, fixtures, build scripts, docs, or .md
  - missing hardening / best-practice gaps with no concrete exploit
  - env vars, wrangler secrets, and CLI flags as the attack vector
    (operator-controlled, not attacker-controlled)
  - regex injection, log spoofing, self-XSS, tabnabbing, CSRF on logout
  - outdated third-party dependency versions
  - "predictable" identifiers that are actually UUIDv4 / 128-bit random tokens

{if --extra <file> was given: append its contents here verbatim}

For each finding you DO report, trace: where does the untrusted input enter,
what path reaches the sink, and what condition triggers it.

OUTPUT — one block per finding, nothing else:

<finding>
<id>F-{focus_idx:02d}-{n:02d}</id>
<file>{relative/path}</file>
<line>{line_number}</line>
<category>{idor | auth-bypass | privilege-escalation | ssrf | open-redirect | sql-injection | xss | header-injection | redos | webhook-signature-bypass | timing-unsafe-compare | secret-exposure | cache-poisoning | rate-limit-bypass | ...}</category>
<severity>{HIGH | MEDIUM | LOW}</severity>
<confidence>{0.0-1.0}</confidence>
<title>{one line}</title>
<description>{root cause, attacker control, trigger, data flow from entry to sink. Cite line numbers.}</description>
<exploit_scenario>{concrete attack: what request, from whom, causing what outcome}</exploit_scenario>
<recommendation>{specific fix: add the user_id predicate, verify the signature first, wrap in esc(), set redirect: manual, etc.}</recommendation>
</finding>

SEVERITY: HIGH = directly exploitable → auth bypass, cross-tenant data breach,
SSRF to internal services, RCE. MEDIUM = significant impact under specific
conditions. LOW = defense-in-depth.

If you find nothing reportable after a thorough read, emit a single <finding>
with category=none and a one-line note of what you covered.
```

## Step 3 — Collate

1. Collect `<finding>` blocks from all subagents. Drop `category=none`
   placeholders.
2. **Light dedupe** — same `file:line` + same category → keep the longer
   description, note the duplicate id. (Heavy dedupe is `/vuln-triage`'s job.)
3. Assign stable ids `F-001`, `F-002`, … in (severity desc, file, line) order.

## Step 3b — Confidence pass (skip if `--no-score`)

A cheap second-opinion read that **ranks** findings by signal quality.
**Nothing is dropped.** Spawn one Task subagent per finding in parallel:

```
You are giving ONE candidate security finding an independent confidence score.
You are NOT deciding whether to keep it — every finding is kept. You are
deciding how likely it is to survive rigorous triage.

FINDING:
{the full <finding> block}

TARGET: {target_dir} (you may Read/Grep inside it; do NOT execute)

STEP 1 — Re-read the cited code. Does it actually do what the description claims?
STEP 2 — Check against false-positive patterns (esc'd/auto-escaped output,
parameterized D1 bind present, path-only SSRF, operator-controlled env var,
test/fixture file, UUID/random token, missing-hardening-only). A match lowers
confidence sharply but does not auto-zero it.
STEP 3 — Score 1-10 that this is a real, actionable vulnerability:
  1-3  likely false positive or noise
  4-5  plausible but speculative
  6-7  credible, needs investigation
  8-10 high confidence, clear pattern

OUTPUT (exactly this, nothing else):
  CONFIDENCE: <1-10>
  REASON: <one line>
```

**Resolve:** overwrite each finding's `confidence` with the score (÷10) and
attach `confidence_reason`. Re-sort by (`confidence` desc, `severity` desc,
`file`, `line`) and reassign ids `F-001..`. Compute `low_confidence_count` =
findings with confidence < 0.4.

## Step 4 — Write output

Write **both** files to `<target-dir>/` (or repo root if scanning `.`):

**`VULN-FINDINGS.json`** — the `/vuln-triage` ingest shape:

```json
{
  "target": "<target-dir>",
  "scanned_at": "<iso8601>",
  "focus_areas": ["..."],
  "findings": [
    {
      "id": "F-001",
      "file": "src/db/scans.ts",
      "line": 88,
      "category": "idor",
      "severity": "HIGH",
      "confidence": 0.9,
      "title": "...",
      "description": "...",
      "exploit_scenario": "...",
      "recommendation": "...",
      "confidence_reason": "..."
    }
  ],
  "summary": {"total": 0, "high": 0, "medium": 0, "low": 0, "low_confidence": 0}
}
```

**`VULN-FINDINGS.md`** — human-readable: a summary table (id | severity |
category | file:line | title), then one `### F-NNN` section per finding.

## Step 5 — Hand back

1. Counts: N findings (H/M/L split, X low-confidence), across K focus areas,
   from M source files.
2. Top 3 by confidence, one line each.
3. Next step: `/vuln-triage <target-dir>/VULN-FINDINGS.json --repo <repo-root>`
4. Remind: these are **static candidates**, not verified.

> **Public-repo note (dmarcheck-specific):** `VULN-FINDINGS.*` and `TRIAGE.*`
> are gitignored. Do NOT commit them — a file enumerating live unpatched bugs
> in a public repo is an attacker roadmap. Report findings in-session; commit
> only the patches for confirmed issues.

## Constraints

- **Never execute target code.** No Bash beyond the read-only allowlist, no
  builds, no network. If asked to "reproduce" or "confirm with a PoC", decline.
- **Don't fabricate line numbers.** Every `file:line` must be something you
  Read or Grep'd. If unsure of the exact line, cite the function and say so.
- **Stay in `<target-dir>`.** Don't follow symlinks or `..` out of it.
- This skill **never drops a finding** — Step 3b only ranks. `/vuln-triage`
  does the N-vote verification where false positives are removed.

## Provenance

The focus-area recon pattern and per-finding confidence pass are adapted from
`anthropics/defending-code-reference-harness` (`.claude/skills/vuln-scan/`).
The memory-safety category tiers from the original are replaced with web /
Cloudflare Worker classes (IDOR, auth bypass, SSRF, XSS, webhook-signature
bypass, redirect posture) appropriate to this codebase; the DO-NOT-REPORT
exclusions and the `exploit_scenario`/`recommendation` output fields are
retained.
