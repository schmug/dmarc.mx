---
name: vuln-triage
description: >-
  Adversarially triage a batch of raw security-scanner findings (e.g. from
  /vuln-scan's VULN-FINDINGS.json). Verify each is real, collapse duplicates,
  re-rank by derived exploitability rather than the scanner's claimed severity,
  and route each to a component owner. Writes TRIAGE.json + TRIAGE.md sorted by
  what actually needs attention. Read-only — never executes target code or
  reaches the network. Named vuln-triage to avoid colliding with the repo's
  issue/PR /triage skill. Use when asked to "triage findings", "validate
  scanner output", "prioritize vulns", or "review the security backlog".
  Adapted for dmarcheck from anthropics/defending-code-reference-harness.
argument-hint: "<findings-path> [--auto] [--votes N] [--repo PATH] [--fp-rules FILE]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - AskUserQuestion
  - Bash(git log:*)
  - Bash(jq:*)
  - Bash(find:*)
  - Bash(ls:*)
  - Bash(wc:*)
---

# vuln-triage

Adversarial triage of raw security-scanner output. Four jobs: **verify** each
finding is real, **deduplicate** across runs and scanners, **rank** survivors
by derived exploitability rather than the scanner's claimed severity, and
**route** each to a component owner. Output is a short, ranked, owned list
instead of a raw dump.

Invoke with `/vuln-triage <findings-path> [--auto] [--votes N] [--repo PATH] [--fp-rules FILE]`.

**Do not execute target code.** No building, running, installing dependencies,
or sending requests. "Couldn't write a working PoC" is weak evidence of
non-exploitability — every conclusion comes from reading source. This applies
to the orchestrator and every subagent; include the constraint in every Task
prompt. For high-confidence HIGH findings, recommend a human-built PoC as a
follow-up instead. **Do not reach the network** (no CVE-DB or upstream fetches).

Bash is permitted only for `git log` (owner hints), `jq`/`find`/`ls`/`wc`
(ingest). The safety property is "no execution of target code."

## Arguments

- findings path (first positional, required): a `VULN-FINDINGS.json`, a
  directory of JSON files, a single `.json`/`.jsonl`, or a markdown report.
- `--auto`: skip the interview, use defaults. Default mode is **interactive**.
- `--votes N`: verifier votes per finding (default 3; 1 for a quick pass, 5
  for high-stakes batches).
- `--repo PATH`: path to the target codebase, read-only (default cwd).
  Verification needs source access; stop with an error if cited files aren't
  reachable.
- `--fp-rules FILE`: append the file's contents to the verifier's exclusion
  list (Phase 3a). For org-specific precedents.

## Phase 0 — Mode select & interview

Parse arguments. If interactive (default), use **AskUserQuestion** (one call,
up to 4 questions) to gather context that shapes verification and ranking.
Free-text via "Other" is expected; the options are prompts, not constraints.

1. **Environment & trust boundary** (single-select): `What kind of system, and
   where does untrusted input enter?` Default for dmarcheck:
   `Internet-facing web service (HTTP is untrusted; authenticated users are
   semi-trusted but must not cross tenants)`.
2. **Threat model** (multi-select): `What must never happen?` e.g.
   `Cross-tenant data leakage`, `Auth/billing bypass`, `SSRF to internal
   network`, `Secret/API-key exposure`, `Stored XSS in the report`. If a
   `THREAT_MODEL.md` exists at `--repo`, read its section 4 and pre-fill.
3. **Scoring standard** (single-select): default `Derived HIGH/MEDIUM/LOW from
   preconditions`.
4. **Noise tolerance** (single-select): `Precision: drop anything not
   majority-confirmed` (default) / `Recall: keep split votes as
   needs_manual_test` / `Ask me per-finding`.

**Auto-mode defaults:** environment = "internet-facing web service; treat any
externally-reachable entry point as untrusted"; threat model = empty; scoring =
derived; noise tolerance = precision.

Record answers as a `context` dict carried through every phase and echoed in
the output under `triage_context`.

## Phase 1 — Ingest & normalize

Turn the input into a flat `findings[]` with stable ids.

- **Detect shape:** `VULN-FINDINGS.json` → read `.findings[]`. A directory →
  Glob `**/*.json`. A bare list or `{findings|results|issues|vulnerabilities}`
  array → that array. Markdown → split on `##`/`###` headings and extract
  `file`/`line`/`category`/`severity`/`description` by pattern (best-effort,
  mark `source_format: "markdown_heuristic"`).
- **Normalize fields** (alias → canonical): `path|location.file` → `file`;
  `line_number|lineno` → `line`; `type|cwe|rule_id` → `category`;
  `level|priority|risk` → `severity`; `name|summary` → `title`;
  `details|body` → `description`; `confidence|score` → `scanner_confidence`
  (→ 0.0-1.0); `fix|remediation` → `recommendation`.
- **Attach** to each: `id` (`f001`, `f002`, … in ingest order, highest
  `scanner_confidence` first if present); `source`; `missing_fields`. If `file`
  is missing or doesn't resolve under `--repo`, mark **unlocatable**: emit
  directly with `verdict: false_positive`, `verify_verdict: needs_manual_test`,
  `confidence: 0`, rationale "no source location; human review required". Never
  confidently verdict a finding you couldn't locate, and never let it
  participate in dedup.
- **Locate the repo:** resolve `--repo` (default cwd). Check the first 5
  located findings resolve. If none do, stop and suggest a `--repo` value.

## Phase 2 — Deduplicate (before verification)

Collapse repeats so duplicates don't each burn N verifiers.

- **Deterministic pass (inline):** cluster findings with same `file` + same
  `category` (case-insensitive) + `line` within 10. Canonical = fewest
  `missing_fields`, ties to lowest id. Others get `verdict: duplicate`,
  `duplicate_of`, and drop out; record `absorbed: [...]` on the canonical.
- **Semantic pass (one subagent, only if >1 cluster survives):** spawn ONE Task
  (`subagent_type: "general-purpose"`). Two findings are DUPLICATES if fixing
  one fixes the other (same root cause, shared vulnerable helper reported per
  call site, one missing global control reported per endpoint, cause +
  consequence in the same path). DISTINCT if independent root causes even in
  the same file/category. Give it only `id | file:line | category | title` per
  finding; respond with `GROUP: <canonical> <- <dup>, <dup>` lines only.

Carry `candidates[]` = surviving canonicals.

## Phase 3 — Verify

For each candidate, N independent adversarial verifiers re-derive the claim
from the code and vote. Each starts from the code at the cited location (not
the scanner's description) and **never sees the other verifiers' reasoning**.

### 3a. Verifier prompt (assemble once, reuse per spawn)

```
You are a skeptical security engineer adversarially verifying ONE finding from
an automated scanner. Your default assumption is that the scanner is WRONG.
Re-derive the claim from the source code yourself and decide TRUE_POSITIVE or
FALSE_POSITIVE.

Read-only access scoped to {REPO_PATH} ONLY. Do NOT read/grep/glob outside it.
You may NOT build, run, test, install deps, or reach the network. Every
conclusion must come from reading source under {REPO_PATH}.

ENVIRONMENT (defines the trust boundary): {context.environment}

PROCEDURE — follow all four steps:
1. READ THE CODE AT THE CITED LOCATION YOURSELF. Open {file}:{line}. Don't
   trust the scanner's description; scanners misread code.
2. TRACE REACHABILITY BACKWARDS FROM THE SINK. Grep for callers; follow imports
   and route registration. Establish whether attacker-controlled input (per
   ENVIRONMENT) actually reaches this line. QUOTE the first call-site file:line.
   For an IDOR claim, confirm whether the query/handler is reachable by an
   authenticated user and whether it is scoped by the caller's identity.
3. HUNT FOR PROTECTIONS. Look for reasons the finding is WRONG: input
   validation/normalization upstream (normalizeDomain, parseSelectors); output
   escaping (esc()); parameterized D1 binds; auth/ownership middleware; a
   verified signature before the sink; redirect: manual; type/enum constraints;
   dead/test code.
4. STRESS-TEST EACH PROTECTION. Applied on EVERY path to the sink, or only the
   one traced? Any encoding/alternate entry point that bypasses it?

EXCLUSION RULES — if matched, FALSE_POSITIVE even if technically accurate; cite
the rule number:
  1. Volumetric DoS / missing rate-limiting (infra layer). ReDoS, algorithmic
     complexity, unbounded fan-out ARE valid.
  2. Test/dead/example/fixture code, or a crash with no security impact.
  3. Intended design (a documented, deliberate posture).
  4. Memory-safety concerns in a memory-safe language outside FFI.
  5. SSRF where the attacker controls only the path, not host or scheme.
  6. User input flowing into an AI/LLM prompt (prompt injection ≠ code vuln).
  7. Operator-controlled inputs as the vector (env vars, wrangler secrets, CLI
     flags) UNLESS ENVIRONMENT marks them untrusted.
  8. Client-side code flagged for a server-side vuln class.
  9. Outdated dependency versions (separate process).
 10. Weak random used for non-security purposes (jitter, cache spreading).
 11. Low-impact nuisance (log spoofing, CSRF on logout, self-XSS, tabnabbing,
     open redirect with no privileged sink, regex injection).
 12. Missing hardening / best-practice gap with no concrete exploit path
     (missing header, no audit log, permissive config not reached by untrusted
     input).
 13. XSS where the sink value passes through esc() (or a framework
     auto-escape) on every path. Raw-HTML escape hatches (interpolating user
     input into an inline <script> or unescaped attribute) are STILL valid.
 14. Identifiers unguessable by construction (UUIDv4, 128-bit+ random tokens)
     flagged as "predictable".
 15. Theoretical-only TOCTOU/race with no realistic window or no
     security-relevant state change.
 16. MTA-STS using redirect: "manual" flagged as wrong — that is the REQUIRED
     RFC 8461 §3.3 posture for dmarcheck, not a bug.

{if context.extra_fp_rules: append verbatim under "ORG-SPECIFIC RULES:"}

VERDICT — your response MUST end with EXACTLY:
  VERDICT: TRUE_POSITIVE | FALSE_POSITIVE | CANNOT_VERIFY
  CONFIDENCE: <0-10>
  REFUTE_REASON: <doesnt_exist|already_handled|implausible_trigger|
    intentional_behavior|misread_code|duplicate|not_actionable|n/a>
  EXCLUSION_RULE: <1-16, org rule, or none>
  FIRST_LINK: <file:line of the first call site you read, or "none found">
  RATIONALE: <2-5 sentences citing file:line evidence for reachability,
    protections found/absent, and why each held or didn't>

TRUE_POSITIVE requires ALL of: reachable from untrusted input per ENVIRONMENT;
protections insufficient or bypassable; real-world exploitation feasible.
FALSE_POSITIVE requires ANY of: unreachable; adequately protected on all paths;
scanner misread; an exclusion rule applies.
CANNOT_VERIFY: static reasoning genuinely hit its limit. Use sparingly.
```

### 3b. Spawn N verifiers per candidate, all in one message

For each candidate, build N Task calls (`subagent_type: "general-purpose"`,
`description: "verify {id} vote {k}/{N}"`). **Always set `subagent_type`** —
omitting it forks the orchestrator and the verifier inherits this
conversation's context, defeating independence. Append to each prompt:

```
FINDING UNDER REVIEW (treat as a CLAIM, not a fact):
  id: {id}   file: {file}   line: {line}   category: {category}
  severity (claimed): {severity}
  title: {title}
  description: {description}
  exploit_scenario: {exploit_scenario or "(not provided)"}

You are vote {k} of {N}. You have NOT seen the other verifiers' reasoning and
must NOT seek it. Work independently from the code.
```

Put all verifier Task calls in a **single message** so they run concurrently.
Don't background them. If `candidates × N > ~40`, shard into sequential batches
of ~40, each a single message. Findings with a `file` but no `line` get one
vote regardless of `--votes`.

### 3c. Tally

For each candidate, parse the trailing block from its N verifiers. Re-spawn a
verifier once if it errored or produced no parseable block; if the retry fails,
count it `cannot_verify`. Build `vote_breakdown`, `confidence` (mean of votes
agreeing with the majority), `exclusion_rule` (modal among FP votes),
`refute_reasons`, `first_links`, and `rationale` (highest-confidence vote on
the winning side, verbatim).

**Decide `verdict`:** majority TRUE_POSITIVE → `true_positive` (→ Phase 4);
majority FALSE_POSITIVE → `false_positive` (skip Phase 4); no majority →
precision: `false_positive` (note "split vote, dropped"); recall:
`true_positive` + `verify_verdict: needs_manual_test`; ask: collect splits into
one AskUserQuestion at end of Phase 3. Build `confirmed[]`.

## Phase 4 — Rank by exploitability (confirmed only)

Spawn one Task per confirmed finding (all in one message). The verdict is
settled; derive **how bad** independently of the claimed severity.

```
You are assigning severity to a CONFIRMED finding. Assume it's real. Derive how
bad, independently of the scanner's claim. Read/Grep {REPO_PATH}; do NOT execute.

ENVIRONMENT: {context.environment}
THREAT MODEL: {context.threat_model bullets or "(none)"}

FINDING: {id} {file}:{line} {category}, claimed {severity}
reachability: {first_links}   verifier rationale: {rationale}

STEP 1 — Enumerate EVERY precondition (auth state, config, prior request, race
window, attacker position). State the minimum ACCESS LEVEL (unauthenticated
remote / authenticated / local / physical).
STEP 2 — Derive severity:
  | Preconditions | Access required           | Severity |
  | 0             | Unauthenticated remote    | HIGH     |
  | 1-2           | Authenticated             | MEDIUM   |
  | 3+            | Local-only / no demo path | LOW      |
  Evaluate columns independently, take the LOWER. (0 preconditions but
  authenticated-only = MEDIUM. If preconditions ≥ 3, HIGH is almost surely wrong.)
STEP 3 — Threat-model match: if non-empty and this maps onto an entry, note it;
  a match may raise severity by ONE step, never two.
STEP 4 — Judge the claimed severity from the view of an engineer allergic to
  inflation. Score -5..+5 (+ = justified, - = inflated).
STEP 5 — verify_verdict: exploitable | mitigated (name the control) |
  needs_manual_test.

Respond with ONLY:
  PRECONDITIONS:
  - <one per line>
  ACCESS_LEVEL: <unauthenticated_remote|authenticated|local|physical>
  SEVERITY: <HIGH|MEDIUM|LOW>
  THREAT_MATCH: <entry or none>
  SEVERITY_ALIGNMENT: <-5..+5>
  VERIFY_VERDICT: <exploitable|mitigated|needs_manual_test>
  RANK_RATIONALE: <2-4 sentences>
```

Merge results onto each confirmed finding. Non-confirmed findings get
`severity: null`, `verify_verdict: null`, `preconditions: []`.

## Phase 5 — Route

Tag each confirmed true-positive with the most specific owner, first hit wins:

1. **CODEOWNERS.** Grep `--repo` for `.github/CODEOWNERS`; match the finding's
   `file` against its patterns (last match wins). Hint:
   `"CODEOWNERS: <pattern> -> <owner>"`.
2. **git log.** `git -C {REPO} log --format='%an' -n 50 -- "{file}" | sort |
   uniq -c | sort -rn | head -3`. Hint: `"top committer: <name>; no CODEOWNERS"`.
3. **Module fallback.** `"component: <top-level dir>/"`.

Attach as `owner_hint` (state the source). Non-true-positives get `null`.

## Phase 6 — Output

**Sort** all findings: by `verdict` (true_positive, then duplicate, then
false_positive); within true positives by severity (HIGH>MEDIUM>LOW) then
`confidence` desc then `severity_alignment` desc; others by id.

**Write `<repo>/TRIAGE.json`** — every input finding appears exactly once
(duplicates reference their canonical via `duplicate_of`); don't drop anything.
Shape:

```json
{
  "triage_completed": true,
  "triage_context": {"mode": "...", "environment": "...", "threat_model": ["..."], "scoring": "...", "noise_tolerance": "...", "votes_per_finding": 3, "repo": "..."},
  "summary": {"input_count": 0, "duplicates": 0, "false_positives": 0, "true_positives": 0, "needs_manual_test": 0, "by_severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}},
  "findings": [
    {"id": "f001", "title": "...", "file": "...", "line": 0, "category": "...",
     "claimed_severity": "HIGH", "verdict": "true_positive|false_positive|duplicate",
     "verify_verdict": "exploitable|mitigated|needs_manual_test|null",
     "confidence": 0.0, "severity": "HIGH|MEDIUM|LOW|null", "severity_alignment": 0,
     "preconditions": ["..."], "access_level": "...", "threat_match": "...|null",
     "rationale": "file:line-cited reachability/protections + ranking rationale",
     "vote_breakdown": {"true_positive": 0, "false_positive": 0, "cannot_verify": 0},
     "refute_reasons": ["..."], "exclusion_rule": null, "first_links": ["file:line"],
     "duplicate_of": null, "absorbed": ["..."], "owner_hint": "...", "missing_fields": ["..."]}
  ]
}
```

**Write `<repo>/TRIAGE.md`** — reviewer-facing. Title + summary line + `## Act
on these` (one `### [SEVERITY] title (id)` block per true_positive with
file:line, owner, verdict+votes, preconditions, threat match, why, reachability
evidence), then a `## Dropped` table (false positives with refute_reason +
exclusion rule; duplicates with `duplicate of X`; unlocatable).

**Terminal summary** (≤12 lines): `N findings → T confirmed, F false positives,
D duplicates`, the H/M/L counts, top HIGH + owner, top 3 refute reasons.

> **Public-repo note (dmarcheck):** `TRIAGE.*` and `VULN-FINDINGS.*` are
> gitignored. Don't commit them. Report confirmed findings in-session; commit
> only patches.

## Design notes

- **Dedupe before verify** cuts verifier spend by the duplication factor.
- **Verifier independence** is the load-bearing property: each gets a fresh
  context and only the one finding. Sharing context propagates blind spots.
- **`CANNOT_VERIFY`** maps to `needs_manual_test` under recall, a drop under
  precision.
- **Threat-model boost capped at one step** so a stated threat can't re-inflate
  a LOW back to HIGH and defeat the precondition rule.
- **No network, deliberately** — preserves the air-gapped-review property.

## Provenance

Adapted from `anthropics/defending-code-reference-harness`
(`.claude/skills/triage/`). The phase structure (ingest → dedupe → N-vote
adversarial verify → exploitability rank → route → output), the verifier and
ranking prompts, and the precondition→severity table are preserved. The
`checkpoint.py` resume machinery and ASan/pipeline-`report.json` ingest are
dropped (overkill for an ~80-file TS Worker); the exclusion rules are adjusted
for web/Worker classes, including rule 16 protecting the MTA-STS `redirect:
manual` invariant. Renamed `vuln-triage` to avoid colliding with this repo's
existing issue/PR `/triage` skill.
