# OSPS Baseline — declared deviations

This document records where dmarcheck intentionally deviates from the
[Open Source Project Security (OSPS) Baseline](https://baseline.openssf.org/)
and the compensating controls that manage the residual risk. Declaring
deviations explicitly is itself an OSPS expectation; this file is the canonical
home for them.

## QA-07.01 — Code change review before merge

**Control:** Changes to the project's source code should be reviewed by a second
person (someone other than the author) before being merged to the primary
branch.

**Deviation:** The `main` branch sets `required_approving_review_count = 0`. The
`main-protection` ruleset does **not** require a blanket approving review on
every PR. This is deliberate: autonomous [Claude Code Routines](routine-pipeline.md)
open and merge low-risk PRs unattended (sourced from triaged, `spec-approved`
issues), and a blanket two-person review requirement would make that pipeline
impossible for a single-maintainer project.

**Why we accept it:** dmarcheck is maintained by one person. A hard
second-reviewer requirement on every change would either halt the autonomous
routine pipeline entirely or reduce "review" to self-approval theater. Instead
of a blanket-but-hollow gate, we run a **path-scoped** human-review gate plus
deterministic automated gating, so review effort concentrates on the
security-sensitive minority of changes.

### Compensating controls

1. **Path-scoped human review (CODEOWNERS).** Any PR whose diff touches a
   security-sensitive path — CI/workflows, `package.json`/lockfile,
   `wrangler.toml`, `SECURITY.md`, `CLAUDE.md`, input validation
   (`src/index.ts`), rate limiting, DB migrations, analyzer modules,
   orchestration, or scoring — requires an approving review from a code owner
   via [`.github/CODEOWNERS`](../.github/CODEOWNERS) and
   `require_code_owner_review`. The riskiest changes always get a human.

2. **Deterministic fail-closed trust gate.** Before any routine auto-merge, a
   six-condition gate (`scripts/routine-gate/`) must pass: issue author in
   allowlist, `spec-approved` label, resolvable `Closes #N`, no risk-path hit,
   ≤250 lines / ≤8 files, and CI green with no scope drift. It fails closed —
   ambiguity escalates to the maintainer, never auto-merges. The gate is always
   executed from `main`, so a PR cannot weaken its own judge.

3. **Required CI status.** Every PR must pass the `check` status (lint,
   typecheck, tests, and a `npm audit --audit-level=high --omit=dev`
   supply-chain gate) before merge. The ruleset also blocks force-pushes and
   branch deletion on `main`.

4. **Per-merge audit trail.** Each auto-merged PR receives a comment containing
   the full gate verdict JSON, giving an immutable record of why each PR was
   allowed to merge.

### Residual risk and the path to closing it

The CODEOWNERS gate is only *enforcing* once the autonomous routine runs as a
distinct **non-admin** identity. Today the routines run with the maintainer's
admin credentials, and the repo Admin role bypasses the ruleset — so for
automation the CODEOWNERS gate is currently **advisory**. Closing this is
tracked as the bot-identity split,
[#299](https://github.com/schmug/dmarcheck/issues/299). The deterministic gate
(control 2) and required CI (control 3) apply regardless of identity and are the
active controls until #299 lands.

## Adding a new deviation

When a future change knowingly deviates from an OSPS criterion, add a section
here (criterion ID + control + deviation + why + compensating controls) rather
than leaving it undocumented. Reference this file from
[SECURITY.md](../SECURITY.md).
