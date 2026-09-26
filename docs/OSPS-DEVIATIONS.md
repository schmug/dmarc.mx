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

1. **Path-scoped human review (CODEOWNERS).** Ruleset `main-protection`
   (id `14716629`) has `require_code_owner_review: true` and no bypass actors.
   GitHub enforces code-owner review per path for identities that are not code
   owners; `andonos[bot]` merges on owned paths were refused with 405. The gate
   is inert only for @schmug's own merges. The owned paths are exactly the
   entries in [`.github/CODEOWNERS`](../.github/CODEOWNERS), narrowed on
   2026-09-22. Paths not listed there merge with zero reviews by design: the
   ruleset's `required_approving_review_count: 0` is the intended autonomy
   carve-out, not a deviation.

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

### Residual risk

The path-scoped review gate protects the listed paths for identities that are
not code owners. Its exception is @schmug's own merges. The ruleset's zero
approving-review count intentionally leaves paths outside CODEOWNERS available
for autonomous merges without review; this is the autonomy carve-out.

## Related OSPS controls (passing)

QA-07.01 is a deviation, not a posture. Several adjacent OSPS controls are met,
which is part of why the path-scoped review model above is acceptable:

- **BR-01.01 (input sanitization)** — user-supplied domains are constrained to
  `[a-z0-9.-]` (`normalizeDomain`) and DKIM selectors to `[A-Za-z0-9._-]`; HTML
  output never interpolates raw user input into inline `<script>` (see the
  Input-validation notes in `CLAUDE.md` and [THREAT_MODEL.md](../THREAT_MODEL.md)).
- **AC-04.01 (least-privilege CI)** — every GitHub Actions workflow declares an
  explicit top-level `permissions:` block defaulting to `contents: read`, with
  elevation only at the job level where required, and all actions are pinned by
  full commit SHA.

## Adding a new deviation

When a future change knowingly deviates from an OSPS criterion, add a section
here (criterion ID + control + deviation + why + compensating controls) rather
than leaving it undocumented. Reference this file from
[SECURITY.md](../SECURITY.md).
