# Routine pipeline — operator guide

## Flow
Phone (interactive, /issue + spec-approved) → Routine #1 implementer (scheduled
~4h, batch 6, opens `claude/issue-N` PRs labelled `auto-impl`) → Routine #2
reviewer (+1h, runs `scripts/routine-gate/gate.ts` per PR, exit 0 = squash-merge,
exit 2 = `needs-you` + digest) → Claude-app digest for the rest.

## Trust gate (deterministic, scripts/routine-gate/)
Six conditions, fail-closed, all must hold to auto-merge: (1) issue author in
allowlist, (2) `spec-approved` label, (3) resolvable `Closes #N`, (4) no
risk-path hit, (5) ≤250 lines/≤8 files, (6) CI green + no scope drift. Branch
protection is the independent backstop. Note: the gate over-blocks on ambiguous
`Closes` refs and code-fenced examples (fails safe → escalates, never
auto-merges).

## Cap math (Max = 15 Routine runs/day)
4 cycles/day × (implementer + reviewer) = 8 runs/day. Implementer 6 issues/run ×
4 = up to 24 issues/day. One-off scheduled runs don't count against the cap.

## Registering the Routines (manual cloud step — no IaC for Routines)
For each of routine-implementer.md and routine-reviewer.md: in claude.ai/code →
Routines, create a scheduled routine, bind repo `schmug/dmarcheck`, paste the
prompt file contents, set schedule (implementer every 4h; reviewer offset +1h),
enable `claude/`-branch pushes for the implementer. Routine commits appear as
`schmug`.

## Kill switch (pipeline-paused label)

Both Routines check for the `pipeline-paused` repo label **before any other
action**. If the label is present, the Routine exits immediately with a no-op
message and mutates nothing (no PRs opened, no merges, no comments).

**To pause the pipeline:**
```
gh label create pipeline-paused --repo schmug/dmarcheck \
  --color 5319E7 --description "Kill switch: both Routines will no-op while this label exists" \
  --force
```
(If `setup-labels.sh` has already been run, the label already exists — you only
need to ensure it is present; `--force` makes this idempotent.)

**To resume the pipeline:**
```
gh label delete pipeline-paused --repo schmug/dmarcheck --yes
```

Once the label is deleted, the next scheduled Routine run resumes normal
operation automatically — no config change required.

## Audit trail (gate verdict comments)

On every auto-merged PR the reviewer Routine posts a comment containing the full
gate verdict JSON (`pass: true`, `reasons` array) as returned by
`scripts/routine-gate/gate.ts`. This creates an immutable per-PR record of
exactly why the gate passed the PR, supporting forensics after the fact.
Escalated PRs have always carried a `reasons` comment; auto-merges now carry an
equivalent comment.

## Pilot validation log
Filled in during go-live. Scenario → expected → actual.
