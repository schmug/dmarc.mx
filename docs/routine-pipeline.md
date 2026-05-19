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

## Kill switch

To pause both Routines without editing cloud config: apply the `pipeline-paused`
label to any open issue (e.g. the ledger issue #304). Both the implementer and
reviewer check for this label as step 0 — if found, they print a no-op message
and exit without mutating anything.

To resume: remove the `pipeline-paused` label from the issue. The next scheduled
run proceeds normally.

The label is created by `scripts/routine-pipeline/setup-labels.sh`. Idempotent:
re-running the script is safe.

## Audit trail

Every auto-merged PR receives a comment from the reviewer containing the full
gate verdict JSON (`{ pass: true, reasons: [] }`). Escalated PRs receive the
`reasons` array via the existing step 3d comment. Together these provide an
immutable per-PR record of why the gate passed or failed.

## Pilot validation log
Filled in during go-live. Scenario → expected → actual.
