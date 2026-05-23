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

### Gate-from-main invariant (defence-in-depth)
The reviewer Routine always runs gate code from the **`main` branch**, not from
the PR being evaluated. It uses `git show main:scripts/routine-gate/<file>` to
extract each gate source file into a temporary directory, symlinks the repo's
`node_modules` there, then runs `npx tsx <tmpdir>/gate.ts`. The temp dir is
removed after each PR.

This means a PR that edits `scripts/routine-gate/` is still evaluated by the
unmodified `main` gate — it cannot weaken its own judge. The denylist entry for
`scripts/routine-gate/**` (added in #311) is the primary control; running from
`main` is belt-and-suspenders. PR *metadata* (diff, files, CI status) continues
to be fetched live via `gh`, unaffected by this change.

## Cap math (Max = 15 Routine runs/day)
4 cycles/day × (implementer + reviewer) = 8 runs/day. Implementer 6 issues/run ×
4 = up to 24 issues/day. One-off scheduled runs don't count against the cap.

## Registering the Routines (manual cloud step — no IaC for Routines)
For each of routine-implementer.md and routine-reviewer.md: in claude.ai/code →
Routines, create a scheduled routine, bind repo `schmug/dmarcheck`, paste the
prompt file contents, set schedule (implementer every 4h; reviewer offset +1h),
enable `claude/`-branch pushes for the implementer. Routine commits appear as
`schmug`.

## Kill switch (emergency pause)

To pause both Routines without touching cloud Routine config:

1. Apply the `pipeline-paused` label to any open issue (e.g. the ledger issue #304):
   `gh issue edit 304 --repo schmug/dmarcheck --add-label pipeline-paused`
2. Both Routines check for this label as step 0 and no-op if present — they print a
   clear message and mutate nothing (no PRs opened, no merges, no comments).

To resume:
   `gh issue edit 304 --repo schmug/dmarcheck --remove-label pipeline-paused`

The `pipeline-paused` label is created by `scripts/routine-pipeline/setup-labels.sh`.

## Audit trail

Every auto-merged PR receives a comment from the reviewer Routine containing the full
gate verdict JSON (`pass`, `reasons`). This provides an immutable per-PR record of
why the gate passed the PR, enabling forensics after any unexpected auto-merge.
Escalated PRs already receive a verdict comment with the `reasons` array.

## Pilot validation log
Filled in during go-live. Scenario → expected → actual.
