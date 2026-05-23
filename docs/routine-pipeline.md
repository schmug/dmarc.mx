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

## Gate integrity (belt-and-suspenders)

The reviewer Routine always runs the gate from the `main` branch's code, not from
the PR's checkout. For each PR, it uses `git archive main -- scripts/routine-gate/`
to extract a clean copy into a temp dir, runs it there, then deletes the temp dir.
This means a PR that weakens `scripts/routine-gate/gate-core.ts` is still evaluated
by the unmodified `main` gate. The denylist (`config.ts` risk paths) is the primary
control; this is belt-and-suspenders.

## Kill switch (emergency pause)

Add the `pipeline-paused` label to the repo to no-op both Routines immediately.
While the label exists, neither the implementer nor the reviewer will open PRs,
merge anything, or update the ledger — they exit cleanly after the pause check.

To pause: `gh label create pipeline-paused --repo schmug/dmarcheck --color 5319E7 --description "Kill switch" --force`
To resume: `gh label delete pipeline-paused --repo schmug/dmarcheck --yes`

`setup-labels.sh` creates the label idempotently. Routines detect it via step 0.

## Audit trail

Every auto-merged PR receives a comment containing the full gate verdict JSON
(`pass`, `reasons`). This provides an immutable per-PR record of why the gate
passed it, enabling post-hoc forensics if a bad merge slips through.

## Pilot validation log
Filled in during go-live. Scenario → expected → actual.
