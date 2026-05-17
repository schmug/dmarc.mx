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

## Gate self-modification defence (belt-and-suspenders)
Two layered controls prevent a PR from weakening the gate and then being
auto-merged by the weakened gate:

1. **Denylist** (primary, PR #311): any PR that touches `scripts/routine-gate/**`
   matches a risk-path and force-escalates to `needs-you` regardless of any other
   condition.

2. **Gate-from-main** (secondary, issue #312): the reviewer Routine always
   executes the gate binary from a fresh `main` worktree, not from the PR branch.
   The gate queries PR diff/metadata via `gh` (not the working tree), so running
   it from `main` is transparent — only the gate *code* origin changes.
   Command sequence (see `scripts/routine-pipeline/routine-reviewer.md` step 3a):
   ```
   git worktree add /tmp/gate-from-main main
   cd /tmp/gate-from-main
   npx tsx scripts/routine-gate/gate.ts --repo <REPO> --pr P
   EXIT_CODE=$?
   cd -
   git worktree remove --force /tmp/gate-from-main
   ```
   Even if the denylist were later weakened or bypassed, this layer ensures the
   evaluation logic itself cannot be modified by the PR under review.

## Cap math (Max = 15 Routine runs/day)
4 cycles/day × (implementer + reviewer) = 8 runs/day. Implementer 6 issues/run ×
4 = up to 24 issues/day. One-off scheduled runs don't count against the cap.

## Registering the Routines (manual cloud step — no IaC for Routines)
For each of routine-implementer.md and routine-reviewer.md: in claude.ai/code →
Routines, create a scheduled routine, bind repo `schmug/dmarcheck`, paste the
prompt file contents, set schedule (implementer every 4h; reviewer offset +1h),
enable `claude/`-branch pushes for the implementer. Routine commits appear as
`schmug`.

## Pilot validation log
Filled in during go-live. Scenario → expected → actual.
