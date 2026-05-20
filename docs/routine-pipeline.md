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

## Kill switch — pausing both Routines

Both the implementer and reviewer check for the `pipeline-paused` label **as
their very first action** (step 0). If the label is present, the Routine exits
immediately with "Pipeline is paused. No-op." and mutates nothing — no PRs
opened, no merges, no escalations.

**To pause:** add (or create) the `pipeline-paused` label on the repo:
```
gh label create pipeline-paused --repo schmug/dmarcheck \
  --color CCCCCC --description "Pauses both Routines; remove to resume" --force
```
Or use `scripts/routine-pipeline/setup-labels.sh schmug/dmarcheck` (idempotent;
creates all five labels including `pipeline-paused`).

**To resume:** delete the label:
```
gh label delete pipeline-paused --repo schmug/dmarcheck --yes
```

The label is the sole gate — no cloud Routine config needs editing.

## Pilot validation log
Filled in during go-live. Scenario → expected → actual.
