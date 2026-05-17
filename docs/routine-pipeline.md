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

## Kill switch (emergency pause)

Both Routines check for the `pipeline-paused` repo label as their very first
action. While that label exists, neither Routine will open PRs, merge, push
branches, comment on issues, or modify any label — they exit immediately with a
clear no-op message.

**To pause the pipeline:**
```
gh label create pipeline-paused --repo schmug/dmarcheck --color B60205 \
  --description "Kill switch: both Routines no-op while this label exists" \
  --force
```
Or create it in the GitHub UI: repo → Issues → Labels → New label,
name `pipeline-paused`, color `#B60205`.

**To resume the pipeline:**
```
gh label delete pipeline-paused --repo schmug/dmarcheck --yes
```
Or delete it in the GitHub UI: repo → Issues → Labels → delete `pipeline-paused`.

The `setup-labels.sh` script creates this label along with the other pipeline
labels, so it is available from first setup. The kill switch is idempotent:
running `setup-labels.sh` again will not re-pause a running pipeline; the label
must be present for Routines to no-op.

## Audit trail

Every auto-merged PR receives a comment from the reviewer Routine containing the
full gate verdict JSON (`pass: true`, `reasons` array) before the merge is
triggered. This gives an immutable record on each PR of exactly why the gate
passed it, supporting forensics after any unexpected merge.

Escalated PRs (exit code 2) also receive a comment with the `reasons` array, as
before.

## Pilot validation log
Filled in during go-live. Scenario → expected → actual.
