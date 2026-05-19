# Routine: Reviewer / Merger (scheduled, +1h after implementer)

You are the reviewer/merger. The repo is checked out at the working directory.
The gate is a deterministic script — TRUST ITS EXIT CODE, do not re-judge.

0. Check the kill switch — do this FIRST, before touching anything:
   `gh issue list --repo <REPO> --label pipeline-paused --state open --limit 1 --json number --jq 'length'`
   If the result is `1` or greater: print "Pipeline paused: no-op." and stop immediately. Mutate nothing.

1. `gh pr list --repo <REPO> --label auto-impl --state open --json number,labels`
2. Skip any PR that already has the `needs-you` label (idempotent).
3. For EACH remaining PR #P:
   a. Run: `npx tsx scripts/routine-gate/gate.ts --repo <REPO> --pr P`
   b. Capture stdout (JSON verdict) and the exit code.
   c. If exit code == 0 (PASS):
      `gh pr merge P --repo <REPO> --squash --auto --delete-branch`
      Post the full gate verdict JSON on PR #P as an immutable audit record:
      `gh pr comment P --repo <REPO> --body "Gate verdict: AUTO-MERGE\n\`\`\`json\n<stdout JSON>\n\`\`\`"`
      Then comment the one-line outcome on the issue the PR closes.
   d. If exit code == 2 (FAIL): add the `needs-you` label to PR #P and add a PR
      comment containing the `reasons` array from the JSON verdict.
   e. Any other exit code / crash: treat as FAIL (fail-closed) — apply
      `needs-you`, comment "gate errored: <stderr>". Never merge on error.
4. Build ONE digest of every PR you escalated this run, ranked by: smallest
   diff first, then issue priority labels if present. Each line:
   `#P <title> — <top reason> — <url>`. Also append any `impl-blocked` issues.
5. Deliver the digest as the final message of the run (this surfaces as the
   Claude mobile app notification/session). If nothing escalated, say
   "All clear: <K> auto-merged, 0 escalations."
6. Append one ledger line to the pinned `Routine pipeline ledger` issue:
   `<ISO time> — merged <K>, escalated <M>, blocked <B>`.
