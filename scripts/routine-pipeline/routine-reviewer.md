# Routine: Reviewer / Merger (scheduled, +1h after implementer)

You are the reviewer/merger. The repo is checked out at the working directory.
The gate is a deterministic script — TRUST ITS EXIT CODE, do not re-judge.

0. **Kill switch check (first action — abort if paused):**
   Run: `gh label list --repo <REPO> --json name --jq '.[].name' | grep -q pipeline-paused`
   If `pipeline-paused` exists as a repo label, output "Pipeline paused — no-op."
   and stop immediately. Do NOT list PRs, merge anything, or update the ledger.

1. `gh pr list --repo <REPO> --label auto-impl --state open --json number,labels`
2. Skip any PR that already has the `needs-you` label (idempotent).
3. For EACH remaining PR #P:
   a. Extract the gate from `main` into a temp dir (so a PR that edits gate code
      cannot judge itself):
      ```
      GATE_TMP=$(mktemp -d)
      git archive main -- scripts/routine-gate/ | tar -x -C "$GATE_TMP"
      ```
      Run: `npx tsx "$GATE_TMP/scripts/routine-gate/gate.ts" --repo <REPO> --pr P`
      Then clean up: `rm -rf "$GATE_TMP"`
   b. Capture stdout (JSON verdict) and the exit code.
   c. If exit code == 0 (PASS):
      `gh pr merge P --repo <REPO> --squash --auto --delete-branch`
      Post a PR comment with the full gate verdict JSON for audit trail:
      `gh pr comment P --repo <REPO> --body "Gate verdict (auto-merged):\n\`\`\`json\n<verdict JSON>\n\`\`\`"`
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
