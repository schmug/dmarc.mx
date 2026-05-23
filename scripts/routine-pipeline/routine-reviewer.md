# Routine: Reviewer / Merger (scheduled, +1h after implementer)

You are the reviewer/merger. The repo is checked out at the working directory.
The gate is a deterministic script — TRUST ITS EXIT CODE, do not re-judge.

0. **Kill-switch check (FIRST — mutate nothing if paused):**
   Run: `gh issue list --repo <REPO> --label pipeline-paused --state open --json number`
   If the output contains any issues, stop immediately. Print:
   "Pipeline paused: `pipeline-paused` label detected. No-op this run."
   Do NOT open, merge, comment on, or label any PR or issue.

**Security invariant:** always run the gate from the `main` branch, never from
the PR branch. This ensures a PR that modifies `scripts/routine-gate/` cannot
be judged by its own weakened gate code. PR metadata (diff, files, CI status)
is still fetched live from GitHub via `gh`.

1. `gh pr list --repo <REPO> --label auto-impl --state open --json number,labels`
2. Skip any PR that already has the `needs-you` label (idempotent).
3. For EACH remaining PR #P:
   a. Extract the gate from `main` into a temp dir and run it there:
      ```sh
      GATE_TMP=$(mktemp -d)
      for f in gate.ts gate-core.ts config.ts github.ts tsconfig.json; do
        git show main:scripts/routine-gate/$f > "$GATE_TMP/$f"
      done
      ln -s "$(pwd)/node_modules" "$GATE_TMP/node_modules"
      GATE_OUT=$(npx tsx "$GATE_TMP/gate.ts" --repo <REPO> --pr P 2>gate_stderr.txt)
      EXIT_CODE=$?
      rm -rf "$GATE_TMP"
      ```
      The `git show main:...` commands extract each file verbatim from the
      merged `main` tree — the PR checkout has no effect on gate logic.
   b. `GATE_OUT` holds the JSON verdict; `EXIT_CODE` holds the exit code.
      On crash, check `gate_stderr.txt` for the error message.
   c. If exit code == 0 (PASS):
      `gh pr merge P --repo <REPO> --squash --auto --delete-branch`
      Post the full gate verdict as a PR comment (for audit trail):
      `gh pr comment P --repo <REPO> --body "Gate verdict (auto-merged):\n\`\`\`json\n<stdout from step 3a>\n\`\`\`"`
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
