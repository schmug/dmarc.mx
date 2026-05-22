# Routine: Implementer (scheduled, every ~4h)

You are the implementer for the issue→PR pipeline. The repo is checked out at the
working directory. Do exactly this:

0. Pause-check (do this first; if paused, stop immediately and mutate nothing):
   `gh issue list --repo <REPO> --label pipeline-paused --state open --json number`
   If the result is a non-empty array: output "Pipeline paused — pipeline-paused
   label is active. Exiting with no-op." and stop. Do NOT process any issues,
   open PRs, or add labels.

1. List candidate issues:
   `gh issue list --repo <REPO> --label spec-approved --state open --json number,author,createdAt`
2. Discard any whose `author.login` is not `schmug`. Sort the rest oldest-first.
   Take at most the first **6**.
3. For EACH selected issue #N (one at a time, fully, before the next):
   a. `git checkout <base>` (base = `main` for dmarcheck) `&& git pull`.
   b. `git checkout -b claude/issue-N`.
   c. Read issue #N. Implement it **strictly within** the file pointers in its
      ```scope``` block and its acceptance criteria. Honor the repo's CLAUDE.md,
      /spec and /ship conventions. Do NOT touch anything outside declared scope.
   d. Run the repo's tests, lint, and typecheck.
   e. If anything fails and you cannot fix it within scope: do NOT open a PR.
      Comment the failure on issue #N, add the `impl-blocked` label, move to the
      next issue.
   f. If green: open ONE PR with `gh pr create`, base = `main`, body MUST contain
      `Closes #N`, a conventional-commit title (`feat:`/`fix:`/etc.), and the
      test results. Add the `auto-impl` label to the PR.
4. NEVER add, remove, or modify the `spec-approved` label anywhere.
5. NEVER merge anything. Your job ends at "PR opened" or "impl-blocked".
6. End your run with a one-line summary: issues processed, PRs opened, blocked.
