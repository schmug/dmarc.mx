# Mobile spec'ing runbook (the interactive half — Step 2 of the pipeline)

AskUserQuestion CANNOT run inside a Routine, so issue creation is interactive.

From the phone:
1. Open a session via Remote Control (`claude` on an always-on machine, steered
   from the Claude mobile app) OR claude.ai/code.
2. Describe the intent. Ask Claude to research the repo and propose
   atomically-sized issues.
3. Run the `/issue` skill. It must produce, for each issue:
   - a task-first body usable as a cold prompt,
   - an explicit ```scope``` fenced block listing in-scope file globs/paths,
   - an "Out of scope" section,
   - acceptance criteria.
   Use AskUserQuestion to tighten scope until each issue is one atomic change.
4. Create each issue on `schmug/dmarcheck` and apply the `spec-approved` label
   YOURSELF in this session (this is the trust token; the implementer Routine
   can never apply it).
5. Done. The scheduled implementer Routine will pick them up within ~4h (or
   trigger a one-off run manually; one-off runs don't count against the cap).
