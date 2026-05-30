export const meta = {
  name: 'pr-triage',
  description:
    'Triage open PRs in parallel: assess required CI, merge conflicts, unresolved comments, and superseding siblings, then recommend merge/close/comment/escalate. Default dry-run; execute mode merges only the strictly-eligible, ungated, fully-green subset.',
  whenToUse:
    'Burn down the open-PR backlog. One agent per PR ports the repo /triage playbook (required-check discovery, mergeStateStatus taxonomy, sibling detection, CODEOWNERS gating, no-duplicate-blocked-comments). Recommend-only by default; pass args {execute:true} to auto-merge the eligible subset, {prNumbers:[...]} to scope.',
  phases: [
    { title: 'Gather', detail: 'list open PRs + discover required checks' },
    { title: 'Assess', detail: 'one agent per PR: CI, conflicts, comments, siblings, gating -> verdict' },
    { title: 'Execute', detail: 'merge only ungated, fully-green, high-confidence PRs (execute mode only)' },
  ],
}

const opts = args && typeof args === 'object' ? args : {}
const EXECUTE = opts.execute === true
const ONLY = Array.isArray(opts.prNumbers) ? opts.prNumbers : null
const REPO = opts.repo || 'schmug/dmarcheck'

// --- Deterministic CODEOWNERS backstop ---------------------------------------
// Paths gated by .github/CODEOWNERS (all require an @schmug code-owner review).
// A PR whose diff touches ANY of these requires human approval and must NEVER be
// auto-merged, regardless of a CLEAN mergeStateStatus. CLEAN is unreliable here:
// the autonomous bot currently runs as admin and bypasses the ruleset until the
// #299 bot-identity split lands (see CLAUDE.md). Hardcoded (not read from the PR
// head) on purpose so a PR that edits CODEOWNERS itself can't widen its own gate.
const GATED_PATHS = [
  '.github/',
  'package.json',
  'package-lock.json',
  'wrangler.toml',
  'SECURITY.md',
  'CLAUDE.md',
  '.claude/settings.json',
  'src/index.ts',
  'src/rate-limit.ts',
  'src/db/',
  'src/analyzers/',
  'src/orchestrator.ts',
  'src/shared/scoring.ts',
]
function gatedHits(files) {
  const list = Array.isArray(files) ? files : []
  return list.filter((f) => GATED_PATHS.some((p) => (p.endsWith('/') ? f.startsWith(p) : f === p)))
}

const GATHER_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    requiredChecks: {
      type: 'array',
      items: { type: 'string' },
      description: 'Authoritative list of required status-check contexts from branch protection / ruleset.',
    },
    prs: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          number: { type: 'number' },
          title: { type: 'string' },
          author: { type: 'string' },
          isDraft: { type: 'boolean' },
          headRefName: { type: 'string' },
        },
        required: ['number', 'title'],
      },
    },
  },
  required: ['requiredChecks', 'prs'],
}

const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    number: { type: 'number' },
    title: { type: 'string' },
    action: { type: 'string', enum: ['merge', 'close', 'comment', 'escalate', 'hold'] },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    autoMergeEligible: { type: 'boolean' },
    ciAllGreen: { type: 'boolean', description: 'true only if every REQUIRED check is passing' },
    mergeStateStatus: { type: 'string' },
    mergeStateOk: { type: 'boolean', description: 'true for CLEAN/UNSTABLE/HAS_HOOKS' },
    unresolvedComments: { type: 'boolean', description: 'true if there is unaddressed actionable review feedback' },
    siblings: { type: 'array', items: { type: 'string' }, description: 'sibling/superseding PRs found, e.g. "#410 merged"' },
    changedFiles: { type: 'array', items: { type: 'string' }, description: 'complete name-only diff' },
    rationale: { type: 'string' },
    blockers: { type: 'array', items: { type: 'string' } },
  },
  required: ['number', 'action', 'confidence', 'autoMergeEligible', 'ciAllGreen', 'mergeStateOk', 'rationale'],
}

const MERGE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    merged: { type: 'boolean' },
    reason: { type: 'string' },
  },
  required: ['merged', 'reason'],
}

// --- Gather ------------------------------------------------------------------
phase('Gather')
const scopeNote = ONLY ? `Only consider PRs: ${ONLY.join(', ')}.` : 'Consider all open PRs.'
const gather = await agent(
  `You are gathering triage inputs for the ${REPO} repo. Use the gh CLI (read-only).

1. List open PRs: gh pr list --repo ${REPO} --state open --json number,title,author,isDraft,headRefName --limit 50
   ${scopeNote}
2. Discover the AUTHORITATIVE required status-check contexts (do not hardcode; the list drifts):
   gh api repos/${REPO}/branches/main/protection --jq '.required_status_checks.contexts' 2>/dev/null
   || gh api repos/${REPO}/rules/branches/main --jq '[.[] | select(.type=="required_status_checks") | .parameters.required_status_checks[].context]'
   If both are empty, fall back to ["check"].

Return requiredChecks and the prs list (author = login string, e.g. "schmug").`,
  { phase: 'Gather', label: 'gather:prs+checks', schema: GATHER_SCHEMA },
)

let prs = gather?.prs || []
if (ONLY) prs = prs.filter((p) => ONLY.includes(p.number))
const requiredChecks = (gather?.requiredChecks && gather.requiredChecks.length ? gather.requiredChecks : ['check'])
log(`${prs.length} open PR(s) to assess. Required checks: ${requiredChecks.join(', ')}. Mode: ${EXECUTE ? 'EXECUTE' : 'dry-run'}.`)

if (!prs.length) {
  return { mode: EXECUTE ? 'execute' : 'dry-run', requiredChecks, results: [], summary: 'No open PRs to triage.' }
}

// --- Assess (+ gated Execute) ------------------------------------------------
const reqList = requiredChecks.join(', ')
const results = await pipeline(
  prs,
  // Stage 1: deep per-PR assessment (read-only)
  (pr) =>
    agent(
      `Assess open PR #${pr.number} ("${pr.title}") in ${REPO} for triage. Use the gh CLI READ-ONLY — do NOT merge, close, comment, label, or modify anything.

Gather:
1. gh pr view ${pr.number} --repo ${REPO} --json number,title,author,isDraft,mergeable,mergeStateStatus,reviewDecision,headRefName,baseRefName,statusCheckRollup,comments,reviews,url
2. gh pr checks ${pr.number} --repo ${REPO}    (per-check pass/fail/pending)
3. gh pr diff ${pr.number} --repo ${REPO} --name-only    (REQUIRED — return the COMPLETE file list as changedFiles)
4. Inspect the comment + review threads from step 1. Decide if there is UNADDRESSED, ACTIONABLE review feedback (a requested change not yet resolved). Auto-generated bot summaries with no requested change are NOT blocking and are NOT "unresolved".

Apply the repo /triage playbook:

CI — The required status checks are: ${reqList}. ONLY these gate merge. Treat every other check (legacy 'CodeQL' which is now NEUTRAL/non-blocking, 'Workers Builds', any 'claude-review') as advisory noise. ciAllGreen=true ONLY if every REQUIRED check is passing (not pending, not failing).

Mergeability — re-query 'gh pr view ${pr.number} --json mergeable,mergeStateStatus' once if it is UNKNOWN (GitHub computes it lazily):
  - CLEAN / UNSTABLE / HAS_HOOKS -> mergeStateOk=true
  - BLOCKED + mergeable MERGEABLE + no failed required check -> a required review/check is missing (usually a CODEOWNERS-gated path) -> action=escalate, mergeStateOk=false
  - DIRTY -> merge conflict -> hunt for a sibling PR that superseded this; action=close if clearly superseded else escalate; mergeStateOk=false
  - BEHIND -> branch needs rebase; for bot PRs prefer close-and-retrigger; mergeStateOk=false
  - UNKNOWN after re-query -> mergeStateOk=false

Siblings — before recommending merge or close, search for sibling branches targeting the same change. Strip trailing numeric task IDs and -v2/-v3 from the headRefName ('${pr.headRefName || ""}') and search open+closed PRs (gh pr list --repo ${REPO} --search ...). For claude/issue-NNN-* branches, search for other PRs claiming the same issue number. A sibling merged AFTER this PR opened -> action=close (superseded). Record any siblings in 'siblings'.

Comments — never propose posting a duplicate "we're blocked" comment. If prior Claude-signed comments already converged on a blocker with no owner reply, that is action=escalate (awaiting human), not action=comment.

CODEOWNERS — be aware these source/CI paths require a human code-owner review: .github/**, package.json, package-lock.json, wrangler.toml, SECURITY.md, CLAUDE.md, .claude/settings.json, src/index.ts, src/rate-limit.ts, src/db/**, src/analyzers/**, src/orchestrator.ts, src/shared/scoring.ts. If the diff touches any, the correct action is escalate and autoMergeEligible MUST be false even if mergeStateStatus is CLEAN (the bot currently bypasses the gate as admin; that bypass is not authorization). The orchestrator enforces this independently from changedFiles, so report changedFiles accurately.

Decide action: merge | close | comment | escalate | hold.
Set autoMergeEligible=true ONLY if ALL hold: every required check green; mergeStateOk; mergeable==MERGEABLE; no unresolved actionable comments; no superseding sibling; the diff touches NO CODEOWNERS-gated path; and you are highly confident the change is sane and useful to merge as-is. Otherwise false.

Give a one-line rationale and list concrete blockers. Return the structured verdict; changedFiles MUST be complete.`,
      { phase: 'Assess', label: `assess:#${pr.number}`, schema: VERDICT_SCHEMA },
    ),
  // Stage 2: deterministic gate + optional merge
  async (verdict, pr) => {
    if (!verdict) return null
    const hits = gatedHits(verdict.changedFiles)
    const gated = hits.length > 0
    // Independent, script-side eligibility — never trust the agent's boolean alone.
    const eligible =
      verdict.action === 'merge' &&
      verdict.confidence === 'high' &&
      verdict.autoMergeEligible === true &&
      verdict.ciAllGreen === true &&
      verdict.mergeStateOk === true &&
      verdict.unresolvedComments !== true &&
      (verdict.siblings || []).length === 0 &&
      !gated
    const enriched = {
      ...verdict,
      number: verdict.number || pr.number,
      title: verdict.title || pr.title,
      gatedPaths: hits,
      eligible,
      // If gated, force the surfaced action to escalate regardless of what the agent said.
      action: gated && verdict.action === 'merge' ? 'escalate' : verdict.action,
      executed: false,
    }
    if (!EXECUTE || !eligible) {
      if (gated && verdict.action === 'merge') {
        enriched.blockers = [...(verdict.blockers || []), `CODEOWNERS-gated path(s): ${hits.join(', ')} — requires human review`]
      }
      return enriched
    }
    const merge = await agent(
      `Merge PR #${enriched.number} in ${REPO}. First RE-VERIFY safety (mergeability is computed lazily and may have changed):
1. gh pr view ${enriched.number} --repo ${REPO} --json mergeable,mergeStateStatus,statusCheckRollup
2. Confirm mergeable==MERGEABLE, mergeStateStatus in {CLEAN,UNSTABLE,HAS_HOOKS}, and the required checks (${reqList}) are all passing.
If ANY of those fail, do NOT merge — return {merged:false, reason:"<what failed>"}.
If all pass: gh pr merge ${enriched.number} --repo ${REPO} --squash --delete-branch, then return {merged:true, reason:"squash-merged"}.`,
      { phase: 'Execute', label: `merge:#${enriched.number}`, schema: MERGE_SCHEMA },
    )
    enriched.executed = merge?.merged === true
    enriched.executeReason = merge?.reason || 'no result'
    return enriched
  },
)

const clean = results.filter(Boolean)
const byAction = (a) => clean.filter((r) => r.action === a).map((r) => r.number)
const summary = {
  merge: byAction('merge'),
  close: byAction('close'),
  comment: byAction('comment'),
  escalate: byAction('escalate'),
  hold: byAction('hold'),
  mergedNow: clean.filter((r) => r.executed).map((r) => r.number),
}
log(
  `Assessed ${clean.length} PR(s). merge:${summary.merge.length} close:${summary.close.length} comment:${summary.comment.length} escalate:${summary.escalate.length} hold:${summary.hold.length}` +
    (EXECUTE ? ` | merged-now:${summary.mergedNow.length}` : ' | dry-run (no merges performed)'),
)

return { mode: EXECUTE ? 'execute' : 'dry-run', requiredChecks, summary, results: clean }
