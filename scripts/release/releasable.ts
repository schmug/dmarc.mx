// Skip-pattern strings mirroring cliff.toml commit_parsers with skip = true.
// A drift-check test in __tests__/releasable.test.ts enforces these stay in sync.
//   ^chore        covers chore:, chore(deps):, chore(deps-dev):, …
//   ^[Bb]ump      dependabot-style "Bump X from Y to Z"
//   ^Merge pull request / ^Merge branch  — merge commits
// Serial-number note: skipping a run leaves a gap in vYYYY.M.serial — that is
// acceptable; the counter always counts existing tags.
export const SKIP_PATTERN_SOURCES = [
  "^chore",
  "^[Bb]ump ",
  "^Merge pull request",
  "^Merge branch",
] as const;

const SKIP = SKIP_PATTERN_SOURCES.map((s) => new RegExp(s));

/**
 * Returns true if the commit set should produce a release.
 *   null → no prior tag; this is the first release → always releasable
 *   []   → no new commits since last tag → not releasable (skip)
 *   [...] → releasable iff at least one commit doesn't match every skip pattern
 */
export function isReleasable(commits: string[] | null): boolean {
  if (commits === null) return true;
  if (commits.length === 0) return false;
  return commits.some((msg) => !SKIP.some((p) => p.test(msg)));
}
