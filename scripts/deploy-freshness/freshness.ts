/**
 * Is the running Worker built from the current tip of main?
 *
 * Production ships through the Cloudflare Git integration rather than a
 * GitHub workflow, so a broken deploy leaves GitHub showing a merged PR
 * while dmarc.mx keeps serving the previous version. That happened on
 * 2026-09-21: both build triggers shared a Cloudflare build token that was
 * rolled, and every build failed with "the build token selected for this
 * build has been deleted or rolled". Nothing noticed, because the site was
 * up the whole time - prod-smoke probes whether dmarc.mx answers, not
 * whether it answers with the code we merged.
 *
 * The comparison is timestamps, not commit ids, because a
 * Git-integration deployment records no commit sha in its annotations.
 */
export type FreshnessInput = {
  /** Commit date of the current tip of main, ISO 8601. */
  mainCommitIso: string;
  /** created_on of the active production deployment, ISO 8601. */
  activeDeployIso: string;
  /**
   * How long a deploy is allowed to take before we call it missing. Covers
   * the build itself plus queueing; a successful build is normally well
   * under five minutes.
   */
  graceSeconds: number;
};

export type FreshnessResult = {
  stale: boolean;
  lagSeconds: number;
  summary: string;
};

function parse(label: string, iso: string): number {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) throw new Error(`${label} is not a date: ${iso}`);
  return ms;
}

export function evaluateFreshness(input: FreshnessInput): FreshnessResult {
  const main = parse("main commit date", input.mainCommitIso);
  const deployed = parse("active deployment date", input.activeDeployIso);
  const lagSeconds = Math.round((main - deployed) / 1000);

  // A deployment newer than main's tip is normal: a manual `wrangler
  // deploy`, a rollback, or a redeploy of the same commit. Only main
  // running ahead of production means something failed to ship.
  if (lagSeconds <= input.graceSeconds) {
    return {
      stale: false,
      lagSeconds,
      summary:
        lagSeconds <= 0
          ? `Production is current: active deployment is ${-lagSeconds}s newer than main's tip.`
          : `Production is current: main's tip is ${lagSeconds}s ahead, within the ${input.graceSeconds}s grace period.`,
    };
  }

  return {
    stale: true,
    lagSeconds,
    summary: `Production is stale: main's tip is ${lagSeconds}s (${Math.round(
      lagSeconds / 60,
    )} min) newer than the active deployment, past the ${
      input.graceSeconds
    }s grace period. A deploy has failed or never ran.`,
  };
}
