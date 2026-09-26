// Autonomous merge rate: of the PRs the implementer routine raised and got
// merged, what share needed no human intervention. "Needed a human" is read off
// the labels a human applies when they step in, since that is the only durable
// record of it on a merged PR.

export const INTERVENTION_LABELS = [
  "awaiting-human",
  "blocked",
  "impl-blocked",
  "needs-decision",
  "needs-you",
];

export interface MergedPr {
  number: number;
  headRef: string;
  mergedAt: string | null;
  labels: string[];
}

export interface MergeRate {
  windowStartIso: string;
  mergedTotal: number;
  routineTotal: number;
  autonomous: number;
  intervened: number;
  ratePercent: number;
  interventionCounts: Record<string, number>;
  intervenedPrs: number[];
}

// The implementer routine names its branches claude/*; mine are dmarcus/*, and
// a human's are anything else. Only routine branches count towards the rate.
export function isRoutineBranch(headRef: string): boolean {
  return headRef.startsWith("claude/");
}

export function needsHuman(labels: string[]): string[] {
  const lower = labels.map((l) => l.toLowerCase());
  return INTERVENTION_LABELS.filter((l) => lower.includes(l));
}

export function computeMergeRate(
  prs: MergedPr[],
  windowStartIso: string,
): MergeRate {
  const start = Date.parse(windowStartIso);
  if (Number.isNaN(start)) {
    throw new Error(`windowStartIso is not a date: ${windowStartIso}`);
  }
  const merged = prs.filter(
    (p) => p.mergedAt !== null && Date.parse(p.mergedAt) >= start,
  );
  const routine = merged.filter((p) => isRoutineBranch(p.headRef));
  const interventionCounts: Record<string, number> = {};
  const intervenedPrs: number[] = [];
  for (const pr of routine) {
    const hits = needsHuman(pr.labels);
    if (hits.length === 0) continue;
    intervenedPrs.push(pr.number);
    for (const label of hits) {
      interventionCounts[label] = (interventionCounts[label] ?? 0) + 1;
    }
  }
  const autonomous = routine.length - intervenedPrs.length;
  return {
    windowStartIso,
    mergedTotal: merged.length,
    routineTotal: routine.length,
    autonomous,
    intervened: intervenedPrs.length,
    // An empty window is 0%, not a division by zero. Callers should look at
    // routineTotal before reading anything into the rate.
    ratePercent:
      routine.length === 0
        ? 0
        : Math.round((autonomous / routine.length) * 1000) / 10,
    interventionCounts,
    intervenedPrs: intervenedPrs.sort((a, b) => a - b),
  };
}

export function formatMergeRate(r: MergeRate): string {
  const lines = [
    `window start:        ${r.windowStartIso}`,
    `merged PRs:          ${r.mergedTotal}`,
    `routine PRs merged:  ${r.routineTotal}`,
    `merged autonomously: ${r.autonomous}`,
    `needed a human:      ${r.intervened}`,
    `autonomous rate:     ${r.ratePercent}%`,
  ];
  const counts = Object.entries(r.interventionCounts).sort(
    (a, b) => b[1] - a[1],
  );
  if (counts.length > 0) {
    lines.push("");
    lines.push("intervention labels:");
    for (const [label, n] of counts) lines.push(`  ${label}: ${n}`);
    lines.push(`intervened PRs: ${r.intervenedPrs.join(", ")}`);
  }
  return lines.join("\n");
}
