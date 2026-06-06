// Portfolio-wide grade bucketing, shared by the dashboard view (which tallies
// an in-hand list of domains) and the DB layer (which tallies grouped COUNT(*)
// rows). Kept dependency-free so both layers can import it without dragging in
// view or DB modules.

export type GradeBucket = "healthy" | "drifting" | "failing" | "ungraded";

export interface PortfolioStats {
  total: number;
  healthy: number;
  drifting: number;
  failing: number;
  ungraded: number;
}

// Maps a letter grade to a portfolio bucket. S/A/B (with +/- modifiers) are
// healthy, C/D are drifting, F is failing; null, the "—" placeholder, the
// literal "ungraded", and anything unrecognized fall through to ungraded.
export function gradeBucket(grade: string | null | undefined): GradeBucket {
  if (!grade) return "ungraded";
  const letter = grade.charAt(0).toUpperCase();
  if (letter === "S" || letter === "A" || letter === "B") return "healthy";
  if (letter === "C" || letter === "D") return "drifting";
  if (letter === "F") return "failing";
  return "ungraded";
}

export function emptyPortfolioStats(): PortfolioStats {
  return { total: 0, healthy: 0, drifting: 0, failing: 0, ungraded: 0 };
}

// Folds grouped `{ grade, count }` rows (as returned by a
// `GROUP BY last_grade` query) into a PortfolioStats tally.
export function tallyGradeCounts(
  rows: Iterable<{ grade: string | null; count: number }>,
): PortfolioStats {
  const stats = emptyPortfolioStats();
  for (const row of rows) {
    const n = row.count;
    stats.total += n;
    stats[gradeBucket(row.grade)] += n;
  }
  return stats;
}
