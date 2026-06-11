export interface ScanHistoryRow {
  id: number;
  domain_id: number;
  grade: string;
  score_factors: string | null;
  protocol_results: string | null;
  scanned_at: number;
}

export interface RecordScanInput {
  domainId: number;
  grade: string;
  scoreFactors: unknown;
  protocolResults: unknown;
  scannedAt?: number;
}

// Writes one scan_history row and updates the owning domain's last_grade /
// last_scanned_at in a single D1 batch. Batch is atomic at the D1 layer, so
// the history row and the domain summary stay in sync even if the request is
// cancelled mid-flight.
export async function recordScan(
  db: D1Database,
  input: RecordScanInput,
): Promise<void> {
  const scannedAt = input.scannedAt ?? Math.floor(Date.now() / 1000);
  const scoreFactorsJson = JSON.stringify(input.scoreFactors ?? null);
  const protocolResultsJson = JSON.stringify(input.protocolResults ?? null);

  await db.batch([
    db
      .prepare(
        "INSERT INTO scan_history (domain_id, grade, score_factors, protocol_results, scanned_at) VALUES (?, ?, ?, ?, ?)",
      )
      .bind(
        input.domainId,
        input.grade,
        scoreFactorsJson,
        protocolResultsJson,
        scannedAt,
      ),
    db
      .prepare(
        "UPDATE domains SET last_grade = ?, last_scanned_at = ? WHERE id = ?",
      )
      .bind(input.grade, scannedAt, input.domainId),
  ]);
}

export async function getScanHistory(
  db: D1Database,
  domainId: number,
  limit = 12,
): Promise<ScanHistoryRow[]> {
  const result = await db
    .prepare(
      "SELECT * FROM scan_history WHERE domain_id = ? ORDER BY scanned_at DESC LIMIT ?",
    )
    .bind(domainId, limit)
    .all<ScanHistoryRow>();
  return result.results;
}

export type ProtocolStatus = "pass" | "warn" | "fail" | "info" | null;

export interface ScanHistoryWithProtocols {
  grade: string;
  scannedAt: number;
  protocols: {
    dmarc: ProtocolStatus;
    spf: ProtocolStatus;
    dkim: ProtocolStatus;
    bimi: ProtocolStatus;
    mta_sts: ProtocolStatus;
  };
}

function asStatus(value: unknown): ProtocolStatus {
  return value === "pass" ||
    value === "warn" ||
    value === "fail" ||
    value === "info"
    ? value
    : null;
}

// Parses the JSON blob in `protocol_results` into a flat per-protocol status
// map so history views don't have to reach into the orchestrator shape. Any
// protocol missing or unparseable is returned as null — the view renders that
// as "—" rather than failing the whole row.
// Maps a letter grade to a 0–12 score for the dashboard sparkline.
// 12 = S, 11 = A+, 10 = A … 0 = F. Mirrors the GRADE_RANK_FOR_SPARKLINE
// table inside dashboard.ts but is exported here so the data layer can
// score historical rows without depending on a view module.
const GRADE_SCORE: Record<string, number> = {
  S: 12,
  "A+": 11,
  A: 10,
  "A-": 9,
  "B+": 8,
  B: 7,
  "B-": 6,
  "C+": 5,
  C: 4,
  "C-": 3,
  "D+": 2,
  D: 1,
  "D-": 1,
  F: 0,
};

function gradeToScore(grade: string): number {
  return GRADE_SCORE[grade] ?? 0;
}

// Returns one average-portfolio-score per day for the last `days` days, oldest
// first. Days with no scans are omitted (the consumer pads / renders a stub).
// Cheap because the user's full watchlist is bounded by PRO_WATCHLIST_CAP, so
// at most cap × days rows ever come back; for `days=30, cap=25` that's 750.
export async function getPortfolioTrendForUser(
  db: D1Database,
  userId: string,
  days = 30,
  now: number = Math.floor(Date.now() / 1000),
): Promise<number[]> {
  const since = now - days * 86400;
  const result = await db
    .prepare(
      `SELECT sh.grade AS grade, sh.scanned_at AS scanned_at
       FROM scan_history sh
       JOIN domains d ON d.id = sh.domain_id
       WHERE d.user_id = ? AND sh.scanned_at >= ?
       ORDER BY sh.scanned_at ASC`,
    )
    .bind(userId, since)
    .all<{ grade: string; scanned_at: number }>();

  // Bucket by integer day (UTC). Each bucket gets the *latest* scan per domain,
  // then we average across domains. We approximate "latest per domain per day"
  // by collapsing all scans in the bucket to a single mean — close enough for
  // a 0–100 trend line and avoids a second pass.
  // ⚡ Bolt Optimization: Maintain a running sum and count in the map instead
  // of pushing into arrays and calling .reduce(). This avoids allocating
  // thousands of intermediate arrays and reduces GC pressure on a hot path.
  const buckets = new Map<number, { sum: number; count: number }>();
  for (const row of result.results) {
    const day = Math.floor(row.scanned_at / 86400);
    const stat = buckets.get(day) ?? { sum: 0, count: 0 };
    stat.sum += gradeToScore(row.grade);
    stat.count += 1;
    buckets.set(day, stat);
  }
  const sortedDays = [...buckets.keys()].sort((a, b) => a - b);
  return sortedDays.map((day) => {
    const stat = buckets.get(day);
    if (!stat || stat.count === 0) return 0;
    return stat.sum / stat.count;
  });
}

// One row per domain the user monitors: the domain name, grade, last_scanned_at
// (from the domains table), and the protocol_results blob from the most-recent
// scan_history row. Used exclusively by GET /dashboard/export — no fresh DNS
// lookups are performed.
//
// Future work: a historical bulk-export (all scans over time) would need a
// different query shape; that is intentionally out of scope for this route.
export interface DashboardExportRow {
  domain: string;
  last_scanned_at: number | null;
  last_grade: string | null;
  protocol_results: string | null;
}

// Returns the latest protocol_results blob plus the current grade for every
// domain in the user's watchlist. Used to compute per-protocol failure tallies
// without fresh DNS lookups; the grade lets tallyProtocolFailures scope the
// count to the failing bucket. Reuses the same correlated-subquery shape as
// getDashboardExportRows.
export async function getProtocolResultsForUser(
  db: D1Database,
  userId: string,
): Promise<
  Array<{ last_grade: string | null; protocol_results: string | null }>
> {
  const result = await db
    .prepare(
      `SELECT
         d.last_grade AS last_grade,
         (SELECT sh.protocol_results
            FROM scan_history sh
           WHERE sh.domain_id = d.id
           ORDER BY sh.scanned_at DESC
           LIMIT 1) AS protocol_results
       FROM domains d
       WHERE d.user_id = ?`,
    )
    .bind(userId)
    .all<{ last_grade: string | null; protocol_results: string | null }>();
  return result.results;
}

export async function getDashboardExportRows(
  db: D1Database,
  userId: string,
): Promise<DashboardExportRow[]> {
  // Correlated subquery picks the single most-recent protocol_results blob per
  // domain without a second round-trip. domains.last_grade / last_scanned_at
  // are the authoritative "current posture" fields maintained by recordScan.
  const result = await db
    .prepare(
      `SELECT
         d.domain,
         d.last_scanned_at,
         d.last_grade,
         (SELECT sh.protocol_results
            FROM scan_history sh
           WHERE sh.domain_id = d.id
           ORDER BY sh.scanned_at DESC
           LIMIT 1) AS protocol_results
       FROM domains d
       WHERE d.user_id = ?
       ORDER BY d.domain ASC`,
    )
    .bind(userId)
    .all<DashboardExportRow>();
  return result.results;
}

export async function getScanHistoryWithProtocols(
  db: D1Database,
  domainId: number,
  limit: number,
): Promise<ScanHistoryWithProtocols[]> {
  const rows = await getScanHistory(db, domainId, limit);
  return rows.map((row) => {
    let parsed: Record<string, { status?: unknown } | undefined> | null = null;
    if (row.protocol_results) {
      try {
        parsed = JSON.parse(row.protocol_results) as Record<
          string,
          { status?: unknown } | undefined
        >;
      } catch {
        parsed = null;
      }
    }
    return {
      grade: row.grade,
      scannedAt: row.scanned_at,
      protocols: {
        dmarc: asStatus(parsed?.dmarc?.status),
        spf: asStatus(parsed?.spf?.status),
        dkim: asStatus(parsed?.dkim?.status),
        bimi: asStatus(parsed?.bimi?.status),
        mta_sts: asStatus(parsed?.mta_sts?.status),
      },
    };
  });
}
