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
  const buckets = new Map<number, number[]>();
  for (const row of result.results) {
    const day = Math.floor(row.scanned_at / 86400);
    const list = buckets.get(day) ?? [];
    list.push(gradeToScore(row.grade));
    buckets.set(day, list);
  }
  const sortedDays = [...buckets.keys()].sort((a, b) => a - b);
  return sortedDays.map((day) => {
    const scores = buckets.get(day) ?? [];
    const sum = scores.reduce((acc, n) => acc + n, 0);
    return scores.length ? sum / scores.length : 0;
  });
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

export interface LatestScanRow {
  domain: string;
  last_scanned_at: number | null;
  grade: string | null;
  protocol_results: string | null;
  score_factors: string | null;
}

// Returns the most recent scan for every domain the user owns, in domain
// alphabetical order. Uses the cached last_grade on `domains` for the grade
// column (avoids a nested aggregate per row) and fetches protocol_results +
// score_factors from the matching scan_history row via a correlated subquery.
// Safe for the Pro cap (≤25 domains) — D1 handles this trivially.
export async function getLatestScansForUser(
  db: D1Database,
  userId: string,
): Promise<LatestScanRow[]> {
  const result = await db
    .prepare(
      `SELECT
         d.domain,
         d.last_scanned_at,
         d.last_grade AS grade,
         sh.protocol_results,
         sh.score_factors
       FROM domains d
       LEFT JOIN scan_history sh
         ON sh.domain_id = d.id
         AND sh.scanned_at = (
           SELECT MAX(sh2.scanned_at)
           FROM scan_history sh2
           WHERE sh2.domain_id = d.id
         )
       WHERE d.user_id = ?
       ORDER BY d.domain`,
    )
    .bind(userId)
    .all<LatestScanRow>();
  return result.results;
}
