export interface Domain {
  id: number;
  user_id: string;
  domain: string;
  is_free: number;
  scan_frequency: string;
  last_scanned_at: number | null;
  last_grade: string | null;
  created_at: number;
}

export async function createDomain(
  db: D1Database,
  input: { userId: string; domain: string; isFree: boolean },
): Promise<void> {
  const frequency = input.isFree ? "monthly" : "weekly";
  await db
    .prepare(
      "INSERT INTO domains (user_id, domain, is_free, scan_frequency) VALUES (?, ?, ?, ?)",
    )
    .bind(input.userId, input.domain, input.isFree ? 1 : 0, frequency)
    .run();
}

export async function createDomains(
  db: D1Database,
  inputs: { userId: string; domain: string; isFree: boolean }[],
): Promise<void> {
  if (inputs.length === 0) return;
  const values = inputs.map(() => "(?, ?, ?, ?)").join(", ");
  const binds: unknown[] = [];
  for (const input of inputs) {
    const frequency = input.isFree ? "monthly" : "weekly";
    binds.push(input.userId, input.domain, input.isFree ? 1 : 0, frequency);
  }
  await db
    .prepare(
      `INSERT INTO domains (user_id, domain, is_free, scan_frequency) VALUES ${values} ON CONFLICT DO NOTHING`,
    )
    .bind(...binds)
    .run();
}

export async function getDomainsByUser(
  db: D1Database,
  userId: string,
): Promise<Domain[]> {
  const result = await db
    .prepare("SELECT * FROM domains WHERE user_id = ? ORDER BY created_at")
    .bind(userId)
    .all<Domain>();
  return result.results;
}

export async function countDomainsByUser(
  db: D1Database,
  userId: string,
): Promise<number> {
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM domains WHERE user_id = ?")
    .bind(userId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

// Returns the subset of `domains` that the user already owns. Used by
// `processBulkScan` to distinguish net-new adds (which consume watchlist
// slots) from re-submits (which don't), so a user near their cap can still
// re-scan domains they already track without seeing them rejected.
export async function findExistingDomainsForUser(
  db: D1Database,
  userId: string,
  domains: string[],
): Promise<Set<string>> {
  if (domains.length === 0) return new Set();
  const placeholders = domains.map(() => "?").join(",");
  const result = await db
    .prepare(
      `SELECT domain FROM domains WHERE user_id = ? AND domain IN (${placeholders})`,
    )
    .bind(userId, ...domains)
    .all<{ domain: string }>();
  return new Set(result.results.map((r) => r.domain));
}

export type DomainSortColumn = "domain" | "grade" | "last_scanned" | "created";
export type DomainSortDirection = "asc" | "desc";

export interface ListDomainsOptions {
  userId: string;
  search?: string;
  grade?: string;
  frequency?: "weekly" | "monthly";
  sort?: DomainSortColumn;
  direction?: DomainSortDirection;
  limit: number;
  offset: number;
}

export interface ListDomainsPage {
  rows: Domain[];
  total: number;
}

// SQLite has no NULL-aware ranking and "A+" sorts after "A" textually, so we
// project last_grade onto a numeric scale (best→worst, NULL last) for sort
// stability. Keep this in sync with the grade strings produced by scoring.ts.
const GRADE_RANK_SQL = `CASE last_grade
  WHEN 'A+' THEN 1
  WHEN 'A'  THEN 2
  WHEN 'A-' THEN 3
  WHEN 'B+' THEN 4
  WHEN 'B'  THEN 5
  WHEN 'B-' THEN 6
  WHEN 'C+' THEN 7
  WHEN 'C'  THEN 8
  WHEN 'C-' THEN 9
  WHEN 'D+' THEN 10
  WHEN 'D'  THEN 11
  WHEN 'D-' THEN 12
  WHEN 'F'  THEN 13
  ELSE 99
END`;

function escapeLike(input: string): string {
  return input.replace(/[\\%_]/g, (m) => `\\${m}`);
}

function buildFilter(opts: ListDomainsOptions): {
  where: string;
  bindings: unknown[];
} {
  const clauses: string[] = ["user_id = ?"];
  const bindings: unknown[] = [opts.userId];
  const search = opts.search?.trim();
  if (search) {
    // SQLite's ESCAPE clause must be exactly one character. The JS source
    // here produces a SQL string containing a single backslash; double
    // backslashes blow up at runtime as `ESCAPE expression must be a single
    // character`.
    clauses.push("LOWER(domain) LIKE ? ESCAPE '\\'");
    bindings.push(`%${escapeLike(search.toLowerCase())}%`);
  }
  if (opts.grade) {
    if (opts.grade === "ungraded") {
      clauses.push("last_grade IS NULL");
    } else {
      clauses.push("last_grade = ?");
      bindings.push(opts.grade);
    }
  }
  if (opts.frequency) {
    clauses.push("scan_frequency = ?");
    bindings.push(opts.frequency);
  }
  return { where: clauses.join(" AND "), bindings };
}

function buildOrderBy(
  sort: DomainSortColumn,
  direction: DomainSortDirection,
): string {
  const dir = direction === "desc" ? "DESC" : "ASC";
  switch (sort) {
    case "domain":
      return `domain ${dir}`;
    case "grade":
      return `${GRADE_RANK_SQL} ${dir}, domain ASC`;
    case "last_scanned":
      // Treat "never scanned" as oldest so it surfaces in the natural place
      // for both directions (top of asc, bottom of desc).
      return `COALESCE(last_scanned_at, 0) ${dir}, domain ASC`;
    case "created":
      return `created_at ${dir}, domain ASC`;
  }
}

export async function listDomainsForUserPaged(
  db: D1Database,
  opts: ListDomainsOptions,
): Promise<ListDomainsPage> {
  const { where, bindings } = buildFilter(opts);
  const orderBy = buildOrderBy(opts.sort ?? "domain", opts.direction ?? "asc");
  const rowsStmt = db
    .prepare(
      `SELECT * FROM domains WHERE ${where} ORDER BY ${orderBy} LIMIT ? OFFSET ?`,
    )
    .bind(...bindings, opts.limit, opts.offset);
  const countStmt = db
    .prepare(`SELECT COUNT(*) AS n FROM domains WHERE ${where}`)
    .bind(...bindings);
  const [rowsResult, countResult] = await Promise.all([
    rowsStmt.all<Domain>(),
    countStmt.first<{ n: number }>(),
  ]);
  return {
    rows: rowsResult.results,
    total: countResult?.n ?? 0,
  };
}

export async function getDomainByUserAndName(
  db: D1Database,
  userId: string,
  domain: string,
): Promise<Domain | null> {
  return db
    .prepare("SELECT * FROM domains WHERE user_id = ? AND domain = ?")
    .bind(userId, domain)
    .first<Domain>();
}

export async function deleteDomain(
  db: D1Database,
  userId: string,
  domain: string,
): Promise<void> {
  await db
    .prepare("DELETE FROM domains WHERE user_id = ? AND domain = ?")
    .bind(userId, domain)
    .run();
}

// Returns domains whose cadence has come due: monthly domains scanned more
// than 30 days ago (or never), weekly domains scanned more than 7 days ago.
// The constants are defined inline because the schema only permits two
// frequencies today; if we add more, split this into a per-frequency helper.
export async function getDueDomains(
  db: D1Database,
  now: number,
  limit = 500,
): Promise<Domain[]> {
  const monthlyCutoff = now - 30 * 24 * 60 * 60;
  const weeklyCutoff = now - 7 * 24 * 60 * 60;
  const result = await db
    .prepare(
      `SELECT * FROM domains
       WHERE (scan_frequency = 'monthly' AND (last_scanned_at IS NULL OR last_scanned_at < ?))
          OR (scan_frequency = 'weekly' AND (last_scanned_at IS NULL OR last_scanned_at < ?))
       ORDER BY last_scanned_at ASC NULLS FIRST
       LIMIT ?`,
    )
    .bind(monthlyCutoff, weeklyCutoff, limit)
    .all<Domain>();
  return result.results;
}

export async function updateLastScan(
  db: D1Database,
  domainId: number,
  grade: string,
  scannedAt: number,
): Promise<void> {
  await db
    .prepare(
      "UPDATE domains SET last_grade = ?, last_scanned_at = ? WHERE id = ?",
    )
    .bind(grade, scannedAt, domainId)
    .run();
}

// Marks existing watchlist rows as due for the cron rescanner. Bulk scan
// queues anything beyond inBandCap with status "queued"; net-new domains get
// last_scanned_at = NULL from INSERT, but re-submitted existing domains need
// an explicit reset or getDueDomains won't pick them up until cadence elapses.
export async function markDomainsDueForRescan(
  db: D1Database,
  userId: string,
  domains: string[],
): Promise<void> {
  if (domains.length === 0) return;
  const placeholders = domains.map(() => "?").join(",");
  await db
    .prepare(
      `UPDATE domains SET last_scanned_at = NULL
       WHERE user_id = ? AND domain IN (${placeholders})`,
    )
    .bind(userId, ...domains)
    .run();
}
