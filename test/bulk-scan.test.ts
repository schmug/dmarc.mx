import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  BULK_IN_BAND_CAP,
  BULK_TOTAL_CAP,
  isCapExceeded,
  processBulkScan,
} from "../src/api/bulk-scan.js";

interface DomainRow {
  id: number;
  user_id: string;
  domain: string;
  is_free: number;
  scan_frequency: string;
  last_scanned_at: number | null;
  last_grade: string | null;
}

interface ScanHistoryRow {
  domain_id: number;
  grade: string;
  scanned_at: number;
}

let domainStore: DomainRow[];
let scanHistory: ScanHistoryRow[];
let nextId: number;

// recordScan uses db.batch([prepare(...).bind(...), prepare(...).bind(...)]).
// To make that resolve in tests, .bind() returns a thunk that captures sql +
// params and `batch` invokes each thunk's `run`. .first() also reads from the
// captured sql/params.
function makeDb(): D1Database {
  type BoundStmt = {
    sql: string;
    params: unknown[];
    run: () => Promise<{ success: true; meta: { changes: number } }>;
    first: <T>() => Promise<T | null>;
    all: <T>() => Promise<{ results: T[] }>;
  };

  const applyWrite = async (sql: string, params: unknown[]) => {
    if (/^INSERT INTO domains/i.test(sql)) {
      // Check if it's the multiple row insert
      if (sql.includes("VALUES (?, ?, ?, ?),")) {
        // It's a batched insert
        const CHUNK_SIZE = 4;
        for (let i = 0; i < params.length; i += CHUNK_SIZE) {
          const userId = params[i] as string;
          const domain = params[i + 1] as string;
          const isFree = params[i + 2] as number;
          const frequency = params[i + 3] as string;
          domainStore.push({
            id: nextId++,
            user_id: userId,
            domain,
            is_free: isFree,
            scan_frequency: frequency,
            last_scanned_at: null,
            last_grade: null,
          });
        }
      } else {
        const [userId, domain, isFree, frequency] = params as [
          string,
          string,
          number,
          string,
        ];
        domainStore.push({
          id: nextId++,
          user_id: userId,
          domain,
          is_free: isFree,
          scan_frequency: frequency,
          last_scanned_at: null,
          last_grade: null,
        });
      }
    } else if (/^INSERT INTO scan_history/i.test(sql)) {
      const [domainId, grade, , , scannedAt] = params as [
        number,
        string,
        string,
        string,
        number,
      ];
      scanHistory.push({ domain_id: domainId, grade, scanned_at: scannedAt });
    } else if (/^UPDATE domains SET last_grade/i.test(sql)) {
      const [grade, scannedAt, domainId] = params as [string, number, number];
      const row = domainStore.find((d) => d.id === domainId);
      if (row) {
        row.last_grade = grade;
        row.last_scanned_at = scannedAt;
      }
    } else if (/^UPDATE domains SET last_scanned_at = NULL/i.test(sql)) {
      const [userId, ...domains] = params as [string, ...string[]];
      const wanted = new Set(domains);
      for (const row of domainStore) {
        if (row.user_id === userId && wanted.has(row.domain)) {
          row.last_scanned_at = null;
        }
      }
    }
    return { success: true as const, meta: { changes: 1 } };
  };

  const makeBound = (sql: string, params: unknown[]): BoundStmt => ({
    sql,
    params,
    run: () => applyWrite(sql, params),
    first: async <T>() => {
      if (/SELECT \* FROM domains WHERE user_id = \? AND domain/i.test(sql)) {
        return (domainStore.find(
          (d) => d.user_id === params[0] && d.domain === params[1],
        ) ?? null) as T | null;
      }
      if (
        /^\s*SELECT COUNT\(\*\) AS n FROM domains WHERE user_id = \?/i.test(sql)
      ) {
        const userId = params[0] as string;
        return {
          n: domainStore.filter((d) => d.user_id === userId).length,
        } as T;
      }
      return null as T | null;
    },
    all: async <T>() => {
      if (
        /^\s*SELECT domain FROM domains WHERE user_id = \? AND domain IN/i.test(
          sql,
        )
      ) {
        const [userId, ...wanted] = params as [string, ...string[]];
        const wantedSet = new Set(wanted);
        const rows = domainStore
          .filter((d) => d.user_id === userId && wantedSet.has(d.domain))
          .map((d) => ({ domain: d.domain }));
        return { results: rows as T[] };
      }
      return { results: [] as T[] };
    },
  });

  return {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => makeBound(sql, params),
    }),
    batch: async (stmts: BoundStmt[]) => {
      const out = [];
      for (const stmt of stmts) {
        out.push(await stmt.run());
      }
      return out;
    },
  } as unknown as D1Database;
}

const okScan = (domain: string) => ({
  grade: "B",
  breakdown: { factors: [{ name: "dmarc", status: "pass" }] },
  protocols: { dmarc: { status: "pass" } },
  domain,
});

beforeEach(() => {
  domainStore = [];
  scanHistory = [];
  nextId = 1;
});

describe("processBulkScan", () => {
  it("rejects when more than BULK_TOTAL_CAP domains submitted", async () => {
    const tooMany = Array.from(
      { length: BULK_TOTAL_CAP + 1 },
      (_, i) => `d${i}.example`,
    );
    const out = await processBulkScan({
      db: makeDb(),
      userId: "user_1",
      rawDomains: tooMany,
      scanFn: vi.fn(async (d) => okScan(d)),
    });
    expect(isCapExceeded(out)).toBe(true);
    if (isCapExceeded(out)) {
      expect(out.cap).toBe(BULK_TOTAL_CAP);
      expect(out.submitted).toBe(BULK_TOTAL_CAP + 1);
    }
  });

  it("returns one invalid entry per malformed input, dedup'd", async () => {
    const scanFn = vi.fn(async (d: string) => okScan(d));
    const out = await processBulkScan({
      db: makeDb(),
      userId: "user_1",
      rawDomains: ["not a domain", "not a domain", "  ", "@@@"],
      scanFn,
    });
    if (isCapExceeded(out)) throw new Error("unexpected cap");
    expect(out.results.filter((r) => r.status === "invalid")).toHaveLength(2);
    expect(out.accepted).toBe(0);
    expect(scanFn).not.toHaveBeenCalled();
  });

  it("scans valid domains in-band (status=scanned, with grade)", async () => {
    const scanFn = vi.fn(async (d: string) => okScan(d));
    const out = await processBulkScan({
      db: makeDb(),
      userId: "user_1",
      rawDomains: ["a.example", "b.example", "c.example"],
      scanFn,
    });
    if (isCapExceeded(out)) throw new Error("unexpected cap");
    expect(out.accepted).toBe(3);
    expect(out.rejected).toBe(0);
    const scanned = out.results.filter((r) => r.status === "scanned");
    expect(scanned).toHaveLength(3);
    expect(scanned.every((r) => r.grade === "B")).toBe(true);
    expect(scanHistory).toHaveLength(3);
    expect(domainStore).toHaveLength(3);
    expect(domainStore.every((d) => d.is_free === 0)).toBe(true);
  });

  it("queues overflow existing watchlist domains for cron by clearing last_scanned_at", async () => {
    const now = 1_700_000_000;
    const existing = Array.from({ length: 35 }, (_, i) => ({
      id: i + 1,
      user_id: "user_1",
      domain: `d${i}.example`,
      is_free: 0,
      scan_frequency: "weekly",
      last_scanned_at: now,
      last_grade: "A",
    }));
    domainStore.push(...existing);

    const scanFn = vi.fn(async (d: string) => okScan(d));
    const out = await processBulkScan({
      db: makeDb(),
      userId: "user_1",
      rawDomains: existing.map((d) => d.domain),
      scanFn,
      inBandCap: 30,
      batchSize: 10,
      watchlistCap: 1000,
    });
    if (isCapExceeded(out)) throw new Error("unexpected cap");

    const scanned = out.results.filter((r) => r.status === "scanned");
    const queued = out.results.filter((r) => r.status === "queued");
    expect(scanned).toHaveLength(30);
    expect(queued).toHaveLength(5);
    expect(scanFn).toHaveBeenCalledTimes(30);

    for (const q of queued) {
      const row = domainStore.find((d) => d.domain === q.domain);
      expect(row?.last_scanned_at).toBeNull();
    }
    for (const s of scanned) {
      const row = domainStore.find((d) => d.domain === s.domain);
      expect(row?.last_scanned_at).not.toBeNull();
    }
  });

  it("queues anything beyond inBandCap and flips status=queued", async () => {
    const scanFn = vi.fn(async (d: string) => okScan(d));
    const submitted = Array.from({ length: 35 }, (_, i) => `d${i}.example`);
    const out = await processBulkScan({
      db: makeDb(),
      userId: "user_1",
      rawDomains: submitted,
      scanFn,
      inBandCap: 30,
      batchSize: 10,
      // Watchlist cap raised so this test exercises inBandCap → queued
      // behavior without colliding with the watchlist limit (default 25).
      watchlistCap: 1000,
    });
    if (isCapExceeded(out)) throw new Error("unexpected cap");
    expect(out.accepted).toBe(35);
    expect(out.rejected).toBe(0);
    const scanned = out.results.filter((r) => r.status === "scanned");
    const queued = out.results.filter((r) => r.status === "queued");
    expect(scanned).toHaveLength(30);
    expect(queued).toHaveLength(5);
    // Queued entries land as watchlist rows with last_scanned_at = null so the
    // cron picks them up on the next pass (NULLS FIRST in getDueDomains).
    for (const q of queued) {
      const row = domainStore.find((d) => d.domain === q.domain);
      expect(row).toBeDefined();
      expect(row?.last_scanned_at).toBeNull();
    }
    expect(scanHistory).toHaveLength(30);
  });

  it("isolates per-domain scan failures", async () => {
    const scanFn = vi.fn(async (d: string) => {
      if (d === "broken.example") throw new Error("DNS exploded");
      return okScan(d);
    });
    const out = await processBulkScan({
      db: makeDb(),
      userId: "user_1",
      rawDomains: ["a.example", "broken.example", "c.example"],
      scanFn,
      batchSize: 10,
    });
    if (isCapExceeded(out)) throw new Error("unexpected cap");
    const scanned = out.results.filter((r) => r.status === "scanned");
    const errors = out.results.filter((r) => r.status === "error");
    expect(scanned.map((r) => r.domain).sort()).toEqual([
      "a.example",
      "c.example",
    ]);
    expect(errors).toHaveLength(1);
    expect(errors[0].domain).toBe("broken.example");
    expect(out.accepted).toBe(2);
    expect(out.rejected).toBe(1);
  });

  it("reuses an existing watchlist row instead of creating a duplicate", async () => {
    domainStore.push({
      id: 99,
      user_id: "user_1",
      domain: "already.example",
      is_free: 0,
      scan_frequency: "weekly",
      last_scanned_at: 1700000000,
      last_grade: "A",
    });
    const out = await processBulkScan({
      db: makeDb(),
      userId: "user_1",
      rawDomains: ["already.example"],
      scanFn: async (d) => okScan(d),
    });
    if (isCapExceeded(out)) throw new Error("unexpected cap");
    expect(
      domainStore.filter(
        (d) => d.user_id === "user_1" && d.domain === "already.example",
      ),
    ).toHaveLength(1);
    expect(scanHistory).toHaveLength(1);
    expect(scanHistory[0].domain_id).toBe(99);
  });

  it("normalizes input and dedupes (case + whitespace)", async () => {
    const scanFn = vi.fn(async (d: string) => okScan(d));
    const out = await processBulkScan({
      db: makeDb(),
      userId: "user_1",
      rawDomains: [
        "Example.com",
        "EXAMPLE.com",
        "example.com",
        "  example.com  ",
      ],
      scanFn,
    });
    if (isCapExceeded(out)) throw new Error("unexpected cap");
    const scanned = out.results.filter((r) => r.status === "scanned");
    expect(scanned).toHaveLength(1);
    expect(scanned[0].domain).toBe("example.com");
    expect(scanFn).toHaveBeenCalledTimes(1);
  });

  it("processes the full inBandCap when exactly at the limit", async () => {
    const scanFn = vi.fn(async (d: string) => okScan(d));
    const submitted = Array.from(
      { length: BULK_IN_BAND_CAP },
      (_, i) => `d${i}.example`,
    );
    const out = await processBulkScan({
      db: makeDb(),
      userId: "user_1",
      rawDomains: submitted,
      scanFn,
      batchSize: 10,
      // Same intent as the queued test above — exercise inBandCap, not the
      // watchlist cap.
      watchlistCap: 1000,
    });
    if (isCapExceeded(out)) throw new Error("unexpected cap");
    expect(out.accepted).toBe(BULK_IN_BAND_CAP);
    expect(scanFn).toHaveBeenCalledTimes(BULK_IN_BAND_CAP);
    expect(out.results.every((r) => r.status === "scanned")).toBe(true);
  });

  describe("watchlist cap enforcement", () => {
    it("rejects net-new domains beyond the remaining slots as 'Watchlist limit reached'", async () => {
      const scanFn = vi.fn(async (d: string) => okScan(d));
      const out = await processBulkScan({
        db: makeDb(),
        userId: "user_1",
        rawDomains: ["a.example", "b.example", "c.example", "d.example"],
        scanFn,
        watchlistCap: 2,
      });
      if (isCapExceeded(out)) throw new Error("unexpected cap");
      const scanned = out.results.filter((r) => r.status === "scanned");
      const rejected = out.results.filter(
        (r) => r.status === "error" && r.error === "Watchlist limit reached",
      );
      expect(scanned).toHaveLength(2);
      expect(rejected.map((r) => r.domain)).toEqual(["c.example", "d.example"]);
      expect(scanFn).toHaveBeenCalledTimes(2);
      expect(domainStore).toHaveLength(2);
    });

    it("rejects everything new when the user is already at or above cap (grandfathered)", async () => {
      // Grandfathered Pro user already over a tighter cap.
      for (let i = 0; i < 5; i++) {
        domainStore.push({
          id: i + 1,
          user_id: "user_1",
          domain: `legacy${i}.example`,
          is_free: 0,
          scan_frequency: "weekly",
          last_scanned_at: 1700000000,
          last_grade: "A",
        });
      }
      const scanFn = vi.fn(async (d: string) => okScan(d));
      const out = await processBulkScan({
        db: makeDb(),
        userId: "user_1",
        rawDomains: ["new1.example", "new2.example"],
        scanFn,
        watchlistCap: 3,
      });
      if (isCapExceeded(out)) throw new Error("unexpected cap");
      const rejected = out.results.filter(
        (r) => r.status === "error" && r.error === "Watchlist limit reached",
      );
      expect(rejected.map((r) => r.domain)).toEqual([
        "new1.example",
        "new2.example",
      ]);
      expect(scanFn).not.toHaveBeenCalled();
      // Existing rows preserved — grandfather behavior.
      expect(domainStore).toHaveLength(5);
    });

    it("re-scans domains the user already owns even when at cap (slots not consumed)", async () => {
      domainStore.push({
        id: 1,
        user_id: "user_1",
        domain: "owned.example",
        is_free: 0,
        scan_frequency: "weekly",
        last_scanned_at: 1700000000,
        last_grade: "A",
      });
      const scanFn = vi.fn(async (d: string) => okScan(d));
      const out = await processBulkScan({
        db: makeDb(),
        userId: "user_1",
        rawDomains: ["owned.example", "newly.example"],
        scanFn,
        watchlistCap: 1,
      });
      if (isCapExceeded(out)) throw new Error("unexpected cap");
      const scanned = out.results.filter((r) => r.status === "scanned");
      const rejected = out.results.filter(
        (r) => r.status === "error" && r.error === "Watchlist limit reached",
      );
      // Re-scan of the existing domain succeeds despite cap == current count;
      // only the net-new domain is rejected.
      expect(scanned.map((r) => r.domain)).toEqual(["owned.example"]);
      expect(rejected.map((r) => r.domain)).toEqual(["newly.example"]);
      // No new row inserted.
      expect(domainStore).toHaveLength(1);
    });

    it("accepts the 26th domain when watchlistCap is raised via per-user override", async () => {
      // Simulate a Pro user already at their default 25-domain limit.
      for (let i = 0; i < 25; i++) {
        domainStore.push({
          id: i + 1,
          user_id: "user_1",
          domain: `d${i}.example`,
          is_free: 0,
          scan_frequency: "weekly",
          last_scanned_at: 1700000000,
          last_grade: "A",
        });
      }
      const scanFn = vi.fn(async (d: string) => okScan(d));
      const out = await processBulkScan({
        db: makeDb(),
        userId: "user_1",
        rawDomains: ["new26.example"],
        scanFn,
        watchlistCap: 50, // raised by max_domains_override via watchlistCapFor
      });
      if (isCapExceeded(out)) throw new Error("unexpected cap");
      const scanned = out.results.filter((r) => r.status === "scanned");
      const rejected = out.results.filter(
        (r) => r.status === "error" && r.error === "Watchlist limit reached",
      );
      expect(scanned.map((r) => r.domain)).toEqual(["new26.example"]);
      expect(rejected).toHaveLength(0);
      expect(domainStore).toHaveLength(26);
    });
  });

  it("returns empty results for an empty submission", async () => {
    const out = await processBulkScan({
      db: makeDb(),
      userId: "user_1",
      rawDomains: [],
      scanFn: vi.fn(),
    });
    if (isCapExceeded(out)) throw new Error("unexpected cap");
    expect(out.accepted).toBe(0);
    expect(out.rejected).toBe(0);
    expect(out.results).toEqual([]);
  });
});
