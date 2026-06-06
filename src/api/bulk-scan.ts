import {
  countDomainsByUser,
  createDomain,
  createDomains,
  findExistingDomainsForUser,
  getDomainByUserAndName,
  markDomainsDueForRescan,
} from "../db/domains.js";
import { recordScan } from "../db/scans.js";
import { scan } from "../orchestrator.js";
import { normalizeDomain } from "../shared/domain.js";
import { PRO_WATCHLIST_CAP } from "../shared/limits.js";
import type { ScoringConfig } from "../shared/scoring.js";

// Phase 4c — bulk scan core. Two callers (POST /api/bulk-scan with bearer
// auth, POST /dashboard/bulk with session auth) share this logic; both must
// already have proven the requesting user is on the Pro plan before invoking.

export const BULK_TOTAL_CAP = 100;
export const BULK_IN_BAND_CAP = 30;
export const BULK_BATCH_SIZE = 10;

export type BulkResultStatus = "scanned" | "queued" | "error" | "invalid";

export interface BulkResultEntry {
  // The normalized domain when valid; the raw input when invalid.
  domain: string;
  status: BulkResultStatus;
  // Set when status === "scanned".
  grade?: string;
  // Set when status === "error" or "invalid". String-only — never echoes raw
  // user input verbatim, so this field is safe for both HTML and JSON callers.
  error?: string;
}

export interface BulkScanResponse {
  accepted: number;
  rejected: number;
  results: BulkResultEntry[];
}

interface ScanLike {
  grade: string;
  breakdown: { factors: unknown };
  protocols: unknown;
}

export interface ProcessBulkScanInput {
  db: D1Database;
  userId: string;
  rawDomains: string[];
  // Injectable for tests — defaults to the orchestrator's `scan`.
  scanFn?: (domain: string) => Promise<ScanLike>;
  // Self-host scoring rubric override, forwarded to scan() (issue #25).
  scoringConfig?: Partial<ScoringConfig>;
  now?: number;
  // Knobs for tests; defaults match the production caps above.
  inBandCap?: number;
  batchSize?: number;
  // Plan-based watchlist cap. Net-new domains beyond `cap - currentCount`
  // are returned as error rows tagged "Watchlist limit reached" rather than
  // silently inserted. Re-submits of domains the user already owns don't
  // consume slots. Defaults to PRO_WATCHLIST_CAP because both bulk callers
  // are Pro-only.
  watchlistCap?: number;
}

export interface BulkCapExceededError {
  capExceeded: true;
  submitted: number;
  cap: number;
}

export type ProcessBulkScanOutcome = BulkScanResponse | BulkCapExceededError;

export function isCapExceeded(
  outcome: ProcessBulkScanOutcome,
): outcome is BulkCapExceededError {
  return (outcome as BulkCapExceededError).capExceeded === true;
}

// Splits input into normalized-valid + invalid + dedup, then dispatches up to
// `inBandCap` for synchronous scanning and the rest into the cron queue (a
// `domains` row with last_scanned_at = NULL — `getDueDomains` picks those
// up first because of `NULLS FIRST`).
export async function processBulkScan(
  input: ProcessBulkScanInput,
): Promise<ProcessBulkScanOutcome> {
  const scanFn =
    input.scanFn ??
    ((domain: string) => scan(domain, [], input.scoringConfig ?? {}));
  const inBandCap = input.inBandCap ?? BULK_IN_BAND_CAP;
  const batchSize = input.batchSize ?? BULK_BATCH_SIZE;

  if (input.rawDomains.length > BULK_TOTAL_CAP) {
    return {
      capExceeded: true,
      submitted: input.rawDomains.length,
      cap: BULK_TOTAL_CAP,
    };
  }

  // Normalize + dedupe in input order. Invalid entries become result rows
  // immediately so the caller sees one row per submitted line.
  const seenValid = new Set<string>();
  const seenInvalid = new Set<string>();
  const valid: string[] = [];
  const invalidResults: BulkResultEntry[] = [];

  for (const raw of input.rawDomains) {
    const trimmed = typeof raw === "string" ? raw.trim() : "";
    if (trimmed === "") continue;
    const normalized = normalizeDomain(trimmed);
    if (!normalized) {
      // Echo the raw input back so the user can fix it in the form. Capped at
      // 253 chars (the longest a valid domain could be) to bound JSON payload.
      const safe = trimmed.slice(0, 253);
      if (seenInvalid.has(safe)) continue;
      seenInvalid.add(safe);
      invalidResults.push({
        domain: safe,
        status: "invalid",
        error: "Not a valid domain",
      });
      continue;
    }
    if (seenValid.has(normalized)) continue;
    seenValid.add(normalized);
    valid.push(normalized);
  }

  // Watchlist-cap enforcement. Pre-lookup which submitted domains the user
  // already owns so a user near their cap can still re-scan tracked domains
  // without seeing them rejected. Net-new domains past the remaining slots
  // become error rows the caller surfaces row-by-row.
  const cap = input.watchlistCap ?? PRO_WATCHLIST_CAP;
  const currentCount = await countDomainsByUser(input.db, input.userId);
  const existingSet = await findExistingDomainsForUser(
    input.db,
    input.userId,
    valid,
  );
  const repeatDomains: string[] = [];
  const newDomains: string[] = [];
  for (const d of valid) {
    if (existingSet.has(d)) repeatDomains.push(d);
    else newDomains.push(d);
  }
  const remainingSlots = Math.max(0, cap - currentCount);
  const acceptedNew = newDomains.slice(0, remainingSlots);
  const capRejected: BulkResultEntry[] = newDomains
    .slice(remainingSlots)
    .map((d) => ({
      domain: d,
      status: "error",
      error: "Watchlist limit reached",
    }));
  const accepted = [...repeatDomains, ...acceptedNew];

  const inBand = accepted.slice(0, inBandCap);
  const queued = accepted.slice(inBandCap);

  const inBandResults: BulkResultEntry[] = [];
  for (let i = 0; i < inBand.length; i += batchSize) {
    const batch = inBand.slice(i, i + batchSize);
    const outcomes = await Promise.allSettled(
      batch.map((domain) => scanOne(input.db, input.userId, domain, scanFn)),
    );
    for (let j = 0; j < outcomes.length; j++) {
      const outcome = outcomes[j];
      const domain = batch[j];
      if (outcome.status === "fulfilled") {
        inBandResults.push(outcome.value);
      } else {
        inBandResults.push({
          domain,
          status: "error",
          error: "Scan failed",
        });
      }
    }
  }

  const queuedResults: BulkResultEntry[] = [];

  // Deduplicate queued domains to prevent constraint violations
  // in the bulk insert if the same domain was specified multiple times.
  // Note: 'queued' is already deduped during the normalization phase
  // (via seenValid set), but we use a Set here for clarity.
  const uniqueQueued = Array.from(new Set(queued));

  if (uniqueQueued.length > 0) {
    // Determine which queued domains actually need to be inserted.
    // existingSet already contains all valid domains the user previously owned.
    const queuedToInsert = uniqueQueued.filter(
      (domain) => !existingSet.has(domain),
    );
    const queuedExisting = uniqueQueued.filter((domain) =>
      existingSet.has(domain),
    );

    try {
      if (queuedToInsert.length > 0) {
        await createDomains(
          input.db,
          queuedToInsert.map((domain) => ({
            userId: input.userId,
            domain,
            isFree: false,
          })),
        );
      }
      if (queuedExisting.length > 0) {
        await markDomainsDueForRescan(input.db, input.userId, queuedExisting);
      }

      for (const domain of uniqueQueued) {
        queuedResults.push({ domain, status: "queued" });
      }
    } catch {
      // Fallback: If the bulk insert fails (e.g. D1 error), try inserting them one by one.
      for (const domain of uniqueQueued) {
        try {
          if (existingSet.has(domain)) {
            await markDomainsDueForRescan(input.db, input.userId, [domain]);
          } else {
            // ensureDomainRow is idempotent and handles conflicts
            await ensureDomainRow(input.db, input.userId, domain);
          }
          queuedResults.push({ domain, status: "queued" });
        } catch {
          queuedResults.push({
            domain,
            status: "error",
            error: "Could not queue domain",
          });
        }
      }
    }
  }

  // Stable order: invalid first (so the user sees them), then in-band,
  // then queued, then cap-rejected last. This matches what the dashboard
  // form will render top-to-bottom and keeps the over-cap rows together.
  const results = [
    ...invalidResults,
    ...inBandResults,
    ...queuedResults,
    ...capRejected,
  ];
  const acceptedCount = results.filter(
    (r) => r.status === "scanned" || r.status === "queued",
  ).length;
  const rejectedCount = results.length - acceptedCount;
  return { accepted: acceptedCount, rejected: rejectedCount, results };
}

async function scanOne(
  db: D1Database,
  userId: string,
  domain: string,
  scanFn: (domain: string) => Promise<ScanLike>,
): Promise<BulkResultEntry> {
  const owned = await ensureDomainRow(db, userId, domain);
  const result = await scanFn(domain);
  await recordScan(db, {
    domainId: owned.id,
    grade: result.grade,
    scoreFactors: result.breakdown.factors,
    protocolResults: result.protocols,
  });
  return { domain, status: "scanned", grade: result.grade };
}

// Idempotent watchlist insert: returns the existing row if present, otherwise
// creates one (Pro plan, weekly cadence) and re-fetches to get the row id. We
// look up after insert rather than relying on D1's last_row_id because the
// helper is async and other concurrent inserts could race the cursor.
async function ensureDomainRow(
  db: D1Database,
  userId: string,
  domain: string,
): Promise<{ id: number }> {
  const existing = await getDomainByUserAndName(db, userId, domain);
  if (existing) return { id: existing.id };
  await createDomain(db, { userId, domain, isFree: false });
  const created = await getDomainByUserAndName(db, userId, domain);
  if (!created) {
    throw new Error("Domain row missing after insert");
  }
  return { id: created.id };
}
