import * as Sentry from "@sentry/cloudflare";
import {
  type AlertPayload,
  detectGradeDrop,
  detectProtocolRegressions,
} from "../alerts/detector.js";
import type { ScanResult } from "../analyzers/types.js";
import { recordAlert } from "../db/alerts.js";
import { type Domain, getDueDomains } from "../db/domains.js";
import { recordScan } from "../db/scans.js";
import { scan as defaultScan } from "../orchestrator.js";
import { fireScanCompletedWebhook } from "../webhooks/triggers.js";

export interface RescanResult {
  scanned: number;
  alerts: number;
  errors: number;
}

interface RescanDeps {
  db: D1Database;
  now: number;
  batchSize?: number;
  scanFn?: (domain: string) => Promise<ScanResult>;
}

interface PreviousProtocolStatuses {
  dmarc?: string;
  spf?: string;
  dkim?: string;
  bimi?: string;
  mta_sts?: string;
}

// Reads the most recent scan_history row's protocol_results (parsed JSON) so
// we can diff protocol statuses. Returns null on first-ever scan or when the
// row is missing / unparseable — detectProtocolRegressions handles null.
async function getPreviousProtocolStatuses(
  db: D1Database,
  domainId: number,
): Promise<PreviousProtocolStatuses | null> {
  const row = await db
    .prepare(
      "SELECT protocol_results FROM scan_history WHERE domain_id = ? ORDER BY scanned_at DESC LIMIT 1",
    )
    .bind(domainId)
    .first<{ protocol_results: string | null }>();
  if (!row?.protocol_results) return null;
  try {
    const parsed = JSON.parse(row.protocol_results) as Record<
      string,
      { status?: string }
    >;
    return {
      dmarc: parsed.dmarc?.status,
      spf: parsed.spf?.status,
      dkim: parsed.dkim?.status,
      bimi: parsed.bimi?.status,
      mta_sts: parsed.mta_sts?.status,
    };
  } catch {
    return null;
  }
}

function extractStatuses(result: ScanResult): PreviousProtocolStatuses {
  return {
    dmarc: result.protocols.dmarc.status,
    spf: result.protocols.spf.status,
    dkim: result.protocols.dkim.status,
    bimi: result.protocols.bimi.status,
    mta_sts: result.protocols.mta_sts.status,
  };
}

async function rescanOne(
  deps: RescanDeps,
  domain: Domain,
): Promise<{ alerts: number; error?: unknown }> {
  const scanFn = deps.scanFn ?? defaultScan;
  const prevStatuses = await getPreviousProtocolStatuses(deps.db, domain.id);

  let result: ScanResult;
  try {
    result = await scanFn(domain.domain);
  } catch (err) {
    return { alerts: 0, error: err };
  }

  await recordScan(deps.db, {
    domainId: domain.id,
    grade: result.grade,
    scoreFactors: result.breakdown.factors,
    protocolResults: result.protocols,
    scannedAt: deps.now,
  });

  await fireScanCompletedWebhook(deps.db, domain.user_id, {
    domain: domain.domain,
    grade: result.grade,
    scanId: domain.id,
    trigger: "cron",
  });

  const alerts: AlertPayload[] = [];
  const gradeAlert = detectGradeDrop(domain.last_grade, result.grade);
  if (gradeAlert) alerts.push(gradeAlert);
  const protocolAlerts = detectProtocolRegressions(
    prevStatuses,
    extractStatuses(result),
  );
  alerts.push(...protocolAlerts);

  for (const alert of alerts) {
    await recordAlert(deps.db, {
      domainId: domain.id,
      type: alert.type,
      previousValue: alert.previousValue,
      newValue: alert.newValue,
      createdAt: deps.now,
    });
  }

  return { alerts: alerts.length };
}

// Entry point for the scheduled() handler. Runs the rescan pipeline across
// all due domains in bounded batches. Failures on individual domains are
// caught and counted — one domain's DNS timeout must not stop the rest.
//
// batchSize default is 5: each scan fires ~6 concurrent DNS queries, so
// 5 × 6 = ~30 concurrent lookups per batch — well within the workerd
// node:dns polyfill's capacity. The original value of 25 (~150 concurrent
// lookups) overwhelmed the resolver and caused every query in the batch to
// time out, producing a false-fail cascade across all monitored domains.
// See: https://github.com/schmug/dmarcheck/issues/240
export async function runDueRescans(deps: RescanDeps): Promise<RescanResult> {
  const batchSize = deps.batchSize ?? 5;
  const due = await getDueDomains(deps.db, deps.now);
  let scanned = 0;
  let alertCount = 0;
  let errors = 0;

  Sentry.addBreadcrumb({
    category: "cron.rescan",
    message: `Starting rescan: ${due.length} domains, batchSize=${batchSize}`,
    data: { total: due.length, batchSize },
    level: "info",
  });

  for (let i = 0; i < due.length; i += batchSize) {
    const batch = due.slice(i, i + batchSize);
    Sentry.addBreadcrumb({
      category: "cron.rescan",
      message: `Batch ${Math.floor(i / batchSize) + 1}: scanning ${batch.map((d) => d.domain).join(", ")}`,
      data: {
        batchIndex: Math.floor(i / batchSize),
        domains: batch.map((d) => d.domain),
      },
      level: "info",
    });
    const outcomes = await Promise.allSettled(
      batch.map((d) => rescanOne(deps, d)),
    );
    for (const outcome of outcomes) {
      if (outcome.status === "rejected") {
        errors += 1;
        Sentry.captureException(outcome.reason);
        continue;
      }
      if (outcome.value.error) {
        errors += 1;
        Sentry.captureException(outcome.value.error);
        continue;
      }
      scanned += 1;
      alertCount += outcome.value.alerts;
    }
  }

  Sentry.addBreadcrumb({
    category: "cron.rescan",
    message: `Rescan complete: scanned=${scanned}, alerts=${alertCount}, errors=${errors}`,
    data: { scanned, alerts: alertCount, errors },
    level: errors > 0 ? "warning" : "info",
  });

  return { scanned, alerts: alertCount, errors };
}
