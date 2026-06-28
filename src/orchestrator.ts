import * as Sentry from "@sentry/cloudflare";
import { analyzeBimi, prefetchBimiDns } from "./analyzers/bimi.js";
import { analyzeDane } from "./analyzers/dane.js";
import { analyzeDkim } from "./analyzers/dkim.js";
import { analyzeDmarc } from "./analyzers/dmarc.js";
import { analyzeDnsbl } from "./analyzers/dnsbl.js";
import { analyzeDnssec } from "./analyzers/dnssec.js";
import { analyzeMtaSts } from "./analyzers/mta-sts.js";
import { analyzeMx } from "./analyzers/mx.js";
import { checkMxMtaStsConsistency } from "./analyzers/mx-mta-sts-consistency.js";
import { analyzeSecurityTxt } from "./analyzers/security-txt.js";
import { analyzeSpf } from "./analyzers/spf.js";
import { analyzeTlsRpt } from "./analyzers/tls-rpt.js";
import type {
  BimiResult,
  DaneResult,
  DkimResult,
  DmarcResult,
  DnsblResult,
  DnssecResult,
  MtaStsResult,
  MxResult,
  ScanResult,
  SecurityTxtResult,
  SpfResult,
  TlsRptResult,
  Validation,
} from "./analyzers/types.js";
import { queryTxt } from "./dns/client.js";
import {
  DEFAULT_SCAN_LIMITS,
  ScanBudget,
  type ScanLimits,
} from "./dns/scan-budget.js";
import { computeGradeBreakdown, type ScoringConfig } from "./shared/scoring.js";

export type ProtocolId =
  | "mx"
  | "dmarc"
  | "spf"
  | "dkim"
  | "bimi"
  | "mta_sts"
  | "security_txt"
  | "tls_rpt"
  | "dnssec"
  | "dane"
  | "dnsbl";
export type ProtocolResult =
  | MxResult
  | DmarcResult
  | SpfResult
  | DkimResult
  | BimiResult
  | MtaStsResult
  | SecurityTxtResult
  | TlsRptResult
  | DnssecResult
  | DaneResult
  | DnsblResult;

export const PROTOCOL_LABEL: Record<ProtocolId, string> = {
  mx: "MX",
  dmarc: "DMARC",
  spf: "SPF",
  dkim: "DKIM",
  bimi: "BIMI",
  mta_sts: "MTA-STS",
  security_txt: "security.txt",
  tls_rpt: "TLS-RPT",
  dnssec: "DNSSEC",
  dane: "DANE/TLSA",
  dnsbl: "DNSBL/Spamhaus",
};

function analyzerErrorValidation(id: ProtocolId, message: string): Validation {
  return {
    status: "fail",
    message: `${PROTOCOL_LABEL[id]} analysis could not be completed (analyzer_error): ${message}`,
  };
}

// Synthetic "this analyzer threw" results. A single analyzer rejecting must not
// abort the whole scan (#378) — instead each protocol's outcome is isolated and
// a thrown error surfaces as a `status: "fail"` result with an explanatory
// validation. Types that carry `lookup_error` also tag it `analyzer_error` so
// scoring treats DMARC/SPF/MX/TLS-RPT as "could not verify" rather than "absent".
const ERROR_RESULTS = {
  dmarc: (m: string): DmarcResult => ({
    status: "fail",
    record: null,
    tags: null,
    validations: [analyzerErrorValidation("dmarc", m)],
    lookup_error: { code: "analyzer_error", message: m },
  }),
  spf: (m: string): SpfResult => ({
    status: "fail",
    record: null,
    lookups_used: 0,
    lookup_limit: 10,
    include_tree: null,
    validations: [analyzerErrorValidation("spf", m)],
    lookup_error: { code: "analyzer_error", message: m },
  }),
  dkim: (m: string): DkimResult => ({
    status: "fail",
    selectors: {},
    validations: [analyzerErrorValidation("dkim", m)],
  }),
  bimi: (m: string): BimiResult => ({
    status: "fail",
    record: null,
    tags: null,
    validations: [analyzerErrorValidation("bimi", m)],
  }),
  mta_sts: (m: string): MtaStsResult => ({
    status: "fail",
    dns_record: null,
    policy: null,
    validations: [analyzerErrorValidation("mta_sts", m)],
  }),
  mx: (m: string): MxResult => ({
    status: "fail",
    records: [],
    providers: [],
    validations: [analyzerErrorValidation("mx", m)],
    lookup_error: { code: "analyzer_error", message: m },
  }),
  security_txt: (m: string): SecurityTxtResult => ({
    status: "fail",
    source_url: null,
    signed: false,
    fields: null,
    validations: [analyzerErrorValidation("security_txt", m)],
  }),
  tls_rpt: (m: string): TlsRptResult => ({
    status: "fail",
    record: null,
    tags: null,
    validations: [analyzerErrorValidation("tls_rpt", m)],
    lookup_error: { code: "analyzer_error", message: m },
  }),
  dnssec: (m: string): DnssecResult => ({
    status: "fail",
    signed: false,
    validated: false,
    validations: [analyzerErrorValidation("dnssec", m)],
    lookup_error: { code: "analyzer_error", message: m },
  }),
  dane: (m: string): DaneResult => ({
    status: "fail",
    hosts: [],
    validations: [analyzerErrorValidation("dane", m)],
    lookup_error: { code: "analyzer_error", message: m },
  }),
  dnsbl: (m: string): DnsblResult => ({
    status: "fail",
    checked: 0,
    listed: [],
    validations: [analyzerErrorValidation("dnsbl", m)],
    lookup_error: { code: "analyzer_error", message: m },
  }),
} as const;

// Turn a possibly-rejecting analyzer promise into one that always resolves —
// to its real result, or to a synthetic fail result if it threw. Logs a Sentry
// breadcrumb so the failure is observable even though the scan continues.
function settle<T extends ProtocolResult>(
  id: ProtocolId,
  promise: Promise<T>,
  fallback: (message: string) => T,
): Promise<T> {
  return promise.catch((err) => {
    const message = err instanceof Error ? err.message : String(err);
    Sentry.addBreadcrumb({
      category: "analyzer.error",
      message: `${id}: ${message}`,
      data: { protocol: id, error: message },
      level: "error",
    });
    return fallback(message);
  });
}

// GHSA-f828-8wf8-vqp2 — overall scan deadline. Each analyzer promise here has
// already been through `settle`, so it never rejects. We race it against the
// scan-wide abort signal: if the deadline fires first, the analyzer resolves to
// its synthetic fallback so the scan returns PARTIAL results instead of hanging
// on a slow/attacker-controlled resolver. The real (slow) analyzer promise is
// left to resolve on its own and is ignored — the shared ScanBudget, which also
// holds this signal, already prevents it from issuing any further DNS queries.
const DEADLINE_NOTE = "scan deadline exceeded — partial result";

function raceDeadline<T extends ProtocolResult>(
  settled: Promise<T>,
  fallback: (message: string) => T,
  signal: AbortSignal,
): Promise<T> {
  if (signal.aborted) return Promise.resolve(fallback(DEADLINE_NOTE));
  return new Promise<T>((resolve) => {
    const onAbort = () => resolve(fallback(DEADLINE_NOTE));
    signal.addEventListener("abort", onAbort, { once: true });
    settled.then((result) => {
      signal.removeEventListener("abort", onAbort);
      resolve(result);
    });
  });
}

async function buildScanResult(
  domain: string,
  protocols: ScanResult["protocols"],
  config: Partial<ScoringConfig>,
  budget?: ScanBudget,
): Promise<ScanResult> {
  // Cross-check MX hosts against MTA-STS policy patterns (RFC 8461 §3.4)
  const consistencyValidations = checkMxMtaStsConsistency(
    protocols.mx,
    protocols.mta_sts,
  );
  if (consistencyValidations.length > 0) {
    protocols.mta_sts.validations.push(...consistencyValidations);
    // Re-derive status in case new warn validations were added
    const hasFailure = protocols.mta_sts.validations.some(
      (v) => v.status === "fail",
    );
    const hasWarn = protocols.mta_sts.validations.some(
      (v) => v.status === "warn",
    );
    protocols.mta_sts.status = hasFailure ? "fail" : hasWarn ? "warn" : "pass";
  }

  const breakdown = computeGradeBreakdown(protocols, config);

  // Easter egg: S grade for A+ domains advertising dmarc.mx
  if (breakdown.grade === "A+") {
    try {
      const txt = await queryTxt(domain, budget);
      if (txt?.entries.some((e) => e.toLowerCase().includes("dmarc.mx"))) {
        breakdown.grade = "S";
      }
    } catch {
      // Silently ignore — don't downgrade the experience for a DNS hiccup
    }
  }

  // ⚡ Bolt Optimization: Use a simple loop instead of Object.values().filter()
  // Reduces intermediate array allocations on the hot path
  let dkimFound = 0;
  for (const name in protocols.dkim.selectors) {
    if (protocols.dkim.selectors[name].found) {
      dkimFound++;
    }
  }
  const dmarcPolicy = protocols.dmarc.tags?.p?.toLowerCase() ?? null;

  return {
    domain,
    timestamp: new Date().toISOString(),
    grade: breakdown.grade,
    breakdown,
    summary: {
      mx_records: protocols.mx.records.length,
      mx_providers: protocols.mx.providers.map((p) => p.name),
      dmarc_policy: dmarcPolicy,
      spf_result: protocols.spf.status,
      spf_lookups: `${protocols.spf.lookups_used}/${protocols.spf.lookup_limit}`,
      dkim_selectors_found: dkimFound,
      bimi_enabled: protocols.bimi.status === "pass",
      mta_sts_mode: protocols.mta_sts.policy?.mode ?? null,
    },
    protocols,
  };
}

export async function scan(
  domain: string,
  customSelectors: string[],
  config: Partial<ScoringConfig>,
  limits?: ScanLimits,
  dqsKey?: string,
): Promise<ScanResult> {
  const { maxDnsQueries, deadlineMs } = limits ?? DEFAULT_SCAN_LIMITS;
  // GHSA-f828-8wf8-vqp2 — bound the whole scan with one deadline + one shared
  // DNS-query pool, so neither total outbound queries nor wall-clock can scale
  // with attacker-controlled input (huge selector lists, rua/ruf-stuffed
  // records). The signal both fires the deadline race below and stops the
  // ScanBudget from issuing any further query once it trips.
  const controller = new AbortController();
  const { signal } = controller;
  const deadlineTimer = setTimeout(() => controller.abort(), deadlineMs);
  const budget = new ScanBudget(maxDnsQueries, signal);

  // settle (isolate one analyzer's rejection, #378) THEN race the deadline:
  // a slow analyzer yields its synthetic fallback instead of stalling the scan.
  const bounded = <T extends ProtocolResult>(
    id: ProtocolId,
    promise: Promise<T>,
    fallback: (message: string) => T,
  ): Promise<T> =>
    raceDeadline(settle(id, promise, fallback), fallback, signal);

  try {
    // Fire all independent DNS queries immediately
    const dmarcPromise = analyzeDmarc(domain, budget);
    const spfPromise = analyzeSpf(domain, budget);
    const mtaStsPromise = analyzeMtaSts(domain, budget);
    const bimiDnsPromise = prefetchBimiDns(domain, budget);
    const mxPromise = analyzeMx(domain, budget);
    const securityTxtPromise = analyzeSecurityTxt(domain);
    const tlsRptPromise = analyzeTlsRpt(domain, budget);
    const dnssecPromise = analyzeDnssec(domain, budget);

    // Chain DKIM off MX so it starts as soon as MX resolves
    // without blocking on unrelated queries
    const dkimPromise = mxPromise.then((mxResult) => {
      Sentry.addBreadcrumb({
        category: "analyzer.complete",
        message: `mx: ${mxResult.status}`,
        data: { protocol: "mx", status: mxResult.status },
        level: "info",
      });
      const providerNames = mxResult.providers.map((p) => p.name);
      return analyzeDkim(domain, customSelectors, providerNames, budget);
    });

    // Chain DANE off MX — TLSA records are queried per MX exchange
    const danePromise = mxPromise.then((mxResult) =>
      analyzeDane(
        domain,
        mxResult.records.map((r) => r.exchange),
        budget,
      ),
    );

    // Chain DNSBL off MX + SPF — IPs come from SPF include tree and MX A records
    const dnsblPromise = Promise.all([mxPromise, spfPromise]).then(
      ([mxResult, spfResult]) =>
        analyzeDnsbl(domain, mxResult, spfResult, dqsKey, budget),
    );

    const bimiPromise = Promise.all([dmarcPromise, bimiDnsPromise]).then(
      ([dmarcResult, bimiDns]) => {
        const dmarcPolicy = dmarcResult.tags?.p?.toLowerCase() ?? null;
        return analyzeBimi(domain, dmarcPolicy, bimiDns, budget);
      },
    );

    // Isolate each analyzer: one rejection surfaces as a synthetic fail result
    // instead of aborting the whole scan (#378). This is the contract the docs
    // describe ("partial results, never abort on a single analyzer error").
    const [
      dmarcResult,
      spfResult,
      dkimResult,
      mtaStsResult,
      bimiResult,
      mxResult,
      securityTxtResult,
      tlsRptResult,
      dnssecResult,
      daneResult,
      dnsblResult,
    ] = await Promise.all([
      bounded("dmarc", dmarcPromise, ERROR_RESULTS.dmarc),
      bounded("spf", spfPromise, ERROR_RESULTS.spf),
      bounded("dkim", dkimPromise, ERROR_RESULTS.dkim),
      bounded("mta_sts", mtaStsPromise, ERROR_RESULTS.mta_sts),
      bounded("bimi", bimiPromise, ERROR_RESULTS.bimi),
      bounded("mx", mxPromise, ERROR_RESULTS.mx),
      bounded("security_txt", securityTxtPromise, ERROR_RESULTS.security_txt),
      bounded("tls_rpt", tlsRptPromise, ERROR_RESULTS.tls_rpt),
      bounded("dnssec", dnssecPromise, ERROR_RESULTS.dnssec),
      bounded("dane", danePromise, ERROR_RESULTS.dane),
      bounded("dnsbl", dnsblPromise, ERROR_RESULTS.dnsbl),
    ]);

    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `dmarc: ${dmarcResult.status}`,
      data: { protocol: "dmarc", status: dmarcResult.status },
      level: "info",
    });
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `spf: ${spfResult.status}`,
      data: { protocol: "spf", status: spfResult.status },
      level: "info",
    });
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `dkim: ${dkimResult.status}`,
      data: { protocol: "dkim", status: dkimResult.status },
      level: "info",
    });
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `mta_sts: ${mtaStsResult.status}`,
      data: { protocol: "mta_sts", status: mtaStsResult.status },
      level: "info",
    });
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `bimi: ${bimiResult.status}`,
      data: { protocol: "bimi", status: bimiResult.status },
      level: "info",
    });
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `security_txt: ${securityTxtResult.status}`,
      data: { protocol: "security_txt", status: securityTxtResult.status },
      level: "info",
    });
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `tls_rpt: ${tlsRptResult.status}`,
      data: { protocol: "tls_rpt", status: tlsRptResult.status },
      level: "info",
    });
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `dnssec: ${dnssecResult.status}`,
      data: { protocol: "dnssec", status: dnssecResult.status },
      level: "info",
    });
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `dane: ${daneResult.status}`,
      data: { protocol: "dane", status: daneResult.status },
      level: "info",
    });
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `dnsbl: ${dnsblResult.status}`,
      data: { protocol: "dnsbl", status: dnsblResult.status },
      level: "info",
    });

    return await buildScanResult(
      domain,
      {
        mx: mxResult,
        dmarc: dmarcResult,
        spf: spfResult,
        dkim: dkimResult,
        bimi: bimiResult,
        mta_sts: mtaStsResult,
        security_txt: securityTxtResult,
        tls_rpt: tlsRptResult,
        dnssec: dnssecResult,
        dane: daneResult,
        dnsbl: dnsblResult,
      },
      config,
      budget,
    );
  } finally {
    // Cancel the deadline timer so it can't fire after an early finish — in the
    // Workers runtime a dangling timer is otherwise wasted work.
    clearTimeout(deadlineTimer);
  }
}

export async function scanStreaming(
  domain: string,
  customSelectors: string[],
  onResult: (id: ProtocolId, result: ProtocolResult) => void,
  config: Partial<ScoringConfig>,
  limits?: ScanLimits,
  dqsKey?: string,
): Promise<ScanResult> {
  const { maxDnsQueries, deadlineMs } = limits ?? DEFAULT_SCAN_LIMITS;
  // GHSA-f828-8wf8-vqp2 — same deadline + shared DNS-query pool as scan() (see
  // there). The SSE contract is preserved under the deadline: protocols that
  // settled early already streamed; any still in flight when the deadline fires
  // stream a synthetic fallback card, so every protocol is emitted exactly once
  // and the client never waits past the deadline.
  const controller = new AbortController();
  const { signal } = controller;
  const deadlineTimer = setTimeout(() => controller.abort(), deadlineMs);
  const budget = new ScanBudget(maxDnsQueries, signal);

  // Emit each protocol's card at most once, and never after the scan has been
  // finalized — guards against both a deadline-fallback/real-result double emit
  // and a slow analyzer resolving after the done event has been sent.
  const emitted = new Set<ProtocolId>();
  let finalized = false;
  const emit = (id: ProtocolId, result: ProtocolResult): void => {
    if (finalized || emitted.has(id)) return;
    emitted.add(id);
    onResult(id, result);
  };

  // settle (#378) → stream the moment it lands → race the deadline, streaming a
  // fallback card for whatever hasn't emitted yet. The settle handler attaches
  // synchronously (before the await below), so fast protocols still stream the
  // instant they complete.
  const streamBounded = <T extends ProtocolResult>(
    id: ProtocolId,
    promise: Promise<T>,
    fallback: (message: string) => T,
  ): Promise<T> => {
    const settled = settle(id, promise, fallback).then((r) => {
      Sentry.addBreadcrumb({
        category: "analyzer.complete",
        message: `${id}: ${r.status}`,
        data: { protocol: id, status: r.status },
        level: "info",
      });
      emit(id, r);
      return r;
    });
    return raceDeadline(settled, fallback, signal).then((r) => {
      emit(id, r);
      return r;
    });
  };

  try {
    // ⚡ Bolt Optimization: Start all independent DNS queries immediately.
    // Previously, the streaming sequence awaited MX resolution before dispatching
    // DKIM *and* blocked the stream from yielding fast protocols (like SPF)
    // until MX finished. Now, all lookups are chained directly from their
    // prerequisites, maximizing concurrency and reducing scan latency.
    const dmarcPromise = analyzeDmarc(domain, budget);
    const spfPromise = analyzeSpf(domain, budget);
    const mtaStsPromise = analyzeMtaSts(domain, budget);
    const bimiDnsPromise = prefetchBimiDns(domain, budget);
    const mxPromise = analyzeMx(domain, budget);
    const securityTxtPromise = analyzeSecurityTxt(domain);
    const tlsRptPromise = analyzeTlsRpt(domain, budget);
    const dnssecPromise = analyzeDnssec(domain, budget);

    // Chain DKIM off MX so it starts as soon as MX resolves
    const dkimPromise = mxPromise.then((mxResult) => {
      const providerNames = mxResult.providers.map((p) => p.name);
      return analyzeDkim(domain, customSelectors, providerNames, budget);
    });

    // Chain DANE off MX — TLSA records are queried per MX exchange
    const danePromise = mxPromise.then((mxResult) =>
      analyzeDane(
        domain,
        mxResult.records.map((r) => r.exchange),
        budget,
      ),
    );

    // Chain DNSBL off MX + SPF — IPs come from SPF include tree and MX A records
    const dnsblPromise = Promise.all([mxPromise, spfPromise]).then(
      ([mxResult, spfResult]) =>
        analyzeDnsbl(domain, mxResult, spfResult, dqsKey, budget),
    );

    // Chain BIMI off DMARC and BIMI DNS
    const bimiPromise = Promise.all([dmarcPromise, bimiDnsPromise]).then(
      ([dmarcResult, bimiDns]) => {
        const dmarcPolicy = dmarcResult.tags?.p?.toLowerCase() ?? null;
        return analyzeBimi(domain, dmarcPolicy, bimiDns, budget);
      },
    );

    // Stream each protocol as it settles. Each analyzer is isolated: a rejection
    // streams a synthetic fail card (via streamBounded) instead of leaking an
    // unhandled rejection, and never aborts the others (#378). Because the
    // streamBounded promises never reject, this Promise.all always resolves with
    // the full set of results.
    //
    // MTA-STS is the exception: it uses bare `settle` + deadline race (no early
    // emit) and is streamed after buildScanResult, because the MX/MTA-STS
    // consistency check (RFC 8461 §3.4) can add warn validations that downgrade
    // mta_sts.status (pass→warn). Emitting it here would stream a stale "pass"
    // card while the done event carries the corrected grade.
    const [
      dmarcResult,
      spfResult,
      dkimResult,
      mtaStsResult,
      bimiResult,
      mxResult,
      securityTxtResult,
      tlsRptResult,
      dnssecResult,
      daneResult,
      dnsblResult,
    ] = await Promise.all([
      streamBounded("dmarc", dmarcPromise, ERROR_RESULTS.dmarc),
      streamBounded("spf", spfPromise, ERROR_RESULTS.spf),
      streamBounded("dkim", dkimPromise, ERROR_RESULTS.dkim),
      raceDeadline(
        settle("mta_sts", mtaStsPromise, ERROR_RESULTS.mta_sts),
        ERROR_RESULTS.mta_sts,
        signal,
      ),
      streamBounded("bimi", bimiPromise, ERROR_RESULTS.bimi),
      streamBounded("mx", mxPromise, ERROR_RESULTS.mx),
      streamBounded(
        "security_txt",
        securityTxtPromise,
        ERROR_RESULTS.security_txt,
      ),
      streamBounded("tls_rpt", tlsRptPromise, ERROR_RESULTS.tls_rpt),
      streamBounded("dnssec", dnssecPromise, ERROR_RESULTS.dnssec),
      streamBounded("dane", danePromise, ERROR_RESULTS.dane),
      streamBounded("dnsbl", dnsblPromise, ERROR_RESULTS.dnsbl),
    ]);

    const result = await buildScanResult(
      domain,
      {
        mx: mxResult,
        dmarc: dmarcResult,
        spf: spfResult,
        dkim: dkimResult,
        bimi: bimiResult,
        mta_sts: mtaStsResult,
        security_txt: securityTxtResult,
        tls_rpt: tlsRptResult,
        dnssec: dnssecResult,
        dane: daneResult,
        dnsbl: dnsblResult,
      },
      config,
      budget,
    );

    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `mta_sts: ${result.protocols.mta_sts.status}`,
      data: { protocol: "mta_sts", status: result.protocols.mta_sts.status },
      level: "info",
    });
    emit("mta_sts", result.protocols.mta_sts);
    // Done event is next; suppress any straggler analyzer that resolves late.
    finalized = true;

    return result;
  } finally {
    clearTimeout(deadlineTimer);
  }
}
