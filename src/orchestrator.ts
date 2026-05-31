import * as Sentry from "@sentry/cloudflare";
import { analyzeBimi, prefetchBimiDns } from "./analyzers/bimi.js";
import { analyzeDane } from "./analyzers/dane.js";
import { analyzeDkim } from "./analyzers/dkim.js";
import { analyzeDmarc } from "./analyzers/dmarc.js";
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
  | "dane";
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
  | DaneResult;

const PROTOCOL_LABEL: Record<ProtocolId, string> = {
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

// Streaming variant: settle the analyzer, then emit a completion breadcrumb and
// stream the result (real or synthetic) exactly once. Because it builds on the
// never-rejecting `settle`, a thrown analyzer streams a fail card instead of
// leaking an unhandled rejection from a bare `.then(onResult)` handler.
function streamSettled<T extends ProtocolResult>(
  id: ProtocolId,
  promise: Promise<T>,
  fallback: (message: string) => T,
  onResult: (id: ProtocolId, result: ProtocolResult) => void,
): Promise<T> {
  return settle(id, promise, fallback).then((r) => {
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `${id}: ${r.status}`,
      data: { protocol: id, status: r.status },
      level: "info",
    });
    onResult(id, r);
    return r;
  });
}

async function buildScanResult(
  domain: string,
  protocols: ScanResult["protocols"],
  config: Partial<ScoringConfig>,
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
      const txt = await queryTxt(domain);
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
): Promise<ScanResult> {
  // Fire all independent DNS queries immediately
  const dmarcPromise = analyzeDmarc(domain);
  const spfPromise = analyzeSpf(domain);
  const mtaStsPromise = analyzeMtaSts(domain);
  const bimiDnsPromise = prefetchBimiDns(domain);
  const mxPromise = analyzeMx(domain);
  const securityTxtPromise = analyzeSecurityTxt(domain);
  const tlsRptPromise = analyzeTlsRpt(domain);
  const dnssecPromise = analyzeDnssec(domain);

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
    return analyzeDkim(domain, customSelectors, providerNames);
  });

  // Chain DANE off MX — TLSA records are queried per MX exchange
  const danePromise = mxPromise.then((mxResult) =>
    analyzeDane(
      domain,
      mxResult.records.map((r) => r.exchange),
    ),
  );

  const bimiPromise = Promise.all([dmarcPromise, bimiDnsPromise]).then(
    ([dmarcResult, bimiDns]) => {
      const dmarcPolicy = dmarcResult.tags?.p?.toLowerCase() ?? null;
      return analyzeBimi(domain, dmarcPolicy, bimiDns);
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
  ] = await Promise.all([
    settle("dmarc", dmarcPromise, ERROR_RESULTS.dmarc),
    settle("spf", spfPromise, ERROR_RESULTS.spf),
    settle("dkim", dkimPromise, ERROR_RESULTS.dkim),
    settle("mta_sts", mtaStsPromise, ERROR_RESULTS.mta_sts),
    settle("bimi", bimiPromise, ERROR_RESULTS.bimi),
    settle("mx", mxPromise, ERROR_RESULTS.mx),
    settle("security_txt", securityTxtPromise, ERROR_RESULTS.security_txt),
    settle("tls_rpt", tlsRptPromise, ERROR_RESULTS.tls_rpt),
    settle("dnssec", dnssecPromise, ERROR_RESULTS.dnssec),
    settle("dane", danePromise, ERROR_RESULTS.dane),
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
    },
    config,
  );
}

export async function scanStreaming(
  domain: string,
  customSelectors: string[],
  onResult: (id: ProtocolId, result: ProtocolResult) => void,
  config: Partial<ScoringConfig>,
): Promise<ScanResult> {
  // ⚡ Bolt Optimization: Start all independent DNS queries immediately.
  // Previously, the streaming sequence awaited MX resolution before dispatching
  // DKIM *and* blocked the stream from yielding fast protocols (like SPF)
  // until MX finished. Now, all lookups are chained directly from their
  // prerequisites, maximizing concurrency and reducing scan latency.
  const dmarcPromise = analyzeDmarc(domain);
  const spfPromise = analyzeSpf(domain);
  const mtaStsPromise = analyzeMtaSts(domain);
  const bimiDnsPromise = prefetchBimiDns(domain);
  const mxPromise = analyzeMx(domain);
  const securityTxtPromise = analyzeSecurityTxt(domain);
  const tlsRptPromise = analyzeTlsRpt(domain);
  const dnssecPromise = analyzeDnssec(domain);

  // Chain DKIM off MX so it starts as soon as MX resolves
  const dkimPromise = mxPromise.then((mxResult) => {
    const providerNames = mxResult.providers.map((p) => p.name);
    return analyzeDkim(domain, customSelectors, providerNames);
  });

  // Chain DANE off MX — TLSA records are queried per MX exchange
  const danePromise = mxPromise.then((mxResult) =>
    analyzeDane(
      domain,
      mxResult.records.map((r) => r.exchange),
    ),
  );

  // Chain BIMI off DMARC and BIMI DNS
  const bimiPromise = Promise.all([dmarcPromise, bimiDnsPromise]).then(
    ([dmarcResult, bimiDns]) => {
      const dmarcPolicy = dmarcResult.tags?.p?.toLowerCase() ?? null;
      return analyzeBimi(domain, dmarcPolicy, bimiDns);
    },
  );

  // Stream each protocol as it settles. Each analyzer is isolated: a rejection
  // streams a synthetic fail card (via streamSettled) instead of leaking an
  // unhandled rejection, and never aborts the others (#378). Because the
  // streamSettled promises never reject, this Promise.all always resolves with
  // the full set of results. Handlers attach synchronously here, before the
  // await, so fast protocols still stream the moment they complete.
  //
  // MTA-STS is the exception: it uses bare `settle` (still isolated, no early
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
  ] = await Promise.all([
    streamSettled("dmarc", dmarcPromise, ERROR_RESULTS.dmarc, onResult),
    streamSettled("spf", spfPromise, ERROR_RESULTS.spf, onResult),
    streamSettled("dkim", dkimPromise, ERROR_RESULTS.dkim, onResult),
    settle("mta_sts", mtaStsPromise, ERROR_RESULTS.mta_sts),
    streamSettled("bimi", bimiPromise, ERROR_RESULTS.bimi, onResult),
    streamSettled("mx", mxPromise, ERROR_RESULTS.mx, onResult),
    streamSettled(
      "security_txt",
      securityTxtPromise,
      ERROR_RESULTS.security_txt,
      onResult,
    ),
    streamSettled("tls_rpt", tlsRptPromise, ERROR_RESULTS.tls_rpt, onResult),
    streamSettled("dnssec", dnssecPromise, ERROR_RESULTS.dnssec, onResult),
    streamSettled("dane", danePromise, ERROR_RESULTS.dane, onResult),
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
    },
    config,
  );

  Sentry.addBreadcrumb({
    category: "analyzer.complete",
    message: `mta_sts: ${result.protocols.mta_sts.status}`,
    data: { protocol: "mta_sts", status: result.protocols.mta_sts.status },
    level: "info",
  });
  onResult("mta_sts", result.protocols.mta_sts);

  return result;
}
