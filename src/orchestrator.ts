import * as Sentry from "@sentry/cloudflare";
import { analyzeBimi, prefetchBimiDns } from "./analyzers/bimi.js";
import { analyzeDkim } from "./analyzers/dkim.js";
import { analyzeDmarc } from "./analyzers/dmarc.js";
import { analyzeMtaSts } from "./analyzers/mta-sts.js";
import { analyzeMx } from "./analyzers/mx.js";
import { analyzeSecurityTxt } from "./analyzers/security-txt.js";
import { analyzeSpf } from "./analyzers/spf.js";
import { analyzeTlsRpt } from "./analyzers/tls-rpt.js";
import type {
  BimiResult,
  DkimResult,
  DmarcResult,
  MtaStsResult,
  MxResult,
  ScanResult,
  SecurityTxtResult,
  SpfResult,
  TlsRptResult,
} from "./analyzers/types.js";
import { queryTxt } from "./dns/client.js";
import { computeGradeBreakdown } from "./shared/scoring.js";

export type ProtocolId =
  | "mx"
  | "dmarc"
  | "spf"
  | "dkim"
  | "bimi"
  | "mta_sts"
  | "security_txt"
  | "tls_rpt";
export type ProtocolResult =
  | MxResult
  | DmarcResult
  | SpfResult
  | DkimResult
  | BimiResult
  | MtaStsResult
  | SecurityTxtResult
  | TlsRptResult;

async function buildScanResult(
  domain: string,
  protocols: ScanResult["protocols"],
): Promise<ScanResult> {
  const breakdown = computeGradeBreakdown(protocols);

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

  const dkimFound = Object.values(protocols.dkim.selectors).filter(
    (s) => s.found,
  ).length;
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
  customSelectors: string[] = [],
): Promise<ScanResult> {
  // Fire all independent DNS queries immediately
  const dmarcPromise = analyzeDmarc(domain);
  const spfPromise = analyzeSpf(domain);
  const mtaStsPromise = analyzeMtaSts(domain);
  const bimiDnsPromise = prefetchBimiDns(domain);
  const mxPromise = analyzeMx(domain);
  const securityTxtPromise = analyzeSecurityTxt(domain);
  const tlsRptPromise = analyzeTlsRpt(domain);

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

  const bimiPromise = Promise.all([dmarcPromise, bimiDnsPromise]).then(
    ([dmarcResult, bimiDns]) => {
      const dmarcPolicy = dmarcResult.tags?.p?.toLowerCase() ?? null;
      return analyzeBimi(domain, dmarcPolicy, bimiDns);
    },
  );

  const [
    dmarcResult,
    spfResult,
    dkimResult,
    mtaStsResult,
    bimiResult,
    mxResult,
    securityTxtResult,
    tlsRptResult,
  ] = await Promise.all([
    dmarcPromise,
    spfPromise,
    dkimPromise,
    mtaStsPromise,
    bimiPromise,
    mxPromise,
    securityTxtPromise,
    tlsRptPromise,
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

  return await buildScanResult(domain, {
    mx: mxResult,
    dmarc: dmarcResult,
    spf: spfResult,
    dkim: dkimResult,
    bimi: bimiResult,
    mta_sts: mtaStsResult,
    security_txt: securityTxtResult,
    tls_rpt: tlsRptResult,
  });
}

export async function scanStreaming(
  domain: string,
  customSelectors: string[],
  onResult: (id: ProtocolId, result: ProtocolResult) => void,
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

  // Chain DKIM off MX so it starts as soon as MX resolves
  const dkimPromise = mxPromise.then((mxResult) => {
    const providerNames = mxResult.providers.map((p) => p.name);
    return analyzeDkim(domain, customSelectors, providerNames);
  });

  // Chain BIMI off DMARC and BIMI DNS
  const bimiPromise = Promise.all([dmarcPromise, bimiDnsPromise]).then(
    ([dmarcResult, bimiDns]) => {
      const dmarcPolicy = dmarcResult.tags?.p?.toLowerCase() ?? null;
      return analyzeBimi(domain, dmarcPolicy, bimiDns);
    },
  );

  // Attach streaming handlers immediately
  mxPromise.then((r) => {
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `mx: ${r.status}`,
      data: { protocol: "mx", status: r.status },
      level: "info",
    });
    onResult("mx", r);
  });

  spfPromise.then((r) => {
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `spf: ${r.status}`,
      data: { protocol: "spf", status: r.status },
      level: "info",
    });
    onResult("spf", r);
  });

  mtaStsPromise.then((r) => {
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `mta_sts: ${r.status}`,
      data: { protocol: "mta_sts", status: r.status },
      level: "info",
    });
    onResult("mta_sts", r);
  });

  dmarcPromise.then((r) => {
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `dmarc: ${r.status}`,
      data: { protocol: "dmarc", status: r.status },
      level: "info",
    });
    onResult("dmarc", r);
  });

  dkimPromise.then((r) => {
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `dkim: ${r.status}`,
      data: { protocol: "dkim", status: r.status },
      level: "info",
    });
    onResult("dkim", r);
  });

  bimiPromise.then((r) => {
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `bimi: ${r.status}`,
      data: { protocol: "bimi", status: r.status },
      level: "info",
    });
    onResult("bimi", r);
  });

  securityTxtPromise.then((r) => {
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `security_txt: ${r.status}`,
      data: { protocol: "security_txt", status: r.status },
      level: "info",
    });
    onResult("security_txt", r);
  });

  tlsRptPromise.then((r) => {
    Sentry.addBreadcrumb({
      category: "analyzer.complete",
      message: `tls_rpt: ${r.status}`,
      data: { protocol: "tls_rpt", status: r.status },
      level: "info",
    });
    onResult("tls_rpt", r);
  });

  const [
    dmarcResult,
    spfResult,
    dkimResult,
    mtaStsResult,
    bimiResult,
    mxResult,
    securityTxtResult,
    tlsRptResult,
  ] = await Promise.all([
    dmarcPromise,
    spfPromise,
    dkimPromise,
    mtaStsPromise,
    bimiPromise,
    mxPromise,
    securityTxtPromise,
    tlsRptPromise,
  ]);

  return await buildScanResult(domain, {
    mx: mxResult,
    dmarc: dmarcResult,
    spf: spfResult,
    dkim: dkimResult,
    bimi: bimiResult,
    mta_sts: mtaStsResult,
    security_txt: securityTxtResult,
    tls_rpt: tlsRptResult,
  });
}
