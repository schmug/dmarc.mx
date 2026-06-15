import { DnsLookupError, queryTxt } from "../dns/client.js";
import type { ScanBudget } from "../dns/scan-budget.js";
import { LEARN_ANCHORS, learnAnchorHref } from "../shared/learn-anchors.js";
import { parseTags } from "../shared/parse-tags.js";
import type { DmarcResult, Validation } from "./types.js";

/**
 * DoS guard (GHSA-vcw3-wvwx-6fg5): the scanned domain's _dmarc record is
 * attacker-controlled, and every external rua/ruf reporting domain becomes one
 * serial, timeout-bounded outbound DNS lookup in checkReportingAuthorization.
 * An unbounded list lets a single scan request fan out into tens of lookups
 * charged against one rate-limit token. Bound the external authorization
 * lookups per scan, shared across rua+ruf combined. 10 is generous — legitimate
 * records carry 1-2 reporting URIs — and mirrors SPF's MAX_LOOKUPS.
 */
export const MAX_REPORT_AUTH_LOOKUPS = 10;

/**
 * Shared, mutable lookup budget threaded across the rua and ruf authorization
 * passes so the cap bounds their combined external DNS fan-out, and the
 * cap-exceeded warning is emitted at most once per scan.
 */
interface ReportAuthBudget {
  remaining: number;
  capReported: boolean;
}

/**
 * Extract the domain portion from a mailto: URI.
 * Returns null if the URI is not a mailto: or has no @ sign.
 * Does NOT use new URL() — that throws on mailto: in some runtimes.
 */
function extractMailtoDomain(uri: string): string | null {
  const trimmed = uri.trim();
  if (!trimmed.startsWith("mailto:")) return null;
  const address = trimmed.slice("mailto:".length);
  const atIndex = address.indexOf("@");
  if (atIndex === -1) return null;
  return address.slice(atIndex + 1).toLowerCase();
}

/**
 * Parse a comma-separated rua/ruf tag value and return the list of mailto URIs.
 */
function parseReportUris(tagValue: string): string[] {
  return tagValue
    .split(",")
    .map((u) => u.trim())
    .filter((u) => u.length > 0);
}

/**
 * Check external report destination authorization per RFC 7489 §7.1.
 * For each reporting address whose domain differs from the sending domain,
 * query <sending-domain>._report._dmarc.<reporting-domain> for v=DMARC1.
 */
async function checkReportingAuthorization(
  localDomain: string,
  tagValue: string,
  tagName: "rua" | "ruf",
  validations: Validation[],
  // Two distinct budgets: `authBudget` is the per-analyzer rua/ruf cap
  // (GHSA-vcw3-wvwx-6fg5), shared across the rua+ruf passes; `scanBudget` is the
  // orchestrator-wide shared DNS-query pool (GHSA-f828-8wf8-vqp2) passed down to
  // queryTxt. The auth cap bounds this analyzer's fan-out; the scan budget bounds
  // the whole scan's combined fan-out across all analyzers.
  authBudget: ReportAuthBudget,
  scanBudget?: ScanBudget,
): Promise<void> {
  const uris = parseReportUris(tagValue);
  for (const uri of uris) {
    const reportingDomain = extractMailtoDomain(uri);
    if (!reportingDomain) continue;
    // Same domain — no external authorization needed
    if (reportingDomain === localDomain.toLowerCase()) continue;
    // External lookup required — enforce the per-analyzer cap before querying.
    if (authBudget.remaining <= 0) {
      if (!authBudget.capReported) {
        validations.push({
          status: "warn",
          message: `More than ${MAX_REPORT_AUTH_LOOKUPS} external report destinations configured (rua/ruf) — additional destinations were not verified for report authorization`,
        });
        authBudget.capReported = true;
      }
      break;
    }
    authBudget.remaining--;
    const authName = `${localDomain}._report._dmarc.${reportingDomain}`;
    let authRecord: Awaited<ReturnType<typeof queryTxt>>;
    try {
      authRecord = await queryTxt(authName, scanBudget);
    } catch (err) {
      if (err instanceof DnsLookupError) {
        validations.push({
          status: "warn",
          message: `External ${tagName} authorization lookup for ${reportingDomain} failed (${err.code}) — could not verify ${authName}`,
        });
        continue;
      }
      throw err;
    }
    const isAuthorized =
      authRecord?.entries.some((e) => e.trimStart().startsWith("v=DMARC1")) ??
      false;
    if (!isAuthorized) {
      validations.push({
        status: "warn",
        message: `External ${tagName} destination ${reportingDomain} has not authorized ${localDomain} to send reports — missing or invalid ${authName} TXT record`,
      });
    }
  }
}

export async function analyzeDmarc(
  domain: string,
  budget?: ScanBudget,
): Promise<DmarcResult> {
  let txt: Awaited<ReturnType<typeof queryTxt>>;
  try {
    txt = await queryTxt(`_dmarc.${domain}`, budget);
  } catch (err) {
    if (err instanceof DnsLookupError) {
      return {
        status: "warn",
        record: null,
        tags: null,
        lookup_error: { code: err.code, message: err.message },
        validations: [
          {
            status: "warn",
            message: `DMARC lookup failed (${err.code}) — result may be incomplete`,
          },
        ],
      };
    }
    throw err;
  }
  if (!txt) {
    return {
      status: "fail",
      record: null,
      tags: null,
      validations: [{ status: "fail", message: "No DMARC record found" }],
    };
  }

  const dmarcRecords = txt.entries.filter((e) =>
    e.trimStart().startsWith("v=DMARC1"),
  );
  const dmarcRecord = dmarcRecords[0];
  if (!dmarcRecord) {
    return {
      status: "fail",
      record: txt.raw,
      tags: null,
      validations: [
        {
          status: "fail",
          message: `TXT record exists at _dmarc.${domain} but is not a valid DMARC record (possibly a wildcard DNS entry)`,
        },
      ],
    };
  }

  const tags = parseTags(dmarcRecord);
  const validations: Validation[] = [];
  // Shared across the rua + ruf authorization passes so the cap bounds their
  // combined external DNS fan-out (GHSA-vcw3-wvwx-6fg5).
  const reportAuthBudget: ReportAuthBudget = {
    remaining: MAX_REPORT_AUTH_LOOKUPS,
    capReported: false,
  };

  // v= check
  if (tags.v === "DMARC1") {
    validations.push({ status: "pass", message: "DMARC record found" });
  } else {
    validations.push({ status: "fail", message: "Invalid version tag" });
  }

  // Multiple-record check: more than one DMARC record means receivers ignore
  // the policy entirely (RFC 7489 §6.6.3).
  if (dmarcRecords.length > 1) {
    validations.push({
      status: "fail",
      message: `Multiple DMARC records published (${dmarcRecords.length}) — receivers will ignore the policy (RFC 7489 §6.6.3)`,
    });
  }

  // p= check
  const policy = tags.p?.toLowerCase();
  if (!policy) {
    validations.push({ status: "fail", message: "Missing policy tag (p=)" });
  } else if (policy === "reject") {
    validations.push({
      status: "pass",
      message: "Policy is set to reject (strongest enforcement)",
    });
  } else if (policy === "quarantine") {
    validations.push({
      status: "warn",
      message: "Policy is set to quarantine (medium enforcement)",
    });
  } else if (policy === "none") {
    validations.push({
      status: "fail",
      message: "Policy is set to none (monitoring only, no enforcement)",
      learnAnchor: learnAnchorHref(LEARN_ANCHORS.dmarcPolicyNone),
    });
  }

  // sp= check
  if (tags.sp) {
    const spLower = tags.sp.toLowerCase();
    validations.push({
      status: "pass",
      message: "Subdomain policy explicitly set",
    });
    // sp=none overrides stronger parent policy — subdomains lose enforcement
    if (
      spLower === "none" &&
      (policy === "quarantine" || policy === "reject")
    ) {
      validations.push({
        status: "warn",
        message:
          "sp=none overrides subdomain enforcement — subdomains have no DMARC policy applied",
      });
    }
  }

  // rua= check
  if (tags.rua) {
    validations.push({
      status: "pass",
      message: "Aggregate reporting (rua) configured",
    });
    await checkReportingAuthorization(
      domain,
      tags.rua,
      "rua",
      validations,
      reportAuthBudget,
      budget,
    );
  } else {
    validations.push({
      status: "warn",
      message: "No aggregate reporting URI (rua) configured",
    });
  }

  // ruf= check
  if (tags.ruf) {
    validations.push({
      status: "pass",
      message: "Forensic reporting (ruf) configured",
    });
    await checkReportingAuthorization(
      domain,
      tags.ruf,
      "ruf",
      validations,
      reportAuthBudget,
      budget,
    );
  }

  // pct check
  if (tags.pct !== undefined && tags.pct !== null && tags.pct !== "") {
    const pctVal = parseInt(tags.pct, 10);
    if (pctVal === 0) {
      validations.push({
        status: "warn",
        message:
          "pct=0 means no messages are actually subjected to DMARC policy",
      });
    } else if (pctVal < 100) {
      validations.push({
        status: "warn",
        message: `pct=${tags.pct} means only ${tags.pct}% of messages are subjected to DMARC policy (less than full enforcement)`,
      });
    }
  }

  // Alignment mode (adkim / aspf). Default is relaxed ("r"); strict ("s")
  // requires an exact domain match for the passing identifier.
  const adkim = tags.adkim?.toLowerCase();
  validations.push({
    status: "info",
    message:
      adkim === "s"
        ? "DKIM alignment is strict (adkim=s) — signing domain must match exactly"
        : "DKIM alignment is relaxed (adkim=r, the default) — organizational-domain match is sufficient",
  });
  const aspf = tags.aspf?.toLowerCase();
  validations.push({
    status: "info",
    message:
      aspf === "s"
        ? "SPF alignment is strict (aspf=s) — envelope-from domain must match exactly"
        : "SPF alignment is relaxed (aspf=r, the default) — organizational-domain match is sufficient",
  });

  // Failure-reporting options (fo). Default is "0" when absent.
  // Only meaningful when ruf is configured.
  const foSuffix = tags.ruf ? "" : " (no effect without a ruf address)";
  if (!tags.fo || tags.fo === "0") {
    validations.push({
      status: "info",
      message: `Failure-reporting option fo=0 (the default) — a forensic report is generated only when all authentication mechanisms fail${foSuffix}`,
    });
  } else if (tags.fo === "1") {
    validations.push({
      status: "info",
      message: `Failure-reporting option fo=1 — a forensic report is generated when any authentication mechanism fails (SPF or DKIM)${foSuffix}`,
    });
  } else if (tags.fo === "d") {
    validations.push({
      status: "info",
      message: `Failure-reporting option fo=d — a forensic report is generated when DKIM evaluation fails, regardless of SPF${foSuffix}`,
    });
  } else if (tags.fo === "s") {
    validations.push({
      status: "info",
      message: `Failure-reporting option fo=s — a forensic report is generated when SPF evaluation fails, regardless of DKIM${foSuffix}`,
    });
  } else {
    validations.push({
      status: "info",
      message: `Failure-reporting options fo=${tags.fo} configured${foSuffix}`,
    });
  }

  const hasFailure = validations.some((v) => v.status === "fail");
  const hasWarn = validations.some((v) => v.status === "warn");
  const status = hasFailure ? "fail" : hasWarn ? "warn" : "pass";

  return { status, record: dmarcRecord, tags, validations };
}
