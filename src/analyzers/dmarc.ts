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
 * The only values RFC 7489 §6.3 defines for p= and sp=, lowercased (both tags
 * are case-insensitive). Anything else is an unparseable policy, which §6.6.3
 * step 6 says receivers treat as p=none or skip entirely — never enforcement.
 */
const VALID_POLICIES = new Set(["none", "quarantine", "reject"]);

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
  } else {
    // Anything outside none/quarantine/reject is not a valid p= (RFC 7489
    // §6.3). Per §6.6.3 step 6 a receiver then either acts as if p=none was
    // published (when rua carries a valid URI) or applies no DMARC at all —
    // no enforcement either way, so this is a fail, not a warn. Without this
    // arm a typo like p=Quarntine pushed no policy validation and the record
    // reported healthy (#738).
    validations.push({
      status: "fail",
      message: `Unrecognized policy value (p=${tags.p}) — receivers apply no enforcement (RFC 7489 §6.6.3)`,
    });
  }

  // sp= check
  if (tags.sp) {
    const spLower = tags.sp.toLowerCase();
    if (!VALID_POLICIES.has(spLower)) {
      // RFC 7489 §6.6.3 step 6 treats an invalid sp= exactly like a missing
      // p=: it invalidates the whole record, not just subdomain handling. So
      // this is a fail rather than a warn, and the record is not "explicitly
      // set" (#738).
      validations.push({
        status: "fail",
        message: `Unrecognized subdomain policy value (sp=${tags.sp}) — receivers apply no enforcement (RFC 7489 §6.6.3)`,
      });
    } else {
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
    const isWholeNumber = /^\d+$/.test(tags.pct);
    const pctVal = isWholeNumber ? Number(tags.pct) : NaN;
    if (!isWholeNumber || pctVal > 100) {
      validations.push({
        status: "warn",
        message: `pct=${tags.pct} is not a valid percentage (0-100); receivers will treat it as 100`,
      });
    } else if (pctVal === 0) {
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
  // requires an exact domain match for the passing identifier. RFC 7489 §6.3
  // defines only r and s — anything else is not a valid alignment mode, but
  // (unlike p=/sp=) has no defined fallback behavior of its own, so we warn
  // rather than fail and still describe the relaxed-default handling below.
  const adkim = tags.adkim?.toLowerCase();
  if (adkim && adkim !== "r" && adkim !== "s") {
    validations.push({
      status: "warn",
      message: `Unrecognized DKIM alignment mode (adkim=${tags.adkim}) — RFC 7489 §6.3 only defines r and s`,
    });
  }
  validations.push({
    status: "info",
    message:
      adkim === "s"
        ? "DKIM alignment is strict (adkim=s) — signing domain must match exactly"
        : "DKIM alignment is relaxed (adkim=r, the default) — organizational-domain match is sufficient",
  });
  const aspf = tags.aspf?.toLowerCase();
  if (aspf && aspf !== "r" && aspf !== "s") {
    validations.push({
      status: "warn",
      message: `Unrecognized SPF alignment mode (aspf=${tags.aspf}) — RFC 7489 §6.3 only defines r and s`,
    });
  }
  validations.push({
    status: "info",
    message:
      aspf === "s"
        ? "SPF alignment is strict (aspf=s) — envelope-from domain must match exactly"
        : "SPF alignment is relaxed (aspf=r, the default) — organizational-domain match is sufficient",
  });

  // Failure-reporting options (fo). Default is "0" when absent. RFC 7489
  // §6.3 defines fo as a colon-separated list of single-character flags
  // (0, 1, d, s) — e.g. fo=1:d requests a report on any SPF/DKIM failure
  // OR a DKIM-specific failure.
  const foSuffix = tags.ruf ? "" : " (no effect without a ruf address)";
  const FO_TOKEN_EXPLANATIONS: Record<string, string> = {
    "0": "a forensic report is generated only when all authentication mechanisms fail",
    "1": "a forensic report is generated when any authentication mechanism fails (SPF or DKIM)",
    d: "a forensic report is generated when DKIM evaluation fails, regardless of SPF",
    s: "a forensic report is generated when SPF evaluation fails, regardless of DKIM",
  };
  if (!tags.fo || tags.fo === "0") {
    validations.push({
      status: "info",
      message: `Failure-reporting option fo=0 (the default) — ${FO_TOKEN_EXPLANATIONS["0"]}${foSuffix}`,
    });
  } else {
    const foTokens = tags.fo.split(":");
    const validTokens = foTokens.filter((t) => t in FO_TOKEN_EXPLANATIONS);
    const invalidTokens = foTokens.filter((t) => !(t in FO_TOKEN_EXPLANATIONS));

    if (foTokens.length === 1 && validTokens.length === 1) {
      const token = validTokens[0];
      validations.push({
        status: "info",
        message: `Failure-reporting option fo=${token} — ${FO_TOKEN_EXPLANATIONS[token]}${foSuffix}`,
      });
    } else {
      if (validTokens.length > 0) {
        const explanations = validTokens
          .map((t) => FO_TOKEN_EXPLANATIONS[t])
          .join("; or ");
        validations.push({
          status: "info",
          message: `Failure-reporting options fo=${tags.fo} configured — ${explanations}${foSuffix}`,
        });
      }
      if (invalidTokens.length > 0) {
        const labeled = invalidTokens.map((t) => (t === "" ? "(empty)" : t));
        validations.push({
          status: "warn",
          message: `Failure-reporting options fo=${tags.fo} include unrecognized token(s): ${labeled.join(", ")} — RFC 7489 §6.3 only defines 0, 1, d, s${foSuffix}`,
        });
      }
    }
  }

  const hasFailure = validations.some((v) => v.status === "fail");
  const hasWarn = validations.some((v) => v.status === "warn");
  const status = hasFailure ? "fail" : hasWarn ? "warn" : "pass";

  return { status, record: dmarcRecord, tags, validations };
}
