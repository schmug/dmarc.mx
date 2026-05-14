import { queryTxt } from "../dns/client.js";
import { parseTags } from "../shared/parse-tags.js";
import type { DmarcResult, Validation } from "./types.js";

/**
 * Extract the hostname from a URI in a DMARC rua/ruf tag value.
 *
 * RFC 7489 §6.2 allows `mailto:` URIs (most common) and generic URIs.
 * For `mailto:user@domain`, the host is the part after `@`.
 * For other URI schemes (e.g. `https://host/path`), use URL.hostname.
 * Returns null if the URI is malformed or has no discernible host.
 */
function uriHost(uri: string): string | null {
  const trimmed = uri.trim();
  if (trimmed.toLowerCase().startsWith("mailto:")) {
    // mailto:localpart@domain  — the domain is after the last '@'
    const address = trimmed.slice("mailto:".length);
    const atIdx = address.lastIndexOf("@");
    if (atIdx === -1) return null;
    const domain = address.slice(atIdx + 1).trim();
    return domain || null;
  }
  try {
    const parsed = new URL(trimmed);
    return parsed.hostname || null;
  } catch {
    return null;
  }
}

/**
 * Parse a comma-separated DMARC reporting URI list (rua= or ruf= value).
 * Returns an array of individual URI strings.
 */
function parseUriList(value: string): string[] {
  return value
    .split(",")
    .map((u) => u.trim())
    .filter(Boolean);
}

/**
 * Check whether an external reporting domain has authorized report delivery
 * per RFC 7489 §7.1. The authorization record is a TXT lookup at
 * `_report._dmarc.<external-domain>` that contains a DMARC tag `v=DMARC1`.
 *
 * Returns true if authorized, false if not authorized (no record / no v=DMARC1).
 */
async function isExternalReportAuthorized(
  externalDomain: string,
): Promise<boolean> {
  const record = await queryTxt(`_report._dmarc.${externalDomain}`);
  if (!record) return false;
  return record.entries.some((e) => e.trimStart().startsWith("v=DMARC1"));
}

export async function analyzeDmarc(domain: string): Promise<DmarcResult> {
  const txt = await queryTxt(`_dmarc.${domain}`);
  if (!txt) {
    return {
      status: "fail",
      record: null,
      tags: null,
      validations: [{ status: "fail", message: "No DMARC record found" }],
    };
  }

  const dmarcRecord = txt.entries.find((e) =>
    e.trimStart().startsWith("v=DMARC1"),
  );
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

  // v= check
  if (tags.v === "DMARC1") {
    validations.push({ status: "pass", message: "DMARC record found" });
  } else {
    validations.push({ status: "fail", message: "Invalid version tag" });
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
    });
  }

  // sp= check — warn when sp=none weakens subdomain enforcement
  const sp = tags.sp?.toLowerCase();
  if (sp) {
    if (sp === "none" && (policy === "reject" || policy === "quarantine")) {
      validations.push({
        status: "warn",
        message:
          "Subdomain policy (sp=none) weakens subdomain enforcement — subdomains are only monitored while the organizational domain policy is stronger",
      });
    } else {
      validations.push({
        status: "pass",
        message: "Subdomain policy explicitly set",
      });
    }
  }

  // rua= check — presence + external authorization
  if (tags.rua) {
    validations.push({
      status: "pass",
      message: "Aggregate reporting (rua) configured",
    });

    const ruaUris = parseUriList(tags.rua);
    const authChecks = ruaUris.map(async (uri) => {
      const host = uriHost(uri);
      if (!host) return;
      // If the reporting address is on a different domain, verify authorization
      const normalizedDomain = domain.toLowerCase();
      const normalizedHost = host.toLowerCase();
      if (normalizedHost !== normalizedDomain) {
        const authorized = await isExternalReportAuthorized(normalizedHost);
        if (!authorized) {
          validations.push({
            status: "warn",
            message: `rua destination ${normalizedHost} has not published a DMARC report authorization record (_report._dmarc.${normalizedHost}); aggregate reports may be rejected`,
          });
        }
      }
    });
    await Promise.all(authChecks);
  } else {
    validations.push({
      status: "warn",
      message: "No aggregate reporting URI (rua) configured",
    });
  }

  // ruf= check — presence + external authorization
  if (tags.ruf) {
    validations.push({
      status: "pass",
      message: "Forensic reporting (ruf) configured",
    });

    const rufUris = parseUriList(tags.ruf);
    const authChecks = rufUris.map(async (uri) => {
      const host = uriHost(uri);
      if (!host) return;
      const normalizedDomain = domain.toLowerCase();
      const normalizedHost = host.toLowerCase();
      if (normalizedHost !== normalizedDomain) {
        const authorized = await isExternalReportAuthorized(normalizedHost);
        if (!authorized) {
          validations.push({
            status: "warn",
            message: `ruf destination ${normalizedHost} has not published a DMARC report authorization record (_report._dmarc.${normalizedHost}); forensic reports may be rejected`,
          });
        }
      }
    });
    await Promise.all(authChecks);
  }

  // pct= check — warn on pct=0 and pct<100
  if (tags.pct !== undefined) {
    const pct = parseInt(tags.pct, 10);
    if (pct === 0) {
      validations.push({
        status: "warn",
        message:
          "pct=0 means no messages are subject to the policy (policy is effectively disabled)",
      });
    } else if (pct < 100) {
      validations.push({
        status: "warn",
        message: `Only ${tags.pct}% of messages are subject to the policy`,
      });
    }
  }

  const hasFailure = validations.some((v) => v.status === "fail");
  const hasWarn = validations.some((v) => v.status === "warn");
  const status = hasFailure ? "fail" : hasWarn ? "warn" : "pass";

  return { status, record: dmarcRecord, tags, validations };
}
