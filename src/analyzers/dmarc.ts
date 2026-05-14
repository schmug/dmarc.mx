import { queryTxt } from "../dns/client.js";
import { parseTags } from "../shared/parse-tags.js";
import type { DmarcResult, Validation } from "./types.js";

// Returns unique external (non-own-domain) domains from a comma-separated rua/ruf tag value.
function parseExternalReportDomains(
  tagValue: string | undefined,
  ownDomain: string,
): string[] {
  if (!tagValue) return [];
  const domains: string[] = [];
  const own = ownDomain.toLowerCase();
  for (const uri of tagValue.split(",")) {
    const trimmed = uri.trim().toLowerCase();
    if (trimmed.startsWith("mailto:")) {
      const address = trimmed.slice(7);
      const atIdx = address.lastIndexOf("@");
      if (atIdx >= 0) {
        const d = address.slice(atIdx + 1);
        if (d && d !== own && !domains.includes(d)) {
          domains.push(d);
        }
      }
    }
  }
  return domains;
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

  // sp= check — warn when sp=none undercuts a stronger parent policy
  if (tags.sp) {
    const spVal = tags.sp.toLowerCase();
    if (spVal === "none" && (policy === "reject" || policy === "quarantine")) {
      validations.push({
        status: "warn",
        message: `Subdomain policy (sp=none) overrides the stronger parent policy (p=${policy}), leaving subdomains unprotected`,
      });
    } else {
      validations.push({
        status: "pass",
        message: "Subdomain policy explicitly set",
      });
    }
  }

  // rua= check
  if (tags.rua) {
    validations.push({
      status: "pass",
      message: "Aggregate reporting (rua) configured",
    });
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
  }

  // pct= check — distinguish pct=0 (enforcement disabled) from pct<100 (partial)
  if (tags.pct !== undefined) {
    const pctVal = parseInt(tags.pct, 10);
    if (pctVal === 0) {
      validations.push({
        status: "warn",
        message:
          "pct=0 effectively disables policy enforcement; no messages will be filtered",
      });
    } else if (pctVal < 100) {
      validations.push({
        status: "warn",
        message: `Only ${tags.pct}% of messages are subject to the DMARC policy`,
      });
    }
  }

  // rua/ruf external destination authorization check (RFC 7489 §7.1)
  const externalDomains = [
    ...parseExternalReportDomains(tags.rua, domain),
    ...parseExternalReportDomains(tags.ruf, domain),
  ].filter((d, i, arr) => arr.indexOf(d) === i);

  for (const extDomain of externalDomains) {
    const authName = `${domain}._report._dmarc.${extDomain}`;
    const authRecord = await queryTxt(authName);
    if (!authRecord?.entries.some((e) => e.includes("v=DMARC1"))) {
      validations.push({
        status: "warn",
        message: `External report destination ${extDomain} is not authorized; missing TXT record at ${authName}`,
      });
    }
  }

  const hasFailure = validations.some((v) => v.status === "fail");
  const hasWarn = validations.some((v) => v.status === "warn");
  const status = hasFailure ? "fail" : hasWarn ? "warn" : "pass";

  return { status, record: dmarcRecord, tags, validations };
}
