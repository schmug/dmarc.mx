import { DnsLookupError, queryTxt } from "../dns/client.js";
import { parseTags } from "../shared/parse-tags.js";
import type { TlsRptResult, Validation } from "./types.js";

// RFC 8460 — SMTP TLS Reporting. DNS-only; no SMTP socket probing.
// Looks up `_smtp._tls.<domain>` TXT for a v=TLSRPTv1 record.

export async function analyzeTlsRpt(domain: string): Promise<TlsRptResult> {
  let txt: Awaited<ReturnType<typeof queryTxt>>;
  try {
    txt = await queryTxt(`_smtp._tls.${domain}`);
  } catch (err) {
    if (err instanceof DnsLookupError) {
      return {
        status: "warn",
        record: null,
        tags: null,
        validations: [
          {
            status: "warn",
            message: `TLS-RPT lookup failed (${err.code}) — result may be incomplete`,
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
      validations: [{ status: "fail", message: "No TLS-RPT record found" }],
    };
  }

  const tlsRptRecords = txt.entries.filter((e) =>
    e.trimStart().startsWith("v=TLSRPTv1"),
  );
  const unrelated = txt.entries.filter(
    (e) => !e.trimStart().startsWith("v=TLSRPTv1"),
  );

  const validations: Validation[] = [];

  if (unrelated.length > 0) {
    validations.push({
      status: "warn",
      message: `${unrelated.length} unrelated TXT record${unrelated.length > 1 ? "s" : ""} found at _smtp._tls.${domain}`,
    });
  }

  if (tlsRptRecords.length === 0) {
    return {
      status: "fail",
      record: txt.raw,
      tags: null,
      validations: [
        ...validations,
        {
          status: "fail",
          message: "No valid TLS-RPT record found (missing v=TLSRPTv1)",
        },
      ],
    };
  }

  if (tlsRptRecords.length > 1) {
    validations.push({
      status: "warn",
      message: `Multiple TLS-RPT records found at _smtp._tls.${domain} — only one is allowed`,
    });
  }

  // Use the first TLS-RPT record
  const record = tlsRptRecords[0];
  const tags = parseTags(record);

  validations.push({ status: "pass", message: "TLS-RPT record found" });

  // rua= is required (RFC 8460 §3)
  if (!tags.rua) {
    validations.push({
      status: "warn",
      message:
        "Missing required rua= tag — no reporting destination configured",
    });
    return {
      status: "warn",
      record,
      tags,
      validations,
    };
  }

  // Validate rua destinations
  const ruaEntries = tags.rua
    .split(",")
    .map((u) => u.trim())
    .filter(Boolean);
  if (ruaEntries.length === 0) {
    validations.push({
      status: "warn",
      message: "rua= tag is empty — no reporting destination configured",
    });
  } else {
    const validUriPrefixes = ["mailto:", "https://"];
    const invalid = ruaEntries.filter(
      (u) => !validUriPrefixes.some((prefix) => u.startsWith(prefix)),
    );
    if (invalid.length > 0) {
      validations.push({
        status: "warn",
        message: `rua= contains malformed destination${invalid.length > 1 ? "s" : ""}: ${invalid.map((u) => `"${u}"`).join(", ")} — expected mailto: or https:// URI`,
      });
    } else {
      validations.push({
        status: "pass",
        message: `${ruaEntries.length} reporting destination${ruaEntries.length > 1 ? "s" : ""} configured`,
      });
    }
  }

  const hasFailure = validations.some((v) => v.status === "fail");
  const hasWarn = validations.some((v) => v.status === "warn");
  const status = hasFailure ? "fail" : hasWarn ? "warn" : "pass";

  return { status, record, tags, validations };
}
