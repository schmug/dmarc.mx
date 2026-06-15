import { DnsLookupError, queryTxt } from "../dns/client.js";
import type { ScanBudget } from "../dns/scan-budget.js";
import { parseTags } from "../shared/parse-tags.js";
import type { TlsRptResult, Validation } from "./types.js";

// RFC 8460 — SMTP TLS Reporting. Informational analyzer; does not affect
// the letter grade. TLS-RPT is a companion to MTA-STS: it tells receiving
// MTAs where to send TLS failure reports, but its presence or absence does
// not change the enforcement posture.

export async function analyzeTlsRpt(
  domain: string,
  budget?: ScanBudget,
): Promise<TlsRptResult> {
  let txt: Awaited<ReturnType<typeof queryTxt>>;
  try {
    txt = await queryTxt(`_smtp._tls.${domain}`, budget);
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
            message: `TLS-RPT lookup failed (${err.code}) — result may be incomplete`,
          },
        ],
      };
    }
    throw err;
  }

  if (!txt || txt.entries.length === 0) {
    return {
      status: "info",
      record: null,
      tags: null,
      validations: [
        {
          status: "info",
          message: "No TLS-RPT record found at _smtp._tls TXT",
        },
      ],
    };
  }

  const validations: Validation[] = [];

  const tlsRptEntries = txt.entries.filter((e) =>
    e.toLowerCase().startsWith("v=tlsrptv1"),
  );
  const otherEntries = txt.entries.filter(
    (e) => !e.toLowerCase().startsWith("v=tlsrptv1"),
  );

  if (otherEntries.length > 0) {
    validations.push({
      status: "warn",
      message: `${otherEntries.length} unrelated TXT record${otherEntries.length > 1 ? "s" : ""} at _smtp._tls — may cause confusion`,
    });
  }

  if (tlsRptEntries.length === 0) {
    validations.push({
      status: "warn",
      message:
        "TXT record(s) found at _smtp._tls but none begin with v=TLSRPTv1",
    });
    return { status: "warn", record: null, tags: null, validations };
  }

  if (tlsRptEntries.length > 1) {
    validations.push({
      status: "warn",
      message: `${tlsRptEntries.length} TLS-RPT records found; exactly one is required (RFC 8460 §3)`,
    });
  }

  const record = tlsRptEntries[0];
  const tags = parseTags(record);

  validations.push({
    status: "info",
    message: "TLS-RPT record found (v=TLSRPTv1)",
  });

  if (!tags.rua) {
    validations.push({
      status: "warn",
      message: "Missing required rua= tag (RFC 8460 §3.1)",
    });
  } else {
    const ruas = tags.rua
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    if (ruas.length === 0) {
      validations.push({ status: "warn", message: "rua= tag is empty" });
    } else {
      const invalid = ruas.filter(
        (r) => !r.startsWith("mailto:") && !r.startsWith("https://"),
      );
      if (invalid.length > 0) {
        validations.push({
          status: "warn",
          message: `rua= destination${invalid.length > 1 ? "s" : ""} not in mailto:/https:// format: ${invalid.slice(0, 3).join(", ")}`,
        });
      } else {
        validations.push({
          status: "info",
          message: `Report destination${ruas.length > 1 ? "s" : ""}: ${ruas.join(", ")}`,
        });
      }
    }
  }

  const hasWarn = validations.some((v) => v.status === "warn");
  return {
    status: hasWarn ? "warn" : "pass",
    record,
    tags,
    validations,
  };
}
