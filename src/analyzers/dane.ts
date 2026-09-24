import { DnsLookupError, queryDoh } from "../dns/client.js";
import type { ScanBudget } from "../dns/scan-budget.js";
import type {
  DaneHostResult,
  DaneResult,
  DaneTlsaRecord,
  Validation,
} from "./types.js";

// TLSA record data can arrive in two shapes:
//  1. Presentation format (RFC 6698 §2.2): "<usage> <selector> <matching-type>
//     <hex-data>", e.g. "3 1 1 abcdef1234...".
//  2. RFC 3597 §5 generic format: "\# <rdlength> <hex octets>", e.g.
//     "\# 35 03 01 01 0f0c...". This is what Cloudflare's DoH JSON API returns
//     for TLSA, since it predates a type-specific presentation in that API.
// Both decode to the same RFC 6698 §2.1 RDATA: 1 octet certificate usage,
// 1 octet selector, 1 octet matching type, then the certificate-association data.
function parseTlsaRecord(data: string): DaneTlsaRecord | null {
  const trimmed = data.trim();

  if (trimmed.startsWith("\\#")) {
    // Drop the "\#" marker, keep the rdlength token, then concatenate the
    // remaining (possibly space-separated) hex octets into one lowercase string.
    const tokens = trimmed.slice(2).trim().split(/\s+/);
    if (tokens.length < 2) return null;
    const rdlength = parseInt(tokens[0], 10);
    if (Number.isNaN(rdlength)) return null;
    const hex = tokens.slice(1).join("").toLowerCase();
    // Need at least the 3 header octets (6 hex chars); reject anything non-hex.
    // After this guard every two-char slice is valid hex, so parseInt base-16
    // can never return NaN — no further NaN check needed in this branch.
    if (hex.length < 6 || !/^[0-9a-f]+$/.test(hex)) return null;
    // RFC 3597 §5: RDLENGTH must equal the actual octet count. A mismatch
    // means the hex octets are truncated (or padded) relative to what the
    // record claims, so the data can't be trusted — reject rather than
    // silently decode a partial/misleading TLSA record.
    if (hex.length !== rdlength * 2) return null;
    const usage = parseInt(hex.slice(0, 2), 16);
    const selector = parseInt(hex.slice(2, 4), 16);
    const matchingType = parseInt(hex.slice(4, 6), 16);
    return { usage, selector, matchingType, data: hex.slice(6) };
  }

  const parts = trimmed.split(/\s+/);
  if (parts.length < 4) return null;
  const usage = parseTlsaField(parts[0], 3);
  const selector = parseTlsaField(parts[1], 1);
  const matchingType = parseTlsaField(parts[2], 2);
  if (usage === null || selector === null || matchingType === null) return null;
  return { usage, selector, matchingType, data: parts.slice(3).join("") };
}

// RFC 6698 §2.1: certificate usage is 0-3, selector is 0-1, matching type is
// 0-2. `parseInt` alone accepts trailing garbage ("3x" -> 3) and out-of-range
// values (9, 7, 8), so require the token to be a whole, non-negative number
// within [0, max] or treat the record as malformed.
function parseTlsaField(token: string, max: number): number | null {
  if (!/^\d+$/.test(token)) return null;
  const value = Number(token);
  return value <= max ? value : null;
}

export async function analyzeDane(
  _domain: string,
  mxExchanges: string[],
  budget?: ScanBudget,
): Promise<DaneResult> {
  const validations: Validation[] = [];

  if (mxExchanges.length === 0) {
    validations.push({
      status: "info",
      message: "DANE/TLSA not applicable — no MX records configured",
    });
    return { status: "info", hosts: [], validations };
  }

  const hosts: DaneHostResult[] = [];
  let anyTlsaAdValidated = false;
  let anyTlsaUnvalidated = false;
  let successfulQueries = 0;
  let firstLookupError: { code: string; message: string } | undefined;

  await Promise.all(
    mxExchanges.map(async (exchange) => {
      try {
        const response = await queryDoh(`_25._tcp.${exchange}`, "TLSA", budget);
        successfulQueries++;
        if (!response) {
          hosts.push({ exchange, tlsaRecords: [], dnssecValidated: false });
          return;
        }
        const tlsaRecords = (response.Answer ?? [])
          .map((a) => parseTlsaRecord(a.data))
          .filter((r): r is DaneTlsaRecord => r !== null);
        const dnssecValidated = response.AD;
        hosts.push({ exchange, tlsaRecords, dnssecValidated });
        if (tlsaRecords.length > 0) {
          if (dnssecValidated) anyTlsaAdValidated = true;
          else anyTlsaUnvalidated = true;
        }
      } catch (err) {
        if (err instanceof DnsLookupError) {
          if (!firstLookupError)
            firstLookupError = { code: err.code, message: err.message };
          hosts.push({ exchange, tlsaRecords: [], dnssecValidated: false });
          return;
        }
        throw err;
      }
    }),
  );

  if (anyTlsaAdValidated) {
    const validatedHosts = hosts
      .filter((h) => h.tlsaRecords.length > 0 && h.dnssecValidated)
      .map((h) => h.exchange)
      .join(", ");
    validations.push({
      status: "pass",
      message: `DANE/TLSA configured and DNSSEC-validated on: ${validatedHosts}`,
    });
    const unvalidatedHosts = hosts.filter(
      (h) => h.tlsaRecords.length > 0 && !h.dnssecValidated,
    );
    if (unvalidatedHosts.length > 0) {
      validations.push({
        status: "warn",
        message: `TLSA records present but DNSSEC not validated on: ${unvalidatedHosts.map((h) => h.exchange).join(", ")}`,
      });
    }
    return { status: "pass", hosts, validations };
  }

  if (anyTlsaUnvalidated) {
    const tlsaHosts = hosts
      .filter((h) => h.tlsaRecords.length > 0)
      .map((h) => h.exchange)
      .join(", ");
    validations.push({
      status: "warn",
      message: `TLSA records found but DNSSEC not validated — DANE enforcement requires DNSSEC (${tlsaHosts})`,
    });
    return { status: "warn", hosts, validations };
  }

  if (successfulQueries === 0 && firstLookupError) {
    validations.push({
      status: "fail",
      message: `DANE/TLSA lookup failed: ${firstLookupError.message}`,
    });
    return {
      status: "fail",
      hosts,
      validations,
      lookup_error: firstLookupError,
    };
  }

  validations.push({
    status: "info",
    message: "DANE/TLSA not configured — no TLSA records found for MX hosts",
  });
  return { status: "info", hosts, validations };
}
