import { DnsLookupError, queryDoh } from "../dns/client.js";
import type {
  DaneHostResult,
  DaneResult,
  DaneTlsaRecord,
  Validation,
} from "./types.js";

// TLSA record data arrives as "<usage> <selector> <matching-type> <hex-data>"
// e.g. "3 1 1 abcdef1234..."
function parseTlsaRecord(data: string): DaneTlsaRecord | null {
  const parts = data.trim().split(/\s+/);
  if (parts.length < 4) return null;
  const usage = parseInt(parts[0], 10);
  const selector = parseInt(parts[1], 10);
  const matchingType = parseInt(parts[2], 10);
  if (
    Number.isNaN(usage) ||
    Number.isNaN(selector) ||
    Number.isNaN(matchingType)
  )
    return null;
  return { usage, selector, matchingType, data: parts.slice(3).join("") };
}

export async function analyzeDane(
  _domain: string,
  mxExchanges: string[],
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
        const response = await queryDoh(`_25._tcp.${exchange}`, "TLSA");
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
