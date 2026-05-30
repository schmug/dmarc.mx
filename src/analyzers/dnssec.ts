import { DnsLookupError, queryDoh } from "../dns/client.js";
import type { DnssecResult, Validation } from "./types.js";

export async function analyzeDnssec(domain: string): Promise<DnssecResult> {
  const validations: Validation[] = [];

  let response: Awaited<ReturnType<typeof queryDoh>>;
  try {
    // Query DS records for the domain. DS records live in the parent zone and
    // signal that the parent has signed the delegation — the presence of DS
    // records (plus the AD flag from a validating resolver) is the standard
    // way to determine DNSSEC status without doing a full chain-of-trust walk.
    response = await queryDoh(domain, "DS");
  } catch (err) {
    if (err instanceof DnsLookupError) {
      validations.push({
        status: "fail",
        message: `DNSSEC lookup failed: ${err.message}`,
      });
      return {
        status: "fail",
        signed: false,
        validated: false,
        validations,
        lookup_error: { code: err.code, message: err.message },
      };
    }
    throw err;
  }

  if (!response) {
    // NXDOMAIN or no DS records — zone is unsigned
    validations.push({
      status: "info",
      message: "DNSSEC not configured — no DS records in the parent zone",
    });
    return { status: "info", signed: false, validated: false, validations };
  }

  const ad = response.AD;

  if (ad) {
    validations.push({
      status: "pass",
      message:
        "DNSSEC signed and validated — DS records present, AD flag set by resolver",
    });
    return { status: "pass", signed: true, validated: true, validations };
  }

  // DS records exist but the resolver did not set the AD flag — the zone has
  // DNSSEC configured but validation failed or the resolving path is not
  // DNSSEC-aware. Surface as warn rather than pass so the user knows to check
  // their DNSSEC signing chain.
  validations.push({
    status: "warn",
    message:
      "DNSSEC signed but not validated — DS records present but resolver AD flag not set (check zone signing chain)",
  });
  return { status: "warn", signed: true, validated: false, validations };
}
