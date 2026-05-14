import { DnsLookupError, queryTxt } from "../dns/client.js";
import type { TxtRecord } from "../dns/types.js";
import { parseTags } from "../shared/parse-tags.js";
import type { BimiResult, Validation } from "./types.js";

export function prefetchBimiDns(domain: string): Promise<TxtRecord | null> {
  return queryTxt(`default._bimi.${domain}`).catch((err) => {
    if (err instanceof DnsLookupError) return null;
    throw err;
  });
}

export async function analyzeBimi(
  domain: string,
  dmarcPolicy: string | null,
  prefetchedDns?: TxtRecord | null,
): Promise<BimiResult> {
  const txt =
    prefetchedDns !== undefined
      ? prefetchedDns
      : await queryTxt(`default._bimi.${domain}`);

  if (!txt) {
    const validations: Validation[] = [
      { status: "warn", message: `No BIMI record at default._bimi.${domain}` },
    ];
    if (dmarcPolicy && ["quarantine", "reject"].includes(dmarcPolicy)) {
      validations.push({
        status: "pass",
        message: "DMARC policy meets BIMI requirement (quarantine or reject)",
      });
    } else {
      validations.push({
        status: "warn",
        message: "BIMI requires a DMARC policy of quarantine or reject",
      });
    }
    return { status: "warn", record: null, tags: null, validations };
  }

  const bimiRecord = txt.entries.find((e) =>
    e.trimStart().startsWith("v=BIMI1"),
  );
  if (!bimiRecord) {
    return {
      status: "warn",
      record: txt.raw,
      tags: null,
      validations: [
        {
          status: "warn",
          message:
            "TXT record exists but is not a valid BIMI record (possibly a wildcard DNS entry)",
        },
      ],
    };
  }

  const tags = parseTags(bimiRecord);
  const validations: Validation[] = [];

  validations.push({ status: "pass", message: "BIMI record found" });

  // v= check
  if (tags.v !== "BIMI1") {
    validations.push({ status: "fail", message: "Invalid BIMI version tag" });
  }

  // l= check (logo URL)
  if (tags.l) {
    if (tags.l.startsWith("https://")) {
      validations.push({
        status: "pass",
        message: "Logo URL (l=) is present and uses HTTPS",
      });
    } else {
      validations.push({
        status: "warn",
        message: "Logo URL (l=) should use HTTPS",
      });
    }
  } else {
    validations.push({
      status: "warn",
      message: "No logo URL (l=) specified",
    });
  }

  // a= check (authority / VMC/CMC)
  if (tags.a) {
    validations.push({
      status: "pass",
      message: "Authority evidence (a=) VMC/CMC certificate URL present",
    });
  } else {
    validations.push({
      status: "warn",
      message:
        "No authority certificate (a=) — add a VMC or CMC to display your logo in Gmail and Apple Mail",
    });
  }

  // DMARC cross-check
  if (dmarcPolicy && ["quarantine", "reject"].includes(dmarcPolicy)) {
    validations.push({
      status: "pass",
      message: "DMARC policy meets BIMI requirement",
    });
  } else {
    validations.push({
      status: "fail",
      message:
        "DMARC policy must be quarantine or reject for BIMI to be honored",
    });
  }

  const hasFailure = validations.some((v) => v.status === "fail");
  const hasWarn = validations.some((v) => v.status === "warn");
  const status = hasFailure ? "fail" : hasWarn ? "warn" : "pass";

  return { status, record: bimiRecord, tags, validations };
}
