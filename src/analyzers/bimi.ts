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
      record: null,
      tags: null,
      validations: [
        {
          status: "warn",
          message: `TXT record at default._bimi.${domain} is not a valid BIMI record`,
        },
      ],
    };
  }

  const tags = parseTags(bimiRecord);
  const validations: Validation[] = [];

  validations.push({ status: "pass", message: "BIMI record found" });

  if (dmarcPolicy === "reject") {
    validations.push({
      status: "pass",
      message: "DMARC policy is reject — meets BIMI requirement",
    });
  } else if (dmarcPolicy === "quarantine") {
    validations.push({
      status: "warn",
      message:
        "DMARC quarantine policy meets minimum BIMI requirement, but reject is preferred",
    });
  } else {
    validations.push({
      status: "warn",
      message: "BIMI requires a DMARC policy of quarantine or reject",
    });
  }

  if (tags.l) {
    validations.push({
      status: "pass",
      message: `Logo URL configured: ${tags.l}`,
    });
  } else {
    validations.push({
      status: "warn",
      message: "No logo URL (l=) in BIMI record",
    });
  }

  if (tags.a) {
    validations.push({
      status: "pass",
      message: `Authority certificate (VMC/CMC) configured: ${tags.a}`,
    });
  } else {
    validations.push({
      status: "warn",
      message:
        "No authority certificate (a=) — logo may not appear in Gmail/Apple Mail",
    });
  }

  const hasWarn = validations.some((v) => v.status === "warn");
  const status = hasWarn ? "warn" : "pass";

  return { status, record: bimiRecord, tags, validations };
}
