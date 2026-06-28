import { DnsLookupError, queryDoh } from "../dns/client.js";
import type { ScanBudget } from "../dns/scan-budget.js";
import type {
  DnsblListing,
  DnsblResult,
  MxResult,
  SpfIncludeNode,
  SpfResult,
  Validation,
} from "./types.js";

const MAX_DNSBL_IPS = 10;
const DQS_ZONE = "zen.dq.spamhaus.net";

function extractIpsFromTree(
  node: SpfIncludeNode | null,
  out: Set<string>,
): void {
  if (!node) return;
  for (const mech of node.mechanisms) {
    const bare = mech.replace(/^[+\-~?]/, "");
    if (bare.startsWith("ip4:") || bare.startsWith("ip6:")) {
      const ip = bare.slice(4).split("/")[0];
      if (ip) out.add(ip);
    }
  }
  for (const inc of node.includes) extractIpsFromTree(inc, out);
}

function reverseIpv4(ip: string): string | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  if (parts.some((p) => !/^\d+$/.test(p) || Number(p) > 255)) return null;
  return parts.slice().reverse().join(".");
}

function expandIPv6(ip: string): string | null {
  const trimmed = ip.split("%")[0];
  const halves = trimmed.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0) return null;
  if (halves.length === 1 && left.length !== 8) return null;
  const groups = [...left, ...Array(missing).fill("0"), ...right];
  if (groups.length !== 8) return null;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
  }
  return groups
    .map((g) => g.padStart(4, "0"))
    .join("")
    .toLowerCase();
}

function reverseIPv6(ip: string): string | null {
  const expanded = expandIPv6(ip.toLowerCase());
  if (!expanded) return null;
  return expanded.split("").reverse().join(".");
}

export async function analyzeDnsbl(
  _domain: string,
  mxResult: MxResult,
  spfResult: SpfResult,
  dqsKey: string | undefined,
  budget?: ScanBudget,
): Promise<DnsblResult> {
  if (!dqsKey) {
    return {
      status: "info",
      checked: 0,
      listed: [],
      validations: [
        {
          status: "info",
          message:
            "DNSBL check not configured — set DNSBL_DQS_KEY to enable Spamhaus ZEN lookups",
        },
      ],
    };
  }

  const candidateIps = new Set<string>();
  extractIpsFromTree(spfResult.include_tree, candidateIps);

  // Resolve MX hostnames to A records for additional sending IPs.
  await Promise.allSettled(
    mxResult.records.map(async (rec) => {
      try {
        const response = await queryDoh(rec.exchange, "A", budget);
        if (response?.Answer) {
          for (const a of response.Answer) {
            if (typeof a.data === "string" && a.data.trim()) {
              candidateIps.add(a.data.trim());
            }
          }
        }
      } catch {
        // Per-host resolution failures are ignored — we still check
        // whatever IPs we have from other sources.
      }
    }),
  );

  const ips = [...candidateIps].slice(0, MAX_DNSBL_IPS);
  if (ips.length === 0) {
    return {
      status: "info",
      checked: 0,
      listed: [],
      validations: [
        {
          status: "info",
          message: "No sending IPs derivable for DNSBL check",
        },
      ],
    };
  }

  const listedIps: Array<{ ip: string; returnCode: string }> = [];
  const validations: Validation[] = [];
  let lookupError: { code: string; message: string } | undefined;

  await Promise.allSettled(
    ips.map(async (ip) => {
      const isIPv6 = ip.includes(":");
      const reversed = isIPv6 ? reverseIPv6(ip) : reverseIpv4(ip);
      if (!reversed) return;
      // Query name embeds dqsKey — queryDoh draws from the shared budget.
      const queryName = `${reversed}.${dqsKey}.${DQS_ZONE}`;
      try {
        const response = await queryDoh(queryName, "A", budget);
        if (response?.Answer && response.Answer.length > 0) {
          listedIps.push({ ip, returnCode: response.Answer[0].data });
        }
      } catch (err) {
        if (err instanceof DnsLookupError && !lookupError) {
          lookupError = { code: err.code, message: err.message };
        }
      }
    }),
  );

  if (listedIps.length > 0) {
    const listedStr = listedIps
      .map((l) => `${l.ip} (${l.returnCode})`)
      .join(", ");
    validations.push({
      status: "warn",
      message: `${listedIps.length} sending IP${listedIps.length !== 1 ? "s" : ""} listed on Spamhaus ZEN: ${listedStr}`,
    });
    validations.push({
      status: "info",
      message: `${ips.length} IP${ips.length !== 1 ? "s" : ""} checked`,
    });
    const listed: DnsblListing[] = listedIps.map((l) => ({
      ip: l.ip,
      zones: ["zen"],
    }));
    return { status: "warn", checked: ips.length, listed, validations };
  }

  if (lookupError) {
    validations.push({
      status: "warn",
      message: `DNSBL lookup failed (${lookupError.code}) — could not verify sending IPs`,
    });
    return {
      status: "warn",
      checked: ips.length,
      listed: [],
      validations,
      lookup_error: lookupError,
    };
  }

  validations.push({
    status: "pass",
    message: `${ips.length} sending IP${ips.length !== 1 ? "s" : ""} checked — none listed on Spamhaus ZEN`,
  });
  return { status: "pass", checked: ips.length, listed: [], validations };
}
