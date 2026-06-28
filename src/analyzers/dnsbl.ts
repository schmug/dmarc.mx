import { DnsLookupError, queryDnsbl, queryDoh } from "../dns/client.js";
import type { ScanBudget } from "../dns/scan-budget.js";
import type {
  DnsblListing,
  DnsblResult,
  MxResult,
  SpfIncludeNode,
  SpfResult,
  Status,
  Validation,
} from "./types.js";

// DNSBL / IP-reputation analyzer (Spamhaus DQS free tier). INFORMATIONAL ONLY —
// the result never feeds src/shared/scoring.ts, so it cannot change the letter
// grade (issue #587, follow-up to the #419 decision). It is also OPTIONAL and
// credential-gated: it runs only when a DNSBL_DQS_KEY is threaded in from env,
// and degrades to a clean no-op (status "info", enabled:false — never a fail or
// a throw) when the key is absent, so self-host deploys and the test pool are
// unaffected.
//
// The "sending IPs" are derived from existing scan data — SPF ip4 literals and
// a/MX hostnames resolved to A records — and each is queried against
// `<reversed-ip>.<DQS_KEY>.zen.dq.spamhaus.net`. To respect the per-scan DoS
// budget (GHSA-f828-8wf8-vqp2) the fan-out is hard-capped: at most
// MAX_DNSBL_HOSTNAMES are resolved and at most MAX_DNSBL_IPS are queried,
// regardless of how large an attacker makes the SPF/MX set, and every query
// draws from the shared ScanBudget.

// Spamhaus DQS combined "ZEN" zone, keyed per account.
const DQS_ZONE = "zen.dq.spamhaus.net";

// Per-scan caps. Independent of attacker-controlled SPF/MX size: collection may
// surface thousands of IPs, but these bound the actual outbound DNS work.
export const MAX_DNSBL_HOSTNAMES = 5; // SPF a/MX hosts resolved to IPs
export const MAX_DNSBL_IPS = 10; // distinct IPs queried against the blocklist

// Guard against a pathologically deep/cyclic SPF include tree when collecting.
const MAX_SPF_DEPTH = 12;

/**
 * Validate a single IPv4 address, optionally with a `/32` suffix. SPF `ip4`
 * mechanisms can carry a CIDR range (`192.0.2.0/24`); a whole network is not a
 * meaningful DNSBL target, so ranges other than `/32` are skipped (returns
 * null). Returns the bare dotted-quad on success.
 */
function toSingleIpv4(addr: string): string | null {
  const [ip, prefix] = addr.split("/");
  if (prefix !== undefined && prefix !== "32") return null;
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    if (Number(p) > 255) return null;
  }
  return ip;
}

/** Reverse a (pre-validated) IPv4 address for a DNSBL query: a.b.c.d → d.c.b.a. */
function reverseIpv4(ip: string): string {
  const [a, b, c, d] = ip.split(".");
  return `${d}.${c}.${b}.${a}`;
}

interface SendingSource {
  host: string;
  kind: "a" | "mx";
}

/**
 * Walk SPF + MX, gathering derivable sending IPs. Pure (no DNS): literal `ip4`
 * addresses are returned directly; `a`/`a:host` mechanisms and MX exchanges
 * become hostnames to resolve. Bare `mx`/`mx:` is intentionally not chased
 * (it would require a second DNS hop) — the root domain's MX is already covered
 * by the MX result.
 */
export function collectSendingSources(
  spf: SpfResult,
  mx: MxResult,
): { ips: string[]; hosts: SendingSource[] } {
  const ips = new Set<string>();
  const hosts: SendingSource[] = [];
  const seenHosts = new Set<string>();
  const addHost = (host: string, kind: "a" | "mx") => {
    const key = `${kind}:${host}`;
    if (!seenHosts.has(key)) {
      seenHosts.add(key);
      hosts.push({ host, kind });
    }
  };

  const visited = new Set<string>();
  const walk = (node: SpfIncludeNode | null, depth: number): void => {
    if (!node || depth > MAX_SPF_DEPTH) return;
    if (visited.has(node.domain)) return;
    visited.add(node.domain);
    for (const mech of node.mechanisms) {
      const bare = mech.replace(/^[+\-~?]/, "");
      if (bare.startsWith("ip4:")) {
        const single = toSingleIpv4(bare.slice(4));
        if (single) ips.add(single);
      } else if (bare === "a") {
        addHost(node.domain, "a");
      } else if (bare.startsWith("a:")) {
        const host = bare.slice(2).split("/")[0];
        if (host) addHost(host, "a");
      }
    }
    for (const child of node.includes) walk(child, depth + 1);
  };
  walk(spf.include_tree, 0);

  for (const record of mx.records) {
    if (record.exchange) addHost(record.exchange, "mx");
  }

  return { ips: [...ips], hosts };
}

// Spamhaus ZEN return codes. 127.255.255.x are DQS signalling/error codes
// (e.g. .254 = query through an unauthorized/public resolver), NOT real
// listings — they must surface as "could not verify", never as "listed".
function classifyDqsCode(code: string): {
  kind: "listed" | "error";
  zone: string;
} {
  if (code.startsWith("127.255.255.")) {
    return { kind: "error", zone: "DQS error code" };
  }
  const ZONES: Record<string, string> = {
    "127.0.0.2": "SBL",
    "127.0.0.3": "SBL CSS",
    "127.0.0.4": "XBL (CBL)",
    "127.0.0.5": "XBL (CBL)",
    "127.0.0.6": "XBL (CBL)",
    "127.0.0.7": "XBL (CBL)",
    "127.0.0.9": "SBL DROP/EDROP",
    "127.0.0.10": "PBL",
    "127.0.0.11": "PBL",
  };
  return { kind: "listed", zone: ZONES[code] ?? `listed (${code})` };
}

function noOp(): DnsblResult {
  return {
    status: "info",
    enabled: false,
    checked: [],
    ips_found: 0,
    ips_checked: 0,
    validations: [
      {
        status: "info",
        message: "IP reputation (DNSBL) check not enabled on this deployment",
      },
    ],
  };
}

export async function analyzeDnsbl(
  // The sending IPs are derived from the SPF tree's own node domains + MX
  // exchanges, so the scanned domain itself is not read here. Kept in the
  // signature for shape-parity with the other analyzers (mirrors analyzeDane).
  _domain: string,
  spf: SpfResult,
  mx: MxResult,
  dnsblKey: string | undefined,
  budget?: ScanBudget,
): Promise<DnsblResult> {
  // Credential-gated no-op — the dominant path on self-host / test deploys.
  if (!dnsblKey) return noOp();

  const { ips: literalIps, hosts } = collectSendingSources(spf, mx);

  // ip → set of human-readable sources (never contains the key).
  const sourceOf = new Map<string, Set<string>>();
  const addSource = (ip: string, src: string): void => {
    const set = sourceOf.get(ip) ?? new Set<string>();
    set.add(src);
    sourceOf.set(ip, set);
  };
  for (const ip of literalIps) addSource(ip, "SPF ip4");

  // Resolve a CAPPED slice of hostnames to A records (each draws from budget).
  let resolveError: { code: string; message: string } | undefined;
  await Promise.all(
    hosts.slice(0, MAX_DNSBL_HOSTNAMES).map(async ({ host, kind }) => {
      try {
        const resp = await queryDoh(host, "A", budget);
        for (const ans of resp?.Answer ?? []) {
          if (ans.type !== 1) continue; // A records only (skip CNAME chains)
          const ip = toSingleIpv4(ans.data);
          if (ip) addSource(ip, `${kind === "mx" ? "MX" : "A"}:${host}`);
        }
      } catch (err) {
        if (err instanceof DnsLookupError) {
          if (!resolveError)
            resolveError = { code: err.code, message: err.message };
          return;
        }
        throw err;
      }
    }),
  );

  const allIps = [...sourceOf.keys()];
  const ipsFound = allIps.length;
  const ipsToCheck = allIps.slice(0, MAX_DNSBL_IPS);

  if (ipsToCheck.length === 0) {
    const message = resolveError
      ? `Could not derive sending IPs — DNS lookup failed (${resolveError.code})`
      : "No sending IPs could be derived from SPF or MX to check";
    return {
      status: resolveError ? "warn" : "info",
      enabled: true,
      checked: [],
      ips_found: ipsFound,
      ips_checked: 0,
      validations: [{ status: resolveError ? "warn" : "info", message }],
      ...(resolveError ? { lookup_error: resolveError } : {}),
    };
  }

  const checked: DnsblListing[] = [];
  let firstQueryError: { code: string; message: string } | undefined;
  await Promise.all(
    ipsToCheck.map(async (ip) => {
      const source = [...(sourceOf.get(ip) ?? [])].join(", ");
      try {
        const codes = await queryDnsbl(
          reverseIpv4(ip),
          dnsblKey,
          DQS_ZONE,
          budget,
        );
        if (!codes || codes.length === 0) {
          checked.push({ ip, source, verdict: "clean" });
          return;
        }
        const zones = new Set<string>();
        let listed = false;
        let errored = false;
        for (const code of codes) {
          const c = classifyDqsCode(code);
          if (c.kind === "error") errored = true;
          else {
            listed = true;
            zones.add(c.zone);
          }
        }
        if (listed) {
          checked.push({ ip, source, verdict: "listed", zones: [...zones] });
        } else if (errored) {
          if (!firstQueryError)
            firstQueryError = {
              code: "DQS_RETURN",
              message: "DNSBL returned a query/error code",
            };
          checked.push({ ip, source, verdict: "error" });
        } else {
          checked.push({ ip, source, verdict: "clean" });
        }
      } catch (err) {
        if (err instanceof DnsLookupError) {
          if (!firstQueryError)
            firstQueryError = { code: err.code, message: err.message };
          checked.push({ ip, source, verdict: "error" });
          return;
        }
        throw err;
      }
    }),
  );

  const listed = checked.filter((c) => c.verdict === "listed");
  const clean = checked.filter((c) => c.verdict === "clean");
  const errored = checked.filter((c) => c.verdict === "error");

  const validations: Validation[] = [];
  if (ipsFound > ipsToCheck.length) {
    validations.push({
      status: "info",
      message: `Checked ${ipsToCheck.length} of ${ipsFound} derivable sending IPs (capped to bound per-scan DNS)`,
    });
  }
  for (const l of listed) {
    validations.push({
      status: "warn",
      message: `${l.ip} (${l.source}) is listed on Spamhaus ${l.zones?.join(", ") ?? "ZEN"}`,
    });
  }
  if (clean.length > 0) {
    validations.push({
      status: listed.length > 0 ? "info" : "pass",
      message: `${clean.length} sending IP${clean.length !== 1 ? "s" : ""} checked — not listed on Spamhaus ZEN`,
    });
  }
  if (errored.length > 0) {
    validations.push({
      status: "warn",
      message: `${errored.length} IP${errored.length !== 1 ? "s" : ""} could not be verified${firstQueryError ? ` (${firstQueryError.code})` : ""}`,
    });
  }

  const status: Status =
    listed.length > 0 || errored.length > 0 ? "warn" : "pass";

  // Surface a lookup_error only when nothing could be verified (no clean, no
  // listing) — i.e. a true "could not verify", never a false negative.
  const couldNotVerify =
    listed.length === 0 && clean.length === 0 && firstQueryError;

  return {
    status,
    enabled: true,
    checked,
    ips_found: ipsFound,
    ips_checked: ipsToCheck.length,
    validations,
    ...(couldNotVerify ? { lookup_error: firstQueryError } : {}),
  };
}
