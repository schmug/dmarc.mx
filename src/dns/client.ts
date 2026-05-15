import dns from "node:dns";
import * as Sentry from "@sentry/cloudflare";
import type { MxRecord, TxtRecord } from "./types.js";

export function parseDnsServers(raw: string | undefined): string[] | null {
  if (!raw) return null;
  const servers = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return servers.length > 0 ? servers : null;
}

export class DnsLookupError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "DnsLookupError";
  }
}

const resolver = new dns.promises.Resolver();
const DNS_TIMEOUT_MS = 3000;

// Local-dev override: `DNS_SERVERS=8.8.8.8,1.1.1.1 npm run dev` points the
// resolver at custom servers. In Cloudflare Workers prod the var is absent and
// the built-in polyfill is used as-is; setServers() may be a no-op there.
const customDnsServers =
  typeof process !== "undefined"
    ? parseDnsServers(process.env?.DNS_SERVERS)
    : null;
if (customDnsServers) {
  try {
    resolver.setServers(customDnsServers);
  } catch (err) {
    console.warn("Failed to apply DNS_SERVERS override:", err);
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("DNS timeout")), ms);
  });

  return Promise.race([promise, timeoutPromise]).finally(() => {
    clearTimeout(timer);
  });
}

// ENOTFOUND/ENODATA = record genuinely absent (NXDOMAIN / NODATA).
// ESERVFAIL and timeouts are resolver errors — the record may exist but
// the query failed. These are re-thrown as DnsLookupError so callers can
// surface them to the user rather than treating them as "not configured".
function isDnsAbsent(err: unknown): boolean {
  if (typeof err === "object" && err !== null && "code" in err) {
    const code = (err as { code: string }).code;
    return code === "ENOTFOUND" || code === "ENODATA";
  }
  return false;
}

function toDnsLookupError(err: unknown): DnsLookupError | null {
  if (err instanceof Error && err.message === "DNS timeout") {
    return new DnsLookupError("DNS_TIMEOUT", "DNS query timed out");
  }
  if (typeof err === "object" && err !== null && "code" in err) {
    const code = (err as { code: string }).code;
    if (code === "ESERVFAIL") {
      return new DnsLookupError(code, "DNS server failure (SERVFAIL)");
    }
  }
  return null;
}

export async function queryTxt(name: string): Promise<TxtRecord | null> {
  Sentry.addBreadcrumb({
    category: "dns.query",
    message: `TXT ${name}`,
    data: { type: "TXT", hostname: name },
    level: "info",
  });
  try {
    const records = await withTimeout(
      resolver.resolveTxt(name),
      DNS_TIMEOUT_MS,
    );
    // workerd's node:dns polyfill may join multi-part TXT chunks with literal
    // quote characters (e.g. 'part1" "part2') instead of splitting properly.
    // Strip these artifacts so downstream parsing sees a clean record.
    const entries = records.map((chunks) =>
      chunks.join("").replace(/"\s*"/g, ""),
    );
    return { entries, raw: entries.join(" ") };
  } catch (err: unknown) {
    if (isDnsAbsent(err)) {
      Sentry.addBreadcrumb({
        category: "dns.nxdomain",
        message: `TXT ${name} not found`,
        data: {
          type: "TXT",
          hostname: name,
          reason: (err as { code?: string }).code ?? "nxdomain",
        },
        level: "info",
      });
      return null;
    }
    const lookupErr = toDnsLookupError(err);
    if (lookupErr) {
      Sentry.addBreadcrumb({
        category: "dns.lookup_error",
        message: `TXT ${name} lookup failed: ${lookupErr.code}`,
        data: { type: "TXT", hostname: name, reason: lookupErr.code },
        level: "warning",
      });
      throw lookupErr;
    }
    throw err;
  }
}

export async function queryMx(name: string): Promise<MxRecord[] | null> {
  Sentry.addBreadcrumb({
    category: "dns.query",
    message: `MX ${name}`,
    data: { type: "MX", hostname: name },
    level: "info",
  });
  try {
    const records = await withTimeout(resolver.resolveMx(name), DNS_TIMEOUT_MS);
    return records.map((r) => ({ priority: r.priority, exchange: r.exchange }));
  } catch (err: unknown) {
    if (isDnsAbsent(err)) {
      Sentry.addBreadcrumb({
        category: "dns.nxdomain",
        message: `MX ${name} not found`,
        data: {
          type: "MX",
          hostname: name,
          reason: (err as { code?: string }).code ?? "nxdomain",
        },
        level: "info",
      });
      return null;
    }
    const lookupErr = toDnsLookupError(err);
    if (lookupErr) {
      Sentry.addBreadcrumb({
        category: "dns.lookup_error",
        message: `MX ${name} lookup failed: ${lookupErr.code}`,
        data: { type: "MX", hostname: name, reason: lookupErr.code },
        level: "warning",
      });
      throw lookupErr;
    }
    throw err;
  }
}
