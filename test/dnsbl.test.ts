import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  analyzeDnsbl,
  MAX_DNSBL_HOSTNAMES,
  MAX_DNSBL_IPS,
} from "../src/analyzers/dnsbl.js";
import type { MxResult, SpfResult } from "../src/analyzers/types.js";

// Mock the DNS client: queryDoh resolves SPF/MX hostnames to A records,
// queryDnsbl issues the reversed-IP blocklist lookup.
vi.mock("../src/dns/client.js", () => ({
  queryDoh: vi.fn(),
  queryDnsbl: vi.fn(),
  DnsLookupError: class DnsLookupError extends Error {
    constructor(
      public readonly code: string,
      message: string,
    ) {
      super(message);
      this.name = "DnsLookupError";
    }
  },
}));

const { queryDoh, queryDnsbl, DnsLookupError } = (await import(
  "../src/dns/client.js"
)) as {
  queryDoh: ReturnType<typeof vi.fn>;
  queryDnsbl: ReturnType<typeof vi.fn>;
  DnsLookupError: new (
    code: string,
    message: string,
  ) => Error & { code: string };
};

// ── Fixture builders ──────────────────────────────────────────────

function spfWithMechanisms(
  mechanisms: string[],
  includes: SpfResult["include_tree"][] = [],
): SpfResult {
  return {
    status: "pass",
    record: "v=spf1 ...",
    lookups_used: 0,
    lookup_limit: 10,
    include_tree: {
      domain: "example.com",
      record: "v=spf1 ...",
      mechanisms,
      includes: includes.filter((n): n is NonNullable<typeof n> => n !== null),
    },
    validations: [],
  };
}

function emptySpf(): SpfResult {
  return {
    status: "fail",
    record: null,
    lookups_used: 0,
    lookup_limit: 10,
    include_tree: null,
    validations: [],
  };
}

function mxWith(exchanges: string[]): MxResult {
  return {
    status: "info",
    records: exchanges.map((exchange, i) => ({ priority: i * 10, exchange })),
    providers: [],
    validations: [],
  };
}

function emptyMx(): MxResult {
  return { status: "info", records: [], providers: [], validations: [] };
}

function aAnswer(ips: string[]) {
  return {
    Status: 0,
    AD: false,
    Answer: ips.map((data) => ({
      name: "host.example.com",
      type: 1,
      TTL: 300,
      data,
    })),
  };
}

beforeEach(() => {
  queryDoh.mockReset();
  queryDnsbl.mockReset();
});

// ── Credential-gated no-op ────────────────────────────────────────

describe("analyzeDnsbl — no DQS key (credential-gated no-op)", () => {
  it("returns a clean info result without touching DNS when no key is set", async () => {
    const result = await analyzeDnsbl(
      "example.com",
      spfWithMechanisms(["ip4:192.0.2.5", "-all"]),
      mxWith(["mx.example.com"]),
      undefined,
    );

    expect(result.status).toBe("info");
    expect(result.enabled).toBe(false);
    expect(result.checked).toHaveLength(0);
    expect(result.ips_checked).toBe(0);
    // Absolutely no DNS work on the no-key path.
    expect(queryDnsbl).not.toHaveBeenCalled();
    expect(queryDoh).not.toHaveBeenCalled();
    // Never a fail — self-host deploys and the test pool stay unaffected.
    expect(result.status).not.toBe("fail");
  });

  it("treats an empty-string key as absent (no-op)", async () => {
    const result = await analyzeDnsbl("example.com", emptySpf(), emptyMx(), "");
    expect(result.enabled).toBe(false);
    expect(queryDnsbl).not.toHaveBeenCalled();
  });
});

// ── Listed vs clean verdicts ──────────────────────────────────────

describe("analyzeDnsbl — listed IP", () => {
  it("flags a listed literal SPF ip4 address and cites the IP + zone", async () => {
    queryDnsbl.mockResolvedValue(["127.0.0.2"]); // SBL listing
    const result = await analyzeDnsbl(
      "example.com",
      spfWithMechanisms(["ip4:192.0.2.5", "-all"]),
      emptyMx(),
      "testkey",
    );

    expect(result.enabled).toBe(true);
    expect(result.status).toBe("warn");
    expect(result.checked).toHaveLength(1);
    expect(result.checked[0].ip).toBe("192.0.2.5");
    expect(result.checked[0].verdict).toBe("listed");
    expect(result.checked[0].zones).toContain("SBL");
    expect(
      result.validations.some((v) => v.message.includes("192.0.2.5")),
    ).toBe(true);
  });

  it("reverses the IP and embeds the key into the DQS zone for the lookup", async () => {
    queryDnsbl.mockResolvedValue(null);
    await analyzeDnsbl(
      "example.com",
      spfWithMechanisms(["ip4:192.0.2.5"]),
      emptyMx(),
      "testkey",
    );
    expect(queryDnsbl).toHaveBeenCalledWith(
      "5.2.0.192",
      "testkey",
      "zen.dq.spamhaus.net",
      undefined,
    );
  });

  it("maps an XBL return code to a zone label", async () => {
    queryDnsbl.mockResolvedValue(["127.0.0.4"]);
    const result = await analyzeDnsbl(
      "example.com",
      spfWithMechanisms(["ip4:192.0.2.5"]),
      emptyMx(),
      "testkey",
    );
    expect(result.checked[0].verdict).toBe("listed");
    expect(result.checked[0].zones?.join(" ")).toMatch(/XBL/);
  });
});

describe("analyzeDnsbl — clean IP", () => {
  it("reports not-listed when the DQS query returns NXDOMAIN (null)", async () => {
    queryDnsbl.mockResolvedValue(null);
    const result = await analyzeDnsbl(
      "example.com",
      spfWithMechanisms(["ip4:198.51.100.7", "-all"]),
      emptyMx(),
      "testkey",
    );
    expect(result.status).toBe("pass");
    expect(result.checked[0].verdict).toBe("clean");
    expect(result.ips_checked).toBe(1);
    expect(result.lookup_error).toBeUndefined();
  });
});

// ── Hostname resolution (SPF a / MX exchanges) ────────────────────

describe("analyzeDnsbl — derives IPs from hostnames", () => {
  it("resolves bare-a SPF host and MX exchanges to A records, then checks them", async () => {
    queryDoh.mockImplementation((name: string) => {
      if (name === "example.com")
        return Promise.resolve(aAnswer(["198.51.100.1"]));
      if (name === "mx.example.com")
        return Promise.resolve(aAnswer(["203.0.113.7"]));
      return Promise.resolve(null);
    });
    queryDnsbl.mockResolvedValue(null);

    const result = await analyzeDnsbl(
      "example.com",
      spfWithMechanisms(["a", "-all"]),
      mxWith(["mx.example.com"]),
      "testkey",
    );

    expect(queryDoh).toHaveBeenCalledWith("example.com", "A", undefined);
    expect(queryDoh).toHaveBeenCalledWith("mx.example.com", "A", undefined);
    expect(result.ips_checked).toBe(2);
    expect(result.checked.every((c) => c.verdict === "clean")).toBe(true);
    expect(result.status).toBe("pass");
  });
});

// ── DnsLookupError degrades to "could not verify" ─────────────────

describe("analyzeDnsbl — lookup error", () => {
  it("surfaces a DQS SERVFAIL as 'could not verify', not a false clean", async () => {
    queryDnsbl.mockRejectedValue(
      new DnsLookupError("ESERVFAIL", "DNS server failure (SERVFAIL)"),
    );
    const result = await analyzeDnsbl(
      "example.com",
      spfWithMechanisms(["ip4:192.0.2.5"]),
      emptyMx(),
      "testkey",
    );
    expect(result.status).toBe("warn");
    expect(result.checked[0].verdict).toBe("error");
    expect(result.lookup_error).toBeDefined();
    expect(result.lookup_error?.code).toBe("ESERVFAIL");
  });

  it("degrades to 'could not verify' when the shared budget is exhausted mid-scan", async () => {
    // ScanBudgetError subclasses DnsLookupError, so a budget breach during the
    // DQS query must surface as "could not verify", never a false clean.
    queryDnsbl.mockRejectedValue(
      new DnsLookupError(
        "BUDGET_EXCEEDED",
        "Per-scan DNS query budget exhausted",
      ),
    );
    const result = await analyzeDnsbl(
      "example.com",
      spfWithMechanisms(["ip4:192.0.2.5"]),
      emptyMx(),
      "testkey",
    );
    expect(result.status).toBe("warn");
    expect(result.checked[0].verdict).toBe("error");
    expect(result.lookup_error?.code).toBe("BUDGET_EXCEEDED");
  });

  it("treats a 127.255.255.x DQS return code as an error, not a listing", async () => {
    // 127.255.255.254 = "query via public/unauthorized resolver" — a DQS
    // signal, NOT a real listing.
    queryDnsbl.mockResolvedValue(["127.255.255.254"]);
    const result = await analyzeDnsbl(
      "example.com",
      spfWithMechanisms(["ip4:192.0.2.5"]),
      emptyMx(),
      "testkey",
    );
    expect(result.checked[0].verdict).toBe("error");
    expect(result.status).toBe("warn");
    expect(result.lookup_error).toBeDefined();
  });
});

// ── No derivable IPs ──────────────────────────────────────────────

describe("analyzeDnsbl — no derivable IPs", () => {
  it("returns info (enabled) when the key is set but nothing resolves", async () => {
    const result = await analyzeDnsbl(
      "example.com",
      emptySpf(),
      emptyMx(),
      "testkey",
    );
    expect(result.enabled).toBe(true);
    expect(result.status).toBe("info");
    expect(result.ips_found).toBe(0);
    expect(queryDnsbl).not.toHaveBeenCalled();
  });
});

// ── Per-scan cap (DoS — GHSA-f828-8wf8-vqp2) ──────────────────────

describe("analyzeDnsbl — per-scan IP cap", () => {
  it("a huge SPF/MX set cannot blow the query budget", async () => {
    queryDoh.mockResolvedValue(null);
    queryDnsbl.mockResolvedValue(null);

    // 1000 literal ip4 + 50 a:host mechanisms + 50 MX exchanges — far past caps.
    const ip4Mechs = Array.from(
      { length: 1000 },
      (_, i) => `ip4:198.51.100.${i % 256}`,
    );
    const aMechs = Array.from({ length: 50 }, (_, i) => `a:h${i}.example.com`);
    const exchanges = Array.from(
      { length: 50 },
      (_, i) => `mx${i}.example.com`,
    );

    const result = await analyzeDnsbl(
      "example.com",
      spfWithMechanisms([...ip4Mechs, ...aMechs, "-all"]),
      mxWith(exchanges),
      "testkey",
    );

    // Hostname resolution is capped...
    expect(queryDoh.mock.calls.length).toBeLessThanOrEqual(MAX_DNSBL_HOSTNAMES);
    // ...and the blocklist fan-out is capped, independent of input size.
    expect(queryDnsbl.mock.calls.length).toBeLessThanOrEqual(MAX_DNSBL_IPS);
    expect(result.ips_checked).toBeLessThanOrEqual(MAX_DNSBL_IPS);
    // The cap engaged on a real over-cap input — not a vacuous pass.
    expect(result.ips_found).toBeGreaterThan(MAX_DNSBL_IPS);
    // Still a graceful, well-formed result.
    expect(result.enabled).toBe(true);
    expect(result.validations.length).toBeGreaterThan(0);
  });

  it("threads the shared ScanBudget into every DQS query", async () => {
    queryDnsbl.mockResolvedValue(null);
    const budget = { consume: vi.fn() } as never;
    await analyzeDnsbl(
      "example.com",
      spfWithMechanisms(["ip4:192.0.2.5"]),
      emptyMx(),
      "testkey",
      budget,
    );
    expect(queryDnsbl).toHaveBeenCalledWith(
      "5.2.0.192",
      "testkey",
      "zen.dq.spamhaus.net",
      budget,
    );
  });
});
