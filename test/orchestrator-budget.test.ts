/**
 * GHSA-f828-8wf8-vqp2 — orchestrator-level DoS umbrella.
 *
 * scan()/scanStreaming() must bound total work regardless of attacker-controlled
 * input. Two guards, exercised here against the REAL dmarc/spf/dkim analyzers and
 * the REAL DNS client (only the underlying node:dns resolver is mocked):
 *
 *  1. A shared per-scan DNS-query budget — a large DKIM selector list plus a
 *     rua/ruf-stuffed _dmarc record draws from ONE capped pool, so the total
 *     number of outbound resolver queries cannot scale with input size.
 *  2. A single overall deadline — even against a resolver that never answers,
 *     the scan resolves (with partial results) instead of hanging.
 *
 * The non-fan-out analyzers (mx/dnssec/dane/bimi/tls-rpt/mta-sts/security-txt)
 * are stubbed so the test isolates the DKIM + DMARC TXT fan-out the advisory
 * describes; dmarc/spf/dkim run for real.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Count + control the lowest layer: the node:dns resolver beneath queryTxt.
const { resolveTxtSpy } = vi.hoisted(() => ({ resolveTxtSpy: vi.fn() }));

vi.mock("node:dns", () => {
  class Resolver {
    setServers() {}
    resolveTxt(name: string) {
      return resolveTxtSpy(name);
    }
    resolveMx() {
      return Promise.reject(
        Object.assign(new Error("ENODATA"), { code: "ENODATA" }),
      );
    }
  }
  return { default: { promises: { Resolver } } };
});

// Silence Sentry breadcrumbs (orchestrator + client emit them).
vi.mock("@sentry/cloudflare", () => ({
  addBreadcrumb: vi.fn(),
  captureException: vi.fn(),
}));

// Stub every analyzer EXCEPT dmarc/spf/dkim, which we want to run for real so
// their TXT fan-out actually hits the (mocked) resolver and the shared budget.
vi.mock("../src/analyzers/mx.js", () => ({
  analyzeMx: vi.fn().mockResolvedValue({
    status: "info",
    records: [],
    providers: [],
    validations: [],
  }),
}));
vi.mock("../src/analyzers/dnssec.js", () => ({
  analyzeDnssec: vi.fn().mockResolvedValue({
    status: "info",
    signed: false,
    validated: false,
    validations: [],
  }),
}));
vi.mock("../src/analyzers/dane.js", () => ({
  analyzeDane: vi.fn().mockResolvedValue({
    status: "info",
    hosts: [],
    validations: [],
  }),
}));
vi.mock("../src/analyzers/bimi.js", () => ({
  prefetchBimiDns: vi.fn().mockResolvedValue(null),
  analyzeBimi: vi.fn().mockResolvedValue({
    status: "warn",
    record: null,
    tags: null,
    validations: [],
  }),
}));
vi.mock("../src/analyzers/tls-rpt.js", () => ({
  analyzeTlsRpt: vi.fn().mockResolvedValue({
    status: "info",
    record: null,
    tags: null,
    validations: [],
  }),
}));
vi.mock("../src/analyzers/mta-sts.js", () => ({
  analyzeMtaSts: vi.fn().mockResolvedValue({
    status: "fail",
    dns_record: null,
    policy: null,
    validations: [],
  }),
}));
vi.mock("../src/analyzers/security-txt.js", () => ({
  analyzeSecurityTxt: vi.fn().mockResolvedValue({
    status: "info",
    source_url: null,
    signed: false,
    fields: null,
    validations: [],
  }),
}));
vi.mock("../src/analyzers/mx-mta-sts-consistency.js", () => ({
  checkMxMtaStsConsistency: vi.fn().mockReturnValue([]),
}));

import { scan, scanStreaming } from "../src/orchestrator.js";

const DOMAIN = "attacker.example";

// _dmarc record stuffed with 100 external rua URIs → 100 authorization lookups.
const RUA_COUNT = 100;
const RUA = Array.from(
  { length: RUA_COUNT },
  (_, i) => `mailto:a${i}@ext${i}.example`,
).join(",");
const DMARC_RECORD = `v=DMARC1; p=reject; rua=${RUA}`;

// 300 attacker-supplied DKIM selectors → 300 (+common) selector probes.
const SELECTORS = Array.from({ length: 300 }, (_, i) => `sel${i}`);

// Total TXT demand without a cap: 1 (_dmarc) + 100 (rua auth) + 1 (spf root)
// + ~337 (dkim) ≈ 439 outbound resolver queries.
const UNCAPPED_DEMAND = 400;

function absent(): Promise<never> {
  return Promise.reject(
    Object.assign(new Error("ENODATA"), { code: "ENODATA" }),
  );
}

beforeEach(() => {
  resolveTxtSpy.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("scan() bounds DNS fan-out under worst-case input (GHSA-f828-8wf8-vqp2)", () => {
  it("caps total resolver queries at the shared budget and still completes", async () => {
    const MAX = 40;
    // Fast resolver: _dmarc returns the stuffed record, everything else is absent.
    resolveTxtSpy.mockImplementation((name: string) => {
      if (name === `_dmarc.${DOMAIN}`) {
        return Promise.resolve([[DMARC_RECORD]]);
      }
      return absent();
    });

    const result = await scan(
      DOMAIN,
      SELECTORS,
      {},
      {
        maxDnsQueries: MAX,
        deadlineMs: 5000,
      },
    );

    // The cap engaged: total outbound queries are bounded by the pool, far
    // below the ~439 an uncapped scan would have issued.
    expect(resolveTxtSpy.mock.calls.length).toBeLessThanOrEqual(MAX);
    expect(resolveTxtSpy.mock.calls.length).toBeLessThan(UNCAPPED_DEMAND);
    // Queries did happen — this isn't a vacuous pass.
    expect(resolveTxtSpy.mock.calls.length).toBeGreaterThan(0);
    // Graceful: a well-formed partial result, not a throw.
    expect(result.grade).toBeTruthy();
    expect(result.protocols.dmarc).toBeDefined();
    expect(result.protocols.dkim).toBeDefined();
  });
});

describe("scan() enforces an overall deadline (GHSA-f828-8wf8-vqp2)", () => {
  it("resolves with partial results instead of hanging on a slow resolver", async () => {
    // Resolver that answers only after 500ms — far past the 80ms deadline.
    resolveTxtSpy.mockImplementation(
      (name: string) =>
        new Promise((resolve, reject) => {
          setTimeout(() => {
            if (name === `_dmarc.${DOMAIN}`) resolve([[DMARC_RECORD]]);
            else
              reject(Object.assign(new Error("ENODATA"), { code: "ENODATA" }));
          }, 500);
        }),
    );

    const t0 = Date.now();
    const result = await scan(
      DOMAIN,
      SELECTORS,
      {},
      {
        maxDnsQueries: 1000,
        deadlineMs: 80,
      },
    );
    const elapsed = Date.now() - t0;

    // The deadline (80ms) beat the slow resolver (500ms): we did not wait.
    expect(elapsed).toBeLessThan(400);
    // Still a well-formed result, degraded gracefully.
    expect(result.grade).toBeTruthy();
    expect(result.protocols.dmarc.status).toBe("fail");
  });
});

describe("scanStreaming() bounds fan-out and streams every protocol once", () => {
  it("caps resolver queries and emits each protocol exactly once", async () => {
    const MAX = 40;
    resolveTxtSpy.mockImplementation((name: string) => {
      if (name === `_dmarc.${DOMAIN}`) {
        return Promise.resolve([[DMARC_RECORD]]);
      }
      return absent();
    });

    const counts = new Map<string, number>();
    await scanStreaming(
      DOMAIN,
      SELECTORS,
      (id) => counts.set(id, (counts.get(id) ?? 0) + 1),
      {},
      { maxDnsQueries: MAX, deadlineMs: 5000 },
    );

    expect(resolveTxtSpy.mock.calls.length).toBeLessThanOrEqual(MAX);
    // Every protocol streamed exactly once — no double-emit, no missing card.
    for (const id of [
      "mx",
      "dmarc",
      "spf",
      "dkim",
      "bimi",
      "mta_sts",
      "security_txt",
      "tls_rpt",
      "dnssec",
      "dane",
      "dnsbl",
    ]) {
      expect(counts.get(id)).toBe(1);
    }
  });
});
