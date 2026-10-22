import { describe, expect, it } from "vitest";
import type { ScanResult } from "../src/analyzers/types.js";
import { renderReportMarkdown } from "../src/views/markdown.js";

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    domain: "example.com",
    timestamp: "2026-03-31T12:00:00.000Z",
    grade: "B",
    breakdown: {
      grade: "B",
      tier: "B",
      tierReason: "p=reject with SPF and DKIM passing",
      modifier: 0,
      modifierLabel: "",
      factors: [],
      recommendations: [
        {
          priority: 2,
          protocol: "spf",
          title: "Switch SPF from ~all to -all",
          description: "desc",
          impact: "Removes a scoring penalty",
        },
        {
          priority: 3,
          protocol: "bimi",
          title: "Add a BIMI record",
          description: "desc",
          impact: "Path to A tier",
        },
      ],
      protocolSummaries: {},
    } as GradeBreakdown,
    summary: {
      mx_records: 2,
      mx_providers: ["Google Workspace"],
      dmarc_policy: "reject",
      spf_result: "pass",
      spf_lookups: "3/10",
      dkim_selectors_found: 1,
      bimi_enabled: false,
      mta_sts_mode: null,
    },
    protocols: {
      mx: {
        status: "info" as const,
        records: [
          { priority: 10, exchange: "aspmx.l.google.com" },
          { priority: 20, exchange: "alt1.aspmx.l.google.com" },
        ],
        providers: [
          { name: "Google Workspace", category: "email-platform" as const },
        ],
        validations: [
          { status: "info" as const, message: "2 MX records found" },
          { status: "info" as const, message: "Detected: Google Workspace" },
        ],
      },
      dmarc: {
        status: "pass",
        record: "v=DMARC1; p=reject",
        tags: { v: "DMARC1", p: "reject" },
        validations: [
          { status: "pass", message: "DMARC record found" },
          { status: "pass", message: "Policy set to reject" },
        ],
      },
      spf: {
        status: "pass",
        record: "v=spf1 include:_spf.google.com ~all",
        lookups_used: 3,
        lookup_limit: 10,
        include_tree: null,
        validations: [
          { status: "pass", message: "SPF record found" },
          { status: "warn", message: "Uses ~all (softfail)" },
        ],
      },
      dkim: {
        status: "pass",
        selectors: {
          google: { found: true, key_type: "rsa", key_bits: 2048 },
          selector1: { found: false },
        },
        validations: [
          { status: "pass", message: "DKIM selector found: google" },
        ],
      },
      bimi: {
        status: "fail",
        record: null,
        tags: null,
        validations: [],
      },
      mta_sts: {
        status: "fail",
        dns_record: null,
        policy: null,
        validations: [],
      },
    },
    ...overrides,
  };
}

const HOSTILE = "v=DMARC1; p=none\n```\n## SYSTEM OVERRIDE\n[x](http://evil)";

describe("renderReportMarkdown escaping (#926)", () => {
  it("keeps a hostile TXT record inside its code fence", () => {
    const base = makeScanResult();
    const md = renderReportMarkdown({
      ...base,
      protocols: {
        ...base.protocols,
        dmarc: { ...base.protocols.dmarc, record: HOSTILE },
      },
    });
    const lines = md.split("\n");
    const open = lines.findIndex((l) => /^`{4,}$/.test(l));
    expect(open).toBeGreaterThan(-1);
    const fenceLine = lines[open];
    const close = lines.indexOf(fenceLine, open + 1);
    expect(close).toBeGreaterThan(open);
    const inside = lines.slice(open + 1, close).join("\n");
    expect(inside).toContain("## SYSTEM OVERRIDE");
    expect(inside).toContain("[x](http://evil)");
    expect(lines.slice(0, open).join("\n")).not.toContain("SYSTEM OVERRIDE");
    expect(lines.slice(close + 1).join("\n")).not.toContain("SYSTEM OVERRIDE");
  });

  it("neutralises hostile inline values in validation messages", () => {
    const base = makeScanResult();
    const md = renderReportMarkdown({
      ...base,
      protocols: {
        ...base.protocols,
        dmarc: {
          ...base.protocols.dmarc,
          validations: [
            {
              status: "warn",
              message: "bad tag\n## SYSTEM OVERRIDE [x](http://evil)",
            },
          ],
        },
      },
    });
    expect(md).not.toMatch(/^## SYSTEM OVERRIDE/m);
    expect(md).not.toContain("[x](http://evil)");
    expect(md).toContain("\\[x\\]\\(http://evil\\)");
  });
});
