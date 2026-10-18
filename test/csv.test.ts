import { describe, expect, it } from "vitest";
import type { ScanResult } from "../src/analyzers/types.js";
import { escapeCsvField, generateCsv } from "../src/csv.js";
import type { GradeBreakdown } from "../src/shared/scoring.js";

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

describe("escapeCsvField", () => {
  it("prepends a single quote for fields starting with =", () => {
    expect(escapeCsvField("=cmd|' /C calc'!A0")).toBe("'=cmd|' /C calc'!A0");
  });

  it("prepends a single quote for fields starting with +", () => {
    expect(escapeCsvField("+1+1")).toBe("'+1+1");
  });

  it("prepends a single quote for fields starting with -", () => {
    expect(escapeCsvField("-1+1")).toBe("'-1+1");
  });

  it("prepends a single quote for fields starting with @", () => {
    expect(escapeCsvField("@SUM(1+1)")).toBe("'@SUM(1+1)");
  });

  it("prepends a single quote for fields starting with tab", () => {
    expect(escapeCsvField("\t=1+1")).toBe("'\t'=1+1");
  });

  it("prepends a single quote for fields starting with carriage return", () => {
    expect(escapeCsvField("\r=1+1")).toBe("\"'\r'=1+1\"");
  });

  it("prepends a single quote for fields starting with newline", () => {
    expect(escapeCsvField("\n=1+1")).toBe("\"'\n'=1+1\"");
  });

  it("neutralizes a formula trigger after an embedded semicolon", () => {
    expect(escapeCsvField("v=DMARC1;=HYPERLINK(1)")).toBe(
      "v=DMARC1;'=HYPERLINK(1)",
    );
    expect(escapeCsvField("a; +1")).toBe("a; '+1");
    expect(escapeCsvField("v=DMARC1; p=reject")).toBe("v=DMARC1; p=reject");
  });

  it("neutralizes a formula trigger after an embedded tab, CR or LF", () => {
    expect(escapeCsvField("a\t-1")).toBe("a\t'-1");
    expect(escapeCsvField("a\n@SUM(1)")).toBe('"a\n\'@SUM(1)"');
  });

  it("neutralizes a trigger after a separator and double quotes", () => {
    expect(escapeCsvField('a;"=1+1')).toBe('"a;""\'=1+1"');
    expect(escapeCsvField('a\t"=1+1')).toBe('"a\t""\'=1+1"');
  });

  it("returns plain string unchanged", () => {
    expect(escapeCsvField("hello")).toBe("hello");
  });

  it("wraps field containing comma in double quotes", () => {
    expect(escapeCsvField("a,b")).toBe('"a,b"');
  });

  it("wraps field containing double quote and escapes it", () => {
    expect(escapeCsvField('say "hi"')).toBe('"say ""hi"""');
  });

  it("wraps field containing newline", () => {
    expect(escapeCsvField("line1\nline2")).toBe('"line1\nline2"');
  });

  it("wraps field containing carriage return", () => {
    expect(escapeCsvField("a\rb")).toBe('"a\rb"');
  });

  it("handles empty string", () => {
    expect(escapeCsvField("")).toBe("");
  });
});

// Models a spreadsheet that splits on `sep` and on line breaks and honours a
// double quote only at the start of a cell, keeping any text after the
// closing quote (so `""=1+1` reads as `=1+1`).
function lenientCells(csv: string, sep: string): string[] {
  const cells: string[] = [];
  const isBreak = (ch: string) => ch === sep || ch === "\r" || ch === "\n";
  let i = 0;
  while (i < csv.length) {
    let cell = "";
    if (csv[i] === '"') {
      // Quoted section: "" is a literal quote, a lone " closes it.
      for (i++; i < csv.length; i++) {
        if (csv[i] === '"' && csv[i + 1] !== '"') break;
        if (csv[i] === '"') i++;
        cell += csv[i];
      }
      i++;
    }
    while (i < csv.length && !isBreak(csv[i])) cell += csv[i++];
    cells.push(cell);
    i++;
  }
  return cells;
}

describe("generateCsv", () => {
  it("starts with UTF-8 BOM", () => {
    const csv = generateCsv(makeScanResult());
    expect(csv.charCodeAt(0)).toBe(0xfeff);
  });

  it("has correct header row", () => {
    const csv = generateCsv(makeScanResult());
    const header = csv.split("\r\n")[0].replace("\uFEFF", "");
    expect(header).toBe(
      "Domain,Grade,Timestamp,Protocol,Status,Findings,Recommendations,Raw Record",
    );
  });

  it("produces 6 data rows (one per protocol)", () => {
    const csv = generateCsv(makeScanResult());
    const lines = csv.trim().split("\r\n");
    // header + 6 protocol rows
    expect(lines).toHaveLength(7);
  });

  it("uses CRLF line endings per RFC 4180", () => {
    const csv = generateCsv(makeScanResult());
    // Every line break should be \r\n
    const withoutBom = csv.replace("\uFEFF", "");
    expect(withoutBom).not.toMatch(/[^\r]\n/);
  });

  it("includes correct protocol names in order", () => {
    const csv = generateCsv(makeScanResult());
    const lines = csv.trim().split("\r\n").slice(1); // skip header
    const protocols = lines.map((l) => l.split(",")[3]);
    expect(protocols).toEqual([
      "MX",
      "DMARC",
      "SPF",
      "DKIM",
      "BIMI",
      "MTA-STS",
    ]);
  });

  it("formats findings with status prefix and semicolons", () => {
    const csv = generateCsv(makeScanResult());
    const lines = csv.trim().split("\r\n");
    // DMARC row (index 2, after MX at index 1) has 2 validations
    const dmarcRow = lines[2];
    expect(dmarcRow).toContain("[pass] DMARC record found");
    expect(dmarcRow).toContain("[pass] Policy set to reject");
  });

  it("filters recommendations by protocol", () => {
    const csv = generateCsv(makeScanResult());
    const lines = csv.trim().split("\r\n");
    // SPF row (index 3) should have the SPF recommendation
    const spfRow = lines[3];
    expect(spfRow).toContain("[P2] Switch SPF from ~all to -all");
    // BIMI row (index 5) should have the BIMI recommendation
    const bimiRow = lines[5];
    expect(bimiRow).toContain("[P3] Add a BIMI record");
    // DMARC row (index 2) should have no recommendations
    const dmarcRow = lines[2];
    // Recommendations field is 7th (index 6), should be empty
    // Parse carefully — just check it doesn't contain [P
    expect(dmarcRow).not.toContain("[P1]");
    expect(dmarcRow).not.toContain("[P2]");
    expect(dmarcRow).not.toContain("[P3]");
  });

  it("shows DKIM selector summary as raw record", () => {
    const csv = generateCsv(makeScanResult());
    const lines = csv.trim().split("\r\n");
    // DKIM row (index 4, after MX/DMARC/SPF)
    const dkimRow = lines[4];
    expect(dkimRow).toContain("google: rsa/2048bit");
  });

  it("handles null raw records as empty", () => {
    const csv = generateCsv(makeScanResult());
    const lines = csv.trim().split("\r\n");
    // BIMI row (index 5) has null record
    const bimiRow = lines[5];
    // Last field should be empty
    const fields = bimiRow.split(",");
    expect(fields[fields.length - 1]).toBe("");
  });

  it("handles empty validations", () => {
    const csv = generateCsv(makeScanResult());
    const lines = csv.trim().split("\r\n");
    // BIMI row (index 5) has empty validations
    const bimiFields = lines[5].split(",");
    // Findings field (index 5) should be empty
    expect(bimiFields[5]).toBe("");
  });

  it("escapes fields containing commas", () => {
    const result = makeScanResult();
    result.protocols.dmarc.record =
      "v=DMARC1; p=reject; rua=mailto:dmarc@example.com,mailto:admin@example.com";
    const csv = generateCsv(result);
    // The raw record field should be quoted
    expect(csv).toContain(
      '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com,mailto:admin@example.com"',
    );
  });

  it("leaves no formula-led cell when split on ';' or tab", () => {
    const result = makeScanResult();
    result.protocols.dmarc.record =
      'v=DMARC1;=HYPERLINK("http://evil.example");"=1+1;\t-1';
    result.protocols.mta_sts.validations = [
      { status: "fail", message: 'Unknown policy mode "x;"=1+1;y"' },
    ];
    const csv = generateCsv(result);
    const formulaLed = /^[\s"]*[=+\-@]/;
    for (const sep of [";", "\t"]) {
      const cells = lenientCells(csv, sep);
      expect(cells.filter((cell) => formulaLed.test(cell))).toEqual([]);
    }
  });

  it("includes domain and grade in every row", () => {
    const csv = generateCsv(makeScanResult());
    const lines = csv.trim().split("\r\n").slice(1);
    for (const line of lines) {
      expect(line).toMatch(/^example\.com,B,/);
    }
  });
});
