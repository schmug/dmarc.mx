import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { compareBindings, runCheck, type Exemptions } from "../check-core.js";

const noExemptions: Exemptions = { prodOnly: [], stagingOnly: [] };

const base = `
[[d1_databases]]
binding = "DB"
database_name = "x"
`;

describe("compareBindings", () => {
  it("passes when bindings are identical", () => {
    const result = compareBindings(base, base, noExemptions);
    expect(result.ok).toBe(true);
    expect(result.unexemptedProdOnly).toHaveLength(0);
    expect(result.unexemptedStagingOnly).toHaveLength(0);
  });

  it("fails on a production-only binding", () => {
    const prod = `${base}\n[[kv_namespaces]]\nbinding = "EXTRA"\n`;
    const result = compareBindings(prod, base, noExemptions);
    expect(result.ok).toBe(false);
    expect(result.unexemptedProdOnly).toEqual([
      { category: "kv_namespaces", binding: "EXTRA", missingFrom: "staging" },
    ]);
  });

  it("fails on a staging-only binding", () => {
    const staging = `${base}\n[[kv_namespaces]]\nbinding = "EXTRA"\n`;
    const result = compareBindings(base, staging, noExemptions);
    expect(result.ok).toBe(false);
    expect(result.unexemptedStagingOnly).toEqual([
      {
        category: "kv_namespaces",
        binding: "EXTRA",
        missingFrom: "production",
      },
    ]);
  });

  it("passes when a production-only binding is exempted", () => {
    const prod = `${base}\n[[send_email]]\nname = "EMAIL"\n`;
    const exemptions: Exemptions = {
      prodOnly: [{ binding: "EMAIL", reason: "no real mail in staging" }],
      stagingOnly: [],
    };
    const result = compareBindings(prod, base, exemptions);
    expect(result.ok).toBe(true);
    expect(result.unexemptedProdOnly).toHaveLength(0);
  });

  it("fails when an exemption is stale (no longer a real difference)", () => {
    const exemptions: Exemptions = {
      prodOnly: [{ binding: "DB", reason: "stale, DB exists in both now" }],
      stagingOnly: [],
    };
    const result = compareBindings(base, base, exemptions);
    expect(result.ok).toBe(false);
    expect(result.staleExemptions).toEqual([
      { binding: "DB", reason: "stale, DB exists in both now" },
    ]);
  });

  it("ignores comments and blank lines", () => {
    const withComments = `
# a comment

[[d1_databases]] # trailing comment
binding = "DB" # another trailing comment
database_name = "x" # comment on value

# a full-line comment in between
`;
    const result = compareBindings(withComments, withComments, noExemptions);
    expect(result.ok).toBe(true);
    expect(result.bothCategories.get("d1_databases")).toEqual(["DB"]);
  });

  it("compares [vars] keys as their own category", () => {
    const prod = `${base}\n[vars]\nFOO = "1"\nBAR = "2"\n`;
    const staging = `${base}\n[vars]\nFOO = "1"\n`;
    const result = compareBindings(prod, staging, noExemptions);
    expect(result.ok).toBe(false);
    expect(result.unexemptedProdOnly).toEqual([
      { category: "vars", binding: "BAR", missingFrom: "staging" },
    ]);
  });
});

describe("runCheck", () => {
  function fixtureRoot(files: Record<string, string>): string {
    const root = mkdtempSync(join(tmpdir(), "binding-parity-"));
    mkdirSync(join(root, "scripts", "binding-parity"), { recursive: true });
    for (const [name, body] of Object.entries(files)) {
      writeFileSync(join(root, name), body);
    }
    return root;
  }

  const noExemptionsJson = JSON.stringify(noExemptions);

  it("exits 0 and says so when wrangler.staging.toml is absent", () => {
    const root = fixtureRoot({ "wrangler.toml": base });
    const lines: string[] = [];

    expect(runCheck(root, (l) => lines.push(l))).toBe(0);
    expect(lines).toEqual([
      "wrangler.staging.toml not present, nothing to compare",
    ]);
  });

  it("exits 0 when both configs are present and agree", () => {
    const root = fixtureRoot({
      "wrangler.toml": base,
      "wrangler.staging.toml": base,
      "scripts/binding-parity/exemptions.json": noExemptionsJson,
    });

    expect(runCheck(root, () => {})).toBe(0);
  });

  it("exits 1 when a binding is missing from staging", () => {
    const root = fixtureRoot({
      "wrangler.toml": `${base}\n[[kv_namespaces]]\nbinding = "CACHE"\n`,
      "wrangler.staging.toml": base,
      "scripts/binding-parity/exemptions.json": noExemptionsJson,
    });
    const lines: string[] = [];

    expect(runCheck(root, (l) => lines.push(l))).toBe(1);
    expect(lines.join("\n")).toContain("CACHE");
  });
});
