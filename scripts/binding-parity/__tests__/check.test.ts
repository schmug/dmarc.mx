import { describe, it, expect } from "vitest";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { compareBindings, type Exemptions } from "../check-core.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..", "..");

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

describe("check.ts CLI", () => {
  it("exits 0 and prints a clear message when wrangler.staging.toml is absent", () => {
    expect(existsSync(join(repoRoot, "wrangler.staging.toml"))).toBe(false);

    const output = execFileSync(
      "npx",
      ["tsx", join(repoRoot, "scripts", "binding-parity", "check.ts")],
      { cwd: repoRoot, encoding: "utf8" },
    );

    expect(output.trim()).toBe(
      "wrangler.staging.toml not present, nothing to compare",
    );
  });
});
