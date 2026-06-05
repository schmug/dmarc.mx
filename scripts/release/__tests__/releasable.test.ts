import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { isReleasable, SKIP_PATTERN_SOURCES } from "../releasable.js";

describe("isReleasable", () => {
  it("returns true when there is no prior tag (first release)", () => {
    expect(isReleasable(null)).toBe(true);
  });

  it("returns false when there are no new commits since the last tag", () => {
    expect(isReleasable([])).toBe(false);
  });

  it("returns false when all commits are chore: prefixed", () => {
    expect(isReleasable(["chore: update readme", "chore: cleanup"])).toBe(false);
  });

  it("returns false for chore(deps): (still starts with 'chore')", () => {
    expect(isReleasable(["chore(deps): bump vitest from 3.0.0 to 4.0.0"])).toBe(false);
  });

  it("returns false for chore(deps-dev): (still starts with 'chore')", () => {
    expect(isReleasable(["chore(deps-dev): bump typescript"])).toBe(false);
  });

  it("returns false when all commits are Bump-style (capital B)", () => {
    expect(isReleasable(["Bump lodash from 1.0 to 2.0"])).toBe(false);
  });

  it("returns false when all commits are bump-style (lowercase b)", () => {
    expect(isReleasable(["bump lodash from 1.0 to 2.0"])).toBe(false);
  });

  it("returns false for Merge pull request commits", () => {
    expect(isReleasable(["Merge pull request #42 from owner/feature"])).toBe(false);
  });

  it("returns false for Merge branch commits", () => {
    expect(isReleasable(["Merge branch 'feature/x' into main"])).toBe(false);
  });

  it("returns true when at least one commit is not a skip pattern (mixed set)", () => {
    expect(
      isReleasable([
        "chore(deps): bump eslint",
        "Bump lodash from 1.0 to 2.0",
        "feat: add DNSBL analyzer",
      ]),
    ).toBe(true);
  });

  it("returns true when the only commit is a real feature commit", () => {
    expect(isReleasable(["feat: add SPF strict mode"])).toBe(true);
  });

  it("'bumpversion' (no trailing space) is not a skip pattern", () => {
    expect(isReleasable(["bumpversion"])).toBe(true);
  });
});

describe("cliff.toml sync", () => {
  it("SKIP_PATTERN_SOURCES matches all cliff.toml commit_parsers with skip = true", () => {
    const toml = readFileSync(resolve(process.cwd(), "cliff.toml"), "utf8");
    const cliffSkip = new Set<string>();
    for (const line of toml.split("\n")) {
      // Match lines like: { message = "^chore", skip = true },
      const m = line.match(/\{ message = "([^"]+)"[^}]*skip = true/);
      if (m) cliffSkip.add(m[1]);
    }
    const ourPatterns = new Set<string>(SKIP_PATTERN_SOURCES);
    expect(ourPatterns).toEqual(cliffSkip);
  });
});
