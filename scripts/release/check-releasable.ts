#!/usr/bin/env -S npx tsx
import { execSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { isReleasable } from "./releasable.js";

const lastTag = (() => {
  try {
    return execSync("git describe --tags --abbrev=0", {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  } catch {
    return "";
  }
})();

const commits: string[] | null =
  lastTag === ""
    ? null
    : execSync(`git log "${lastTag}..HEAD" --format=%s`, { encoding: "utf8" })
        .split("\n")
        .filter((s) => s.trim() !== "");

const shouldSkip = !isReleasable(commits);

const outputFile = process.env.GITHUB_OUTPUT ?? "";
if (outputFile) {
  appendFileSync(outputFile, `skip=${shouldSkip}\n`);
}

if (shouldSkip && commits !== null) {
  console.log(`Skipping release — all commits since ${lastTag} are deps/chore only:`);
  for (const c of commits) {
    console.log(`  ${c}`);
  }
} else {
  console.log(
    lastTag
      ? `Releasing — found releasable commits since ${lastTag}`
      : "First release — no prior tag",
  );
}
