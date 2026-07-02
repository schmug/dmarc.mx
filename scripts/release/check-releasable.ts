#!/usr/bin/env -S npx tsx
import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { isReleasable, sanitizeLastTag } from "./releasable.js";

// Both git calls use execFileSync with argv arrays — never a shell command
// string. Tag names can contain shell metacharacters, and this script runs in
// the release workflow with write permissions, so a tag must never be
// interpolated into a shell line. sanitizeLastTag additionally drops any
// non-CalVer tag (treated as "no prior tag") before it reaches git argv.
const lastTag = (() => {
  try {
    return sanitizeLastTag(
      execFileSync("git", ["describe", "--tags", "--abbrev=0"], {
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
      }).trim(),
    );
  } catch {
    return "";
  }
})();

const commits: string[] | null =
  lastTag === ""
    ? null
    : execFileSync("git", ["log", `${lastTag}..HEAD`, "--format=%s"], { encoding: "utf8" })
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
