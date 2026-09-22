#!/usr/bin/env -S npx tsx
// Reports the autonomous merge rate over a window, so the number is measured
// rather than counted by hand.
//
//   GH_TOKEN=... npx tsx scripts/factory-metrics/report.ts --days 90
//
// Needs only read access to pull requests.
import { execFileSync } from "node:child_process";
import { computeMergeRate, formatMergeRate, type MergedPr } from "./metrics.js";

function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : (process.argv[i + 1] ?? fallback);
}

const repo = arg("repo", "schmug/dmarc.mx");
const days = Number(arg("days", "90"));
if (!Number.isFinite(days) || days <= 0) {
  console.error(`--days must be a positive number, got ${arg("days", "")}`);
  process.exit(1);
}

const windowStartIso = new Date(
  Date.now() - days * 24 * 60 * 60 * 1000,
).toISOString();

// gh paginates; closed PRs come back newest-updated first, so read enough pages
// to cover the window rather than guessing one page is enough.
const raw = execFileSync(
  "gh",
  [
    "api",
    "--paginate",
    `repos/${repo}/pulls?state=closed&per_page=100&sort=updated&direction=desc`,
    "--jq",
    "[.[] | {number, headRef: .head.ref, mergedAt: .merged_at," +
      " labels: [.labels[].name]}]",
  ],
  { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
);

// --paginate emits one JSON array per page.
const prs: MergedPr[] = raw
  .trim()
  .split("\n")
  .filter((line) => line.length > 0)
  .flatMap((line) => JSON.parse(line) as MergedPr[]);

console.log(formatMergeRate(computeMergeRate(prs, windowStartIso)));
console.log(`\nread ${prs.length} closed PRs from ${repo}`);
