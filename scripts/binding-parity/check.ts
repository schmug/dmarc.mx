#!/usr/bin/env -S npx tsx
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { compareBindings, type Exemptions } from "./check-core.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");

function main(): number {
  const prodPath = join(repoRoot, "wrangler.toml");
  const stagingPath = join(repoRoot, "wrangler.staging.toml");

  if (!existsSync(stagingPath)) {
    console.log("wrangler.staging.toml not present, nothing to compare");
    return 0;
  }

  const prodText = readFileSync(prodPath, "utf8");
  const stagingText = readFileSync(stagingPath, "utf8");

  const exemptionsPath = join(__dirname, "exemptions.json");
  const exemptions: Exemptions = JSON.parse(
    readFileSync(exemptionsPath, "utf8"),
  );

  const result = compareBindings(prodText, stagingText, exemptions);
  for (const line of result.lines) console.log(line);

  return result.ok ? 0 : 1;
}

process.exit(main());
