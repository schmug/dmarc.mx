#!/usr/bin/env -S npx tsx
import { evaluateFreshness } from "./freshness.js";

const mainCommitIso = process.env.MAIN_COMMIT_ISO ?? "";
const activeDeployIso = process.env.ACTIVE_DEPLOY_ISO ?? "";
const graceSeconds = Number(process.env.GRACE_SECONDS ?? "900");

if (!mainCommitIso || !activeDeployIso) {
  console.error(
    "MAIN_COMMIT_ISO and ACTIVE_DEPLOY_ISO are both required; refusing to" +
      " report freshness from missing data.",
  );
  process.exit(1);
}

const result = evaluateFreshness({
  mainCommitIso,
  activeDeployIso,
  graceSeconds,
});

console.log(result.summary);
console.log(`main tip:          ${mainCommitIso}`);
console.log(`active deployment: ${activeDeployIso}`);
process.exit(result.stale ? 1 : 0);
