// Record a DNS fixture for one domain (#655):
//
//   npm run record -- example.com [selector1,selector2]
//
// Runs one real scan with live DNS, capturing every query and answer, and writes
// test/fixtures/dns/<domain>.json. Replaying that fixture reproduces the same
// grade offline, which is what lets an agent confirm a reported bug before
// changing anything and prove the fix afterwards.

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { DnsFixture } from "../src/dns/replay.js";
import { setRecorder } from "../src/dns/replay.js";
import { scan } from "../src/orchestrator.js";
import { fixturePath, saveFixture } from "./fixtures.js";

// The capture hook in src/dns/client.ts reports every query the scan actually
// made, including names derived at runtime (SPF includes, DKIM selectors), so
// the fixture covers exactly what a replay will ask for.
const answers: DnsFixture["answers"] = {};

async function main(): Promise<void> {
  const [domain, selectorArg] = process.argv.slice(2);
  if (!domain) {
    console.error("usage: npm run record -- <domain> [selector1,selector2]");
    process.exit(1);
  }
  const selectors = selectorArg ? selectorArg.split(",").filter(Boolean) : [];

  setRecorder((key, answer) => {
    answers[key] = answer;
  });
  // A failing scan is still worth recording: the captured error answers are how
  // a resolver-failure bug gets reproduced.
  try {
    await scan(domain, selectors, {});
  } catch (err) {
    console.warn(`scan threw (recording anyway): ${err}`);
  }

  const path = fixturePath(domain);
  mkdirSync(dirname(path), { recursive: true });
  saveFixture(path, {
    domain: domain.toLowerCase(),
    recordedAt: new Date().toISOString(),
    answers,
  });
  console.log(`wrote ${path} (${Object.keys(answers).length} answers)`);
}

main();
