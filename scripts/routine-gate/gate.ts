#!/usr/bin/env -S npx tsx
import { CONFIG } from "./config.js";
import { evaluateGate, parseClosesIssue } from "./gate-core.js";
import { fetchPr, fetchIssue } from "./github.js";

// Usage: npx tsx scripts/routine-gate/gate.ts --repo owner/name --pr 123
function arg(flag: string): string {
  const i = process.argv.indexOf(flag);
  if (i === -1 || i + 1 >= process.argv.length) {
    console.error(`missing ${flag}`);
    process.exit(2);
  }
  return process.argv[i + 1];
}

const repo = arg("--repo");
const prNum = Number(arg("--pr"));

const pr = fetchPr(repo, prNum);
const closes = parseClosesIssue(pr.body);
const issue = closes !== null ? fetchIssue(repo, closes) : null;

const verdict = evaluateGate({ cfg: CONFIG, issue, pr });

// Machine-readable for the Routine to parse.
console.log(JSON.stringify({ repo, pr: prNum, ...verdict }, null, 2));

// Exit code is the contract the Routine keys on: 0 = auto-merge, 2 = escalate.
process.exit(verdict.pass ? 0 : 2);
