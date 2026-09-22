/**
 * Supply-chain merge gate. Blocks on HIGH/CRITICAL advisories in RUNTIME
 * dependencies, and keeps an npm advisory-backend outage distinguishable from
 * a real finding (#745).
 *
 * Fails closed in both cases — an outage still reddens `check`, because
 * `npm ci` keeps working during one and a fail-open gate would let an agent
 * dependency bump to a known critical merge unaudited. What changes is that
 * the outage says so in plain words instead of blaming package-lock.json.
 *
 * Run by .github/workflows/ci.yml via `npx tsx scripts/audit-gate/gate.ts`.
 */

import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";
import { classifyAuditResult } from "./classify.js";

/** Attempts before giving up on an unresponsive advisory backend. */
export const MAX_ATTEMPTS = 3;

/** Base backoff in ms; attempt N waits roughly N * this, plus jitter. */
const BACKOFF_BASE_MS = 20_000;

export interface AuditRun {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export type AuditRunner = () => Promise<AuditRun>;
export type Sleeper = (ms: number) => Promise<void>;

export interface GateResult {
  exitCode: number;
  output: string;
}

/**
 * `--omit=dev` keeps the gate on code that actually ships to the Worker; dev
 * tooling advisories (wrangler/vitest/sharp chains, often unpatchable) stay
 * visible via Dependabot without blocking PRs.
 *
 * `--audit-level` is deliberately NOT passed: the threshold lives in
 * classify.ts where it is tested, rather than in npm's exit-code semantics.
 */
export const runNpmAudit: AuditRunner = () =>
  new Promise((resolve, reject) => {
    const child = spawn("npm", ["audit", "--omit=dev", "--json"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) =>
      resolve({ stdout, stderr, exitCode: code ?? 1 }),
    );
  });

const defaultSleep: Sleeper = (ms) =>
  new Promise((resolve) => setTimeout(resolve, ms));

export async function decideGate(
  runAudit: AuditRunner,
  sleep: Sleeper = defaultSleep,
): Promise<GateResult> {
  const lines: string[] = [];
  let lastReason = "unknown";

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    let run: AuditRun;
    try {
      run = await runAudit();
    } catch (err) {
      // A failed spawn is an infrastructure problem, not a clean tree.
      run = {
        stdout: "",
        stderr: err instanceof Error ? err.message : String(err),
        exitCode: 1,
      };
    }

    const verdict = classifyAuditResult(run.stdout, run.stderr, run.exitCode);

    if (verdict.kind === "clean") {
      const { moderate, low, total } = verdict.counts;
      lines.push(
        `Supply-chain audit clean: no critical or high advisories in runtime deps (${total} total at or below moderate: ${moderate} moderate, ${low} low).`,
      );
      return { exitCode: 0, output: lines.join("\n") };
    }

    if (verdict.kind === "vulnerable") {
      const { critical, high } = verdict.counts;
      for (const advisory of verdict.advisories) lines.push(`  ${advisory}`);
      lines.push(
        `::error::Supply-chain audit found HIGH/CRITICAL advisories in runtime dependencies (${critical} critical, ${high} high). Patch or remove the dependency before merging.`,
      );
      return { exitCode: 1, output: lines.join("\n") };
    }

    lastReason = verdict.reason;
    lines.push(`attempt ${attempt}/${MAX_ATTEMPTS}: ${verdict.reason}`);
    if (attempt < MAX_ATTEMPTS) {
      // Jitter so parallel PR jobs do not retry in lockstep against a
      // recovering backend.
      await sleep(attempt * BACKOFF_BASE_MS + Math.floor(Math.random() * 5_000));
    }
  }

  lines.push(
    `::error::npm advisory backend unreachable after ${MAX_ATTEMPTS} attempts — this is a registry outage, NOT a vulnerability finding, and NOT a problem with package-lock.json. Check https://status.npmjs.org and re-run this job. Last reason: ${lastReason}`,
  );
  return { exitCode: 1, output: lines.join("\n") };
}

// Entry point when executed directly (not when imported by the tests).
// Compare resolved file URLs rather than matching on basename — a substring
// check here would either miss in CI or fire during the test run.
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const result = await decideGate(runNpmAudit);
  console.log(result.output);
  process.exit(result.exitCode);
}
