import { minimatch } from "minimatch";
import type { CONFIG as CONFIG_T } from "./config";

export interface IssueInfo {
  number: number;
  author: string;
  labels: string[];
  filePointers: string[]; // glob-ish paths the issue declared as in-scope
}

export interface PrInfo {
  number: number;
  body: string;
  changedFiles: string[];
  additions: number;
  deletions: number;
  ciAllGreen: boolean;
}

type Cfg = typeof CONFIG_T;

export function parseClosesIssue(body: string): number | null {
  const m = body.match(/\bcloses\s+#(\d+)\b/i);
  return m ? Number(m[1]) : null;
}

export function isProvenanceTrusted(issue: IssueInfo | null, cfg: Cfg): boolean {
  if (!issue) return false; // fail-closed
  return (
    cfg.allowlistAuthors.includes(issue.author) &&
    issue.labels.includes(cfg.labels.specApproved)
  );
}

export function touchesRiskPath(files: string[], denylist: string[]): string[] {
  return files.filter((f) => denylist.some((p) => minimatch(f, p, { dot: true })));
}

export function withinSizeEnvelope(pr: PrInfo, cfg: Cfg): boolean {
  return (
    pr.additions + pr.deletions <= cfg.size.maxChangedLines &&
    pr.changedFiles.length <= cfg.size.maxChangedFiles
  );
}

// Returns changed files NOT covered by the issue's declared pointers.
// Empty pointers => every file is drift (fail-closed: no declared scope = not safe).
export function scopeDrift(changedFiles: string[], pointers: string[]): string[] {
  if (pointers.length === 0) return [...changedFiles];
  return changedFiles.filter((f) => !pointers.some((p) => minimatch(f, p, { dot: true })));
}

export interface GateInput {
  cfg: Cfg;
  issue: IssueInfo | null;
  pr: PrInfo;
}

export interface GateVerdict {
  pass: boolean;
  reasons: string[]; // empty iff pass === true
}

export function evaluateGate(input: GateInput): GateVerdict {
  const { cfg, issue, pr } = input;
  const reasons: string[] = [];

  // Condition 3: linkage
  const closes = parseClosesIssue(pr.body);
  if (closes === null) reasons.push("PR body has no `Closes #n` link");

  // Conditions 1 + 2: provenance + intent token
  if (!issue) {
    reasons.push("linked issue not found / unreadable (fail-closed)");
  } else {
    if (closes !== null && closes !== issue.number) {
      reasons.push(`PR closes #${closes} but evaluated issue is #${issue.number}`);
    }
    if (!cfg.allowlistAuthors.includes(issue.author)) {
      reasons.push(`issue author @${issue.author} not on allowlist`);
    }
    if (!issue.labels.includes(cfg.labels.specApproved)) {
      reasons.push(`issue #${issue.number} missing "${cfg.labels.specApproved}" label`);
    }
  }

  // Condition 4: risk-path denylist
  const risky = touchesRiskPath(pr.changedFiles, cfg.riskPathDenylist);
  if (risky.length) reasons.push(`touches risk-path(s): ${risky.join(", ")}`);

  // Condition 5: size envelope
  if (!withinSizeEnvelope(pr, cfg)) {
    reasons.push(
      `exceeds size envelope (${pr.additions + pr.deletions} lines / ${pr.changedFiles.length} files; ` +
        `max ${cfg.size.maxChangedLines}/${cfg.size.maxChangedFiles})`,
    );
  }

  // Condition 6a: scope-fit
  const drift = issue ? scopeDrift(pr.changedFiles, issue.filePointers) : [...pr.changedFiles];
  if (drift.length) reasons.push(`scope drift outside declared pointers: ${drift.join(", ")}`);

  // Condition 6b: CI
  if (!pr.ciAllGreen) reasons.push("CI not green");

  return { pass: reasons.length === 0, reasons };
}
