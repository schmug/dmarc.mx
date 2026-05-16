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
