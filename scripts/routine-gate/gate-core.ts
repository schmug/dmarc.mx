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
