import { execFileSync } from "node:child_process";
import type { CheckOutcome, CheckState, IssueInfo, PrInfo } from "./gate-core.js";

function gh(args: string[]): string {
  return execFileSync("gh", args, { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 });
}

export function fetchPr(repo: string, pr: number): PrInfo {
  const j = JSON.parse(
    gh(["pr", "view", String(pr), "--repo", repo, "--json",
      "body,additions,deletions,files,statusCheckRollup"]),
  );
  const changedFiles: string[] = (j.files ?? []).map((f: any) => f.path);
  const rollup: any[] = j.statusCheckRollup ?? [];
  return {
    number: pr,
    body: j.body ?? "",
    changedFiles,
    additions: j.additions ?? 0,
    deletions: j.deletions ?? 0,
    checks: rollup.map(toCheckState),
  };
}

// A check-run reports status + conclusion; a commit status reports state only.
// An unfinished check-run has a conclusion of null, which is pending, not failed.
export function toCheckState(c: any): CheckState {
  const name: string = c.name ?? c.context ?? "(unnamed check)";
  const raw = String(c.conclusion ?? c.state ?? "").toUpperCase();
  const outcome: CheckOutcome =
    raw === "SUCCESS" || raw === "NEUTRAL"
      ? "success"
      : raw === "SKIPPED"
        ? "skipped"
        : raw === "" || raw === "PENDING" || raw === "EXPECTED" || raw === "QUEUED" ||
            raw === "IN_PROGRESS" || raw === "WAITING" || raw === "REQUESTED"
          ? "pending"
          : "failed";
  return { name, outcome };
}

// filePointers come from a fenced block in the issue body the /issue skill emits:
//   ```scope
//   src/analyzers/**
//   src/shared/scoring.ts
//   ```
export function fetchIssue(repo: string, num: number): IssueInfo | null {
  let j: any;
  try {
    j = JSON.parse(
      gh(["issue", "view", String(num), "--repo", repo, "--json",
        "number,author,labels,body"]),
    );
  } catch {
    return null; // fail-closed: unreadable issue
  }
  const body: string = j.body ?? "";
  const m = body.match(/```scope\s*([\s\S]*?)```/i);
  const filePointers = m
    ? m[1].split("\n").map((s) => s.trim()).filter(Boolean)
    : [];
  return {
    number: j.number,
    author: j.author?.login ?? "",
    labels: (j.labels ?? []).map((l: any) => l.name),
    filePointers,
  };
}
