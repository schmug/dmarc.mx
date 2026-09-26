export const CONFIG = {
  // Condition 1 (primary, unforgeable): only these issue authors can ever reach auto-merge.
  allowlistAuthors: ["schmug"],

  // Condition 1, second tier: authors trusted only for issues already carrying
  // the spec-approved label. The operating agent self-specs issues, so its own
  // issue text is not a human-vetted spec on its own — but the label can only be
  // applied by someone with write access, so a labelled issue has had a human
  // mint the approval, which is the property Condition 1 actually protects.
  // Owner decision, 2026-09-21.
  allowlistAuthorsWithApproval: ["andonos[bot]"],

  labels: {
    specApproved: "spec-approved", // minted ONLY by the interactive mobile session
    autoImpl: "auto-impl",         // applied by Routine #1 to PRs it opens
    needsYou: "needs-you",         // applied by Routine #2 on escalation
    implBlocked: "impl-blocked",   // applied by Routine #1 when tests fail
  },

  // Condition 5: higher-throughput envelope (spec: N=6, <=250 lines, <=8 files).
  size: { maxChangedLines: 250, maxChangedFiles: 8 },
  implementerBatch: 6,

  // Per-repo integration branch (spec: donthype-me is dev->main).
  baseBranchByRepo: {
    "dmarcheck": "main",
    "donthype-me": "dev",
    "benchburner": "main",
    "apartment-stager": "main",
  } as Record<string, string>,

  // Condition 4: any match -> escalate, never auto-merge. Globs are minimatch with { dot: true }.
  // Aligned to the narrowed CODEOWNERS policy. Owner decision, 2026-09-22.
  riskPathDenylist: [
    "src/auth/**", "src/account/**",
    "src/billing/**", "src/webhooks/**",
    "src/db/migrations/**", "src/db/schema.sql",
    "wrangler.toml",
    ".github/workflows/migrate.yml",
    ".github/workflows/deploy-mta-sts.yml",
    ".github/workflows/deploy-staging.yml",
    ".github/workflows/release.yml",
    ".github/workflows/rollback.yml",
    ".github/workflows/pr-provenance.yml",
    ".github/workflows/factory.yml",
    ".github/CODEOWNERS",
    "package.json", "package-lock.json",
    "scripts/routine-gate/**",
    "mta-sts-worker/**",
    "SECURITY.md",
  ],
};
