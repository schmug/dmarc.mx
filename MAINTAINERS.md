# Maintainers

This file lists the people responsible for dmarcheck and the policy for how
that responsibility is granted and removed. It satisfies the project-governance
expectations of the OSPS Baseline (GV-01, GV-04).

## Current maintainers

| Handle | Role | Scope | Contact |
|--------|------|-------|---------|
| [@schmug](https://github.com/schmug) | Maintainer | Full: write access, releases, secrets, security disclosures | via [GitHub profile](https://github.com/schmug) / [SECURITY.md](SECURITY.md) |

dmarcheck is currently maintained by a single person in their spare time.

## Roles

- **Maintainer** — write access to the repository, authority to merge and
  release, holds deployment/billing secrets, and is the named code owner in
  [`.github/CODEOWNERS`](.github/CODEOWNERS). Maintainers are the approvers for
  security-sensitive PRs.
- **Triager** *(none today; defined for future growth)* — triage access:
  label, assign, and close issues/PRs, but no merge or release authority.

## Automation identity

Autonomous [Claude Code Routines](docs/routine-pipeline.md) open and merge
routine PRs. Ruleset `main-protection` (id `14716629`) sets
`require_code_owner_review: true`, `required_approving_review_count: 0`, and has
no bypass actors. The zero general approval count is the autonomy carve-out:
paths not listed in [`.github/CODEOWNERS`](.github/CODEOWNERS) can merge with no
review. On owned paths, GitHub enforces code-owner review for identities that
are not code owners; merges by the agent `andonos[bot]` were refused with 405.
The gate is inert only for **@schmug's own merges**. The owned paths are exactly
the entries in CODEOWNERS, narrowed on 2026-09-22. See
[docs/OSPS-DEVIATIONS.md](docs/OSPS-DEVIATIONS.md) for related controls.

## Becoming a maintainer

There is no formal nomination process yet given the project's size. A
contributor with a sustained track record of quality PRs and issue triage may
be invited by an existing maintainer to take a Triager or Maintainer role.
Maintainership requires the ability to be reached for security disclosures.

## Removing a maintainer

A maintainer may step down at any time by opening a PR removing themselves from
this file. A maintainer may be removed by consensus of the remaining
maintainers for inactivity (no activity for ~6 months) or for conduct that
undermines the project. When a maintainer is removed, their write access,
secret access, and CODEOWNERS entries are revoked in the same change.

## Security and review policy

- Vulnerability reports follow [SECURITY.md](SECURITY.md) (private disclosure).
- The human-review gate for security-sensitive paths is defined in
  [`.github/CODEOWNERS`](.github/CODEOWNERS) and enforced by the
  `main-protection` ruleset.
- The contribution workflow is in [CONTRIBUTING.md](CONTRIBUTING.md).
