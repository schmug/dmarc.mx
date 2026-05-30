# Contributing to dmarcheck

Thanks for your interest in dmarcheck — a DNS email-security analyzer (DMARC,
SPF, DKIM, BIMI, MTA-STS) running as a Cloudflare Worker, live at
[dmarc.mx](https://dmarc.mx). This guide covers how to report problems and how
to land a change.

## Reporting bugs and requesting features

- **Security vulnerabilities — do not open a public issue.** Follow the private
  disclosure process in [SECURITY.md](SECURITY.md) instead.
- **Bugs and feature requests** go in the
  [GitHub issue tracker](https://github.com/schmug/dmarcheck/issues). Search
  open issues first to avoid duplicates.

A good bug report includes: what you ran (the domain or API call), what you
expected, what actually happened, and — for scan results — whether you can
reproduce it against [dmarc.mx](https://dmarc.mx) or only a self-hosted build.

## Development setup

Requires Node.js 22 (the version CI runs on; v18+ works locally).

```bash
git clone https://github.com/schmug/dmarcheck.git
cd dmarcheck
npm ci            # clean install from the lockfile (use `npm install` only when changing deps)
npm run dev       # local dev server on http://localhost:8790
```

## The four commands you'll use

| Command | What it does |
|---------|--------------|
| `npm test` | Vitest unit tests (`test/`) |
| `npm run lint` | Biome lint + format check (`npm run lint:fix` to auto-fix) |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run dev` | Local Worker on port 8790 |

See [AGENTS.md](AGENTS.md) for the full command list and architecture notes.

> **Do not run `npm run deploy`.** Deployment is automatic via Cloudflare's Git
> integration on push to `main`; a manual deploy collides with it and causes
> stale deploys.

## Submitting a change

1. **Branch off `main`** — never push to `main` directly (it's protected).
2. **Write tests for non-trivial changes.** New analyzer behavior, scoring
   boundaries, and parsing logic all need test coverage; CI runs `npm test` on
   every PR and a change that needs tests but ships without them will be asked
   to add them. Pure-docs changes don't.
3. **Run the gate locally before pushing:**
   ```bash
   npm run lint && npm run typecheck && npm test
   ```
4. **Use a [conventional commit](https://www.conventionalcommits.org/) prefix.**
   The changelog is generated from commit history by git-cliff, so the prefix
   matters. Allowed prefixes: `feat:`, `fix:`, `refactor:`, `test:`, `chore:`,
   `docs:`, `security:`, `seo:`.
5. **Open a pull request against `main`.** CI must pass: lint, typecheck, tests,
   and a `npm audit --audit-level=high --omit=dev` supply-chain gate.

## Review and merge

Most PRs merge once CI is green. PRs that touch security-sensitive paths
(CI workflows, lockfiles, input validation, redirect posture, rate limiting,
DB migrations, analyzer modules, orchestration, or scoring) require an
approving review from a code owner — see
[`.github/CODEOWNERS`](.github/CODEOWNERS) and
[MAINTAINERS.md](MAINTAINERS.md). The autonomous-routine auto-merge path and its
compensating controls are documented in
[docs/OSPS-DEVIATIONS.md](docs/OSPS-DEVIATIONS.md).

## Code of conduct

Be respectful and constructive. A formal `CODE_OF_CONDUCT.md` may be added
later; until then, the maintainer moderates participation at their discretion.

## Sign your commits (DCO)

Every commit must carry a `Signed-off-by:` trailer asserting that you have
legal authorization to contribute the code (Developer Certificate of Origin,
[OSPS LE-01.01](https://baseline.openssf.org/versions/2025-02-25#le-0101)).

```bash
git commit -s -m "feat: your message here"
```

`-s` appends the trailer automatically using your `user.name` and `user.email`
from git config:

```
Signed-off-by: Your Name <you@example.com>
```

If you forget the flag on an existing commit:

```bash
git commit --amend -s   # for the most recent commit
# or
git rebase --signoff HEAD~N   # for the last N commits, then force-push
```

**Squash-merge note:** GitHub copies the PR description into the squash commit
message. Make sure your PR description includes the `Signed-off-by:` line so
the merged commit is also signed off.
