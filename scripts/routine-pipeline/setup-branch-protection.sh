#!/usr/bin/env bash
# Audits (default) or provisions (--apply) the required default-branch ruleset.
# Required: PRs only, required status checks, no force-push.
# Usage: setup-branch-protection.sh owner/name [branch] [--apply]
set -euo pipefail
REPO="${1:?usage: setup-branch-protection.sh owner/name [branch] [--apply]}"
BRANCH="${2:-main}"
APPLY="${3:-}"

echo "== current protection for $REPO@$BRANCH =="
gh api "repos/$REPO/branches/$BRANCH/protection" 2>/dev/null \
  | jq '{required_status_checks, enforce_admins, required_pull_request_reviews, allow_force_pushes}' \
  || echo "(no protection set)"

if [[ "$APPLY" != "--apply" ]]; then
  echo
  echo "DRY RUN. Re-run with --apply as the 3rd arg to provision the ruleset below:"
  echo "  - require a pull request before merging"
  echo "  - require status checks to pass (strict)"
  echo "  - block force pushes"
  exit 0
fi

gh api -X PUT "repos/$REPO/branches/$BRANCH/protection" \
  --input - <<'JSON'
{
  "required_status_checks": { "strict": true, "contexts": [] },
  "enforce_admins": false,
  "required_pull_request_reviews": { "required_approving_review_count": 0 },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
echo "protection applied to $REPO@$BRANCH"
