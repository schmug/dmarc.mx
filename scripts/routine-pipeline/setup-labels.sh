#!/usr/bin/env bash
# Creates the 4 pipeline labels on a repo (idempotent).
# Usage: scripts/routine-pipeline/setup-labels.sh owner/name
set -euo pipefail
REPO="${1:?usage: setup-labels.sh owner/name}"

create() { # name color description
  gh label create "$1" --repo "$REPO" --color "$2" --description "$3" --force
}
create "spec-approved"   "0E8A16" "Issue spec'd by owner in interactive session; trust token for auto-merge"
create "auto-impl"       "1D76DB" "PR opened by the implementer Routine"
create "needs-you"       "D93F0B" "Escalated by the reviewer Routine; needs owner decision"
create "impl-blocked"    "B60205" "Implementer Routine could not produce a green PR"
create "pipeline-paused" "E4E669" "Kill switch: both Routines no-op while this label is on any open issue"
echo "labels ensured on $REPO"
