#!/bin/bash
# upstream-pr.sh — Create an upstream-clean branch for PRing to kubescape/node-agent
#
# Your fork's main looks like:
#
#   upstream/main --- [feat-A] --- [feat-B] --- [fork-only: .github/*]
#                                                 ^^ always the tip
#
# This script takes a feature branch (based on main~1), cherry-picks its
# commits onto upstream/main, and strips any .github/ changes so the
# result is clean for an upstream PR.
#
# Usage:
#   ./scripts/upstream-pr.sh <feature-branch> [upstream-branch-name]
#
# Examples:
#   ./scripts/upstream-pr.sh feat/signature-verification
#   ./scripts/upstream-pr.sh feat/signature-verification upstream-sig-verify
#
set -euo pipefail

FEATURE="${1:?Usage: $0 <feature-branch> [upstream-branch-name]}"
# Default upstream branch name: strip "feat/" prefix, prepend "upstream/"
DEFAULT_NAME="upstream/${FEATURE#feat/}"
UPSTREAM_BRANCH="${2:-$DEFAULT_NAME}"

echo "=== upstream-pr ==="
echo "  Feature branch : $FEATURE"
echo "  Upstream branch: $UPSTREAM_BRANCH"
echo ""

# Ensure we have the latest upstream
git fetch upstream

# Fail if the branch already exists
if git rev-parse --verify "$UPSTREAM_BRANCH" &>/dev/null; then
    echo "ERROR: Branch '$UPSTREAM_BRANCH' already exists."
    echo "  Delete it first:  git branch -D $UPSTREAM_BRANCH"
    exit 1
fi

# Find commits on the feature branch that are above origin/main
COMMITS=$(git rev-list --reverse origin/main.."$FEATURE")
if [ -z "$COMMITS" ]; then
    echo "ERROR: No commits found on '$FEATURE' above origin/main."
    exit 1
fi

# Create branch from upstream/main
git checkout -b "$UPSTREAM_BRANCH" upstream/main

APPLIED=0
SKIPPED=0
for commit in $COMMITS; do
    SUBJECT=$(git log --oneline -1 "$commit")

    # Skip commits that ONLY touch .github/
    NON_GITHUB=$(git diff-tree --no-commit-id --name-only -r "$commit" | grep -v '^\.github/' || true)
    if [ -z "$NON_GITHUB" ]; then
        echo "  SKIP (github-only): $SUBJECT"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    echo "  APPLY: $SUBJECT"
    git cherry-pick "$commit" --no-commit

    # Remove any .github changes that came along for the ride
    if git diff --cached --name-only | grep -q '^\.github/'; then
        git reset HEAD -- .github/ &>/dev/null || true
        git checkout -- .github/ &>/dev/null || true
    fi

    # Re-commit with the original message and author
    git commit -C "$commit"
    APPLIED=$((APPLIED + 1))
done

echo ""
echo "=== Done ==="
echo "  Applied: $APPLIED commits"
echo "  Skipped: $SKIPPED commits (.github-only)"
echo ""
echo "Verify:"
echo "  git log --oneline $UPSTREAM_BRANCH --not upstream/main"
echo "  git diff --stat upstream/main $UPSTREAM_BRANCH -- .github/   # should be empty"
echo ""
echo "Push to upstream:"
echo "  git push upstream $UPSTREAM_BRANCH"
echo ""
echo "Then open PR at: https://github.com/kubescape/node-agent/compare/main...$UPSTREAM_BRANCH"
