#!/usr/bin/env bash
# Dispatch the fork-ci build-image chain for storage + node-agent, then the
# node-agent Performance Benchmark. Requires: gh (auth with workflow scope).
#
#   dispatch-build.sh <source-branch> [image-tag] [before-image]
#
# <source-branch> is checked out by both build workflows (SOURCE_REF); it may
# contain slashes. The storage commit it resolves to is passed to node-agent as
# STORAGE_REF, which MUST be a SHA — go mod rejects a slash branch name as a
# "disallowed version string".
set -euo pipefail

OWNER=k8sstormcenter
CI_REF=fork-ci
SRC=${1:?usage: dispatch-build.sh <source-branch> [image-tag] [before-image]}
TAG=${2:-$(printf '%s' "$SRC" | tr '/:' '--')}
BEFORE=${3:-}

storage_sha=$(git ls-remote "https://github.com/$OWNER/storage" "$SRC" | cut -f1)
[ -n "$storage_sha" ] || { echo "no such branch on $OWNER/storage: $SRC" >&2; exit 1; }

run_build() { # repo, extra -f args...
  local repo=$1; shift
  gh workflow run build.yaml -R "$OWNER/$repo" --ref "$CI_REF" \
    -f SOURCE_REF="$SRC" -f IMAGE_TAG="$TAG" "$@" >/dev/null
  sleep 4
  gh run list -R "$OWNER/$repo" --workflow=build.yaml --limit 1 \
    --json databaseId --jq '.[0].databaseId'
}

echo "storage build  (SOURCE_REF=$SRC IMAGE_TAG=$TAG)"
sid=$(run_build storage)
gh run watch "$sid" -R "$OWNER/storage" --exit-status >/dev/null \
  || { echo "storage build failed: run $sid" >&2; exit 1; }

echo "node-agent build (STORAGE_REF=$storage_sha)"
nid=$(run_build node-agent -f STORAGE_REF="$storage_sha")
# A successful storage build auto-fires a stray node-agent rebuild on the pushed
# ref (no IMAGE_TAG) — cancel anything that is not our fork-ci dispatch.
for r in $(gh run list -R "$OWNER/node-agent" --workflow=build.yaml --limit 5 \
             --json databaseId,headBranch --jq '.[]|select(.headBranch!="'"$CI_REF"'")|.databaseId'); do
  gh run cancel "$r" -R "$OWNER/node-agent" >/dev/null 2>&1 || true
done
gh run watch "$nid" -R "$OWNER/node-agent" --exit-status >/dev/null \
  || { echo "node-agent build failed: run $nid" >&2; exit 1; }

echo "benchmark (after=$TAG${BEFORE:+ before=$BEFORE})"
gh workflow run benchmark.yaml -R "$OWNER/node-agent" --ref "$CI_REF" \
  -f after_image="ghcr.io/$OWNER/node-agent:$TAG" ${BEFORE:+-f before_image="$BEFORE"} >/dev/null

echo "dispatched. component-tests chain from the node-agent build; benchmark queued."
