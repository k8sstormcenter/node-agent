# Fork Workflow: k8sstormcenter/node-agent

## Branch structure

```
upstream/main:  A --- B --- C --- D          (kubescape/node-agent)
                                   \
fork main:                          D --- [feat-X] --- [fork-only: .github/*]
                                           \
feature branch:                             feat/my-feature (1-2 clean commits)
```

**Rules:**
- Fork `main` always has a **fork-only `.github/` commit as the tip** — this is never sent upstream.
- Feature branches start from `main~1` (before the fork-only commit).
- Each feature is a small, focused branch with clean commits.

## Day-to-day workflow

### 1. Sync fork with upstream

```bash
git fetch upstream
git checkout main

# Rebase your features onto latest upstream (fork-only commit stays on top)
git rebase upstream/main

# Force-push (safe — your main is the source of truth)
git push origin main --force-with-lease
```

### 2. Start a new feature

```bash
# Always branch from main~1 (before fork-only commit)
git checkout -b feat/my-feature main~1

# Develop...
# Commit (sign your commits)
# Test locally with local-ci.sh or CI
```

### 3. Test on your fork

```bash
# Push feature branch to your fork
git push origin feat/my-feature

# Merge into fork main (keeps fork-only commit on top):
git checkout main
git rebase --onto feat/my-feature main~2 main
# This replays [feat/my-feature commits] + [fork-only commit] onto the feature
git push origin main --force-with-lease
```

Or simpler: just push the feature branch and trigger CI via workflow_dispatch.

### 4. Create upstream PR

```bash
# Use the script — it cherry-picks your feature onto upstream/main,
# stripping any .github/ changes automatically
./scripts/upstream-pr.sh feat/my-feature

# Verify it's clean
git diff --stat upstream/main upstream/my-feature -- .github/   # should be empty

# Push to upstream and open PR
git push upstream upstream/my-feature
```

Then open the PR at `https://github.com/kubescape/node-agent/compare/main...upstream/my-feature`

### 5. After upstream merges your PR

```bash
# Sync
git fetch upstream
git checkout main
git rebase upstream/main
git push origin main --force-with-lease

# Clean up
git branch -d feat/my-feature
git branch -d upstream/my-feature
git push origin --delete feat/my-feature
```

## What NOT to do

- **Don't develop on `main` directly** — always use feature branches.
- **Don't squash-merge upstream into your fork** — this is what caused the old mess (regressions baked into squash commits). Use `rebase` instead.
- **Don't mix `.github/` changes with feature commits** — keep them in the fork-only tip commit only.
- **Don't push the node-agent image as `latest` from feature branches** — use dedicated tags (`build.yaml` is already configured for this).

## Key files

| File | Purpose |
|---|---|
| `scripts/upstream-pr.sh` | Creates upstream-clean branches for PRs |
| `tests/scripts/local-ci.sh` | Runs component tests locally in Kind |
| `.github/workflows/component-tests.yaml` | Fork CI (triggers on `main`) |
| `.github/workflows/build.yaml` | Builds node-agent image (no `latest` tag) |
