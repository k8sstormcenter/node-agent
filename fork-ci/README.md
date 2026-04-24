# fork-ci/ — workflow overlays for test-mirror branches

This directory is a plug-in point for **fork-specific CI files that must
appear on `test-mirror/**` branches but not on `upstream-pr/**` branches**.

At the time of introduction it is intentionally empty (beyond this README):
node-agent's existing `.github/workflows/` — `build.yaml` (workflow_dispatch
only) and `component-tests.yaml` (internally dispatched by `build.yaml`) —
already work correctly when dispatched on any ref, so the mirror branch can
use the upstream-pr branch's files as-is.

## When to add files here

If you ever need a workflow file that must behave differently on
test-mirror branches than on upstream-pr branches (e.g. a push trigger with
`test-mirror/**` in its branch list, or a different image registry), drop
it into `fork-ci/.github/workflows/`. The `mirror-sync.yaml` workflow on
`main` will overlay everything under `fork-ci/` onto the mirror branch at
sync time. Do **not** add such files to the upstream-pr branch directly —
they would contaminate the upstream PR diff.

## Why the shape exists even when empty

Matches the `fork-ci/` layout on `k8sstormcenter/storage` so there's a
single mental model across both forks. Anyone looking at the mirror-sync
workflow on either fork sees the same template.
