#!/usr/bin/env bash
# Baseline half of the signing benchmark.
#
# Binding a workload to a user-defined profile makes node-agent stop profiling
# that container (see containerprofilemanager lifecycle: a container with a
# user-defined profile is dropped from learning). That saving is far larger than
# anything signature verification costs, so a run where only the AFTER phase is
# bound measures the absence of profiling, not the presence of verification.
#
# This binds the workload to an UNSIGNED flat profile with the same content the
# signed bundle assembles to. Learning is then suppressed in both phases and the
# only difference left is the signature verification the after phase performs on
# every reconcile tick.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKLOAD_NS="${WORKLOAD_NS:-load-simulator}"

log() { echo "==> [baseline] $*"; }

log "Binding the workload to an unsigned flat profile..."
kubectl get ns "$WORKLOAD_NS" >/dev/null
kubectl delete -f "$SCRIPT_DIR/signing/flat-profile.yaml" --ignore-not-found >/dev/null
kubectl create -f "$SCRIPT_DIR/signing/flat-profile.yaml" >/dev/null
kubectl -n "$WORKLOAD_NS" patch daemonset load-simulator --type merge \
    -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":"load-simulator"}}}}}'
kubectl -n "$WORKLOAD_NS" rollout status daemonset load-simulator --timeout=300s
log "Bound: profiling suppressed in this phase too."
