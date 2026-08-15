#!/usr/bin/env bash
# Turn the signature feature ON for a benchmark run and prove it is actually
# doing work.
#
# The benchmark's point is to measure what signature verification costs, so
# both phases run the SAME node-agent image and only the configuration differs:
# the before phase leaves the feature dormant, this script switches it on for
# the after phase.
#
# What gets signed here:
#   - the trust policy      (pre-signed with the root key, committed)
#   - the baseline ruleset  (signed at run time as a base-class fragment)
#   - the workload profile  (signed at run time as base + overlay fragments)
#
# Signing the ruleset is not optional: with rule signing on, an unsigned Rules
# object is dropped whole, which would leave node-agent with no rules, doing
# less work than the before phase and reporting signature verification as free.
# assert_signing_active guards against exactly that and fails the run.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIGNING_DIR="$SCRIPT_DIR/signing"
KUBESCAPE_NS="${KUBESCAPE_NS:-kubescape}"
WORKLOAD_NS="${WORKLOAD_NS:-load-simulator}"
SIGN_OBJECT_VERSION="${SIGN_OBJECT_VERSION:-sign-object-v0.1.5}"
SIGN_OBJECT="${SIGN_OBJECT:-/tmp/sign-object}"

log() { echo "==> [signing] $*"; }

fetch_sign_object() {
    [[ -x "$SIGN_OBJECT" ]] && return 0
    log "Fetching $SIGN_OBJECT_VERSION..."
    curl -fsSL -o "$SIGN_OBJECT" \
        "https://github.com/k8sstormcenter/node-agent/releases/download/${SIGN_OBJECT_VERSION}/sign-object-linux-amd64"
    chmod +x "$SIGN_OBJECT"
}

mount_trust_policy() {
    log "Applying the root-signed trust policy..."
    kubectl -n "$KUBESCAPE_NS" create configmap node-agent-bundle-policy \
        --from-file=trust-policy.json="$SIGNING_DIR/trust-policy.signed.json" \
        --dry-run=client -o yaml | kubectl apply -f -

    kubectl -n "$KUBESCAPE_NS" get configmap node-agent -o json | python3 -c '
import json, sys
cm = json.load(sys.stdin)
cfg = json.loads(cm["data"]["config.json"])
cfg["bundleTrustPolicyPath"] = "/etc/bundle/trust-policy.json"
cm["data"]["config.json"] = json.dumps(cfg, indent=4)
json.dump(cm, sys.stdout)
' | kubectl apply -f -

    kubectl -n "$KUBESCAPE_NS" patch daemonset node-agent --type strategic -p '{
      "spec": {"template": {"spec": {
        "volumes": [{"name": "bundle-policy", "configMap": {"name": "node-agent-bundle-policy"}}],
        "containers": [{
          "name": "node-agent",
          "volumeMounts": [{"name": "bundle-policy", "mountPath": "/etc/bundle/trust-policy.json", "subPath": "trust-policy.json", "readOnly": true}]
        }]
      }}}
    }'
}

sign_baseline_ruleset() {
    # The upstream chart ships no Rules object, so the benchmark supplies its own
    # baseline and signs it as a base-class fragment. Without rules the agent
    # evaluates nothing and the comparison is meaningless.
    log "Signing the baseline ruleset as a base-class fragment..."
    "$SIGN_OBJECT" sign --file "$SIGNING_DIR/rules/baseline-rules.yaml" \
        --output /tmp/baseline-rules-signed.yaml --key "$SIGNING_DIR/operator.pem" --type rules >/dev/null
    kubectl -n "$KUBESCAPE_NS" delete rules.kubescape.io benchmark-baseline-rules >/dev/null 2>&1 || true
    kubectl create -f /tmp/baseline-rules-signed.yaml >/dev/null
    log "Baseline ruleset ingested, signed."
}

sign_workload_bundle() {
    log "Signing a profile bundle for the workload..."
    kubectl get ns "$WORKLOAD_NS" >/dev/null
    # Drop the unsigned flat profile the baseline phase used; the bundle replaces
    # it under the same name so the binding is unchanged.
    kubectl delete -f "$SCRIPT_DIR/signing/flat-profile.yaml" --ignore-not-found >/dev/null
    for f in "$SIGNING_DIR"/fragments/*.yaml; do
        [[ -e "$f" ]] || continue
        local key="$SIGNING_DIR/vendor.pem"
        grep -q 'fragment-class: overlay' "$f" && key="$SIGNING_DIR/operator.pem"
        "$SIGN_OBJECT" sign --file "$f" --output "${f%.yaml}-signed.yaml" --key "$key" --type containerprofile >/dev/null
        kubectl delete -f "${f%.yaml}-signed.yaml" --ignore-not-found >/dev/null
        kubectl create -f "${f%.yaml}-signed.yaml" >/dev/null
    done
    # Bind the workload to the bundle so every reconcile tick re-verifies it.
    kubectl -n "$WORKLOAD_NS" patch daemonset load-simulator --type merge \
        -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":"load-simulator"}}}}}'
    kubectl -n "$WORKLOAD_NS" rollout status daemonset load-simulator --timeout=300s
}

# Fail the run rather than report a misleading number.
assert_signing_active() {
    log "Verifying the feature is actually active..."
    local logs enabled admitted rejected
    logs=$(for p in $(kubectl -n "$KUBESCAPE_NS" get pods -l app.kubernetes.io/component=node-agent -o name); do
        kubectl -n "$KUBESCAPE_NS" logs "$p" -c node-agent --tail=-1 2>/dev/null
    done)

    if [[ "$logs" != *"signed bundle overlays enabled"* ]]; then
        echo "FATAL: bundle signing did not enable — the trust policy was rejected." >&2
        echo "$logs" | grep -i "trust policy" | tail -3 >&2
        exit 1
    fi
    if [[ "$logs" != *"signed rule fragments enabled"* ]]; then
        echo "FATAL: rule signing did not enable." >&2
        exit 1
    fi

    rejected=$(echo "$logs" | grep -o '"rejected":[0-9]*' | tail -1 | cut -d: -f2)
    admitted=$(echo "$logs" | grep -o '"admitted":[0-9]*' | tail -1 | cut -d: -f2)
    if [[ "${rejected:-0}" != "0" || "${admitted:-0}" == "0" ]]; then
        echo "FATAL: rules fragments admitted=${admitted:-?} rejected=${rejected:-?}." >&2
        echo "A dropped ruleset would make node-agent do LESS work and report signing as free." >&2
        echo "$logs" | grep -i "rules fragment rejected" | tail -3 >&2
        exit 1
    fi

    if [[ "$logs" != *"assembled signed bundle overlay"* ]]; then
        echo "FATAL: no bundle was assembled, so per-tick fragment verification is NOT being measured." >&2
        echo "$logs" | grep -i "bundle overlay failed" | tail -3 >&2
        exit 1
    fi

    log "Active: bundle assembled, rule fragments admitted=$admitted rejected=$rejected."
}

main() {
    fetch_sign_object
    mount_trust_policy
    sign_baseline_ruleset
    kubectl -n "$KUBESCAPE_NS" rollout restart daemonset node-agent
    kubectl -n "$KUBESCAPE_NS" rollout status daemonset node-agent --timeout=600s
    sign_workload_bundle
    sleep 30
    assert_signing_active
}

main "$@"
