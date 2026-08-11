# Signature component tests — CI matrix

`.github/workflows/component-tests.yaml` lives on the `fork-ci` branch, not on
this one. Its `component-tests.strategy.matrix.test` list currently carries three
signature entries:

```
Test_29_SignedContainerProfile,
Test_31_TamperDetectionAlert,
Test_37_SignedBundleOverlay,
```

Add these three, so every signature test function in `tests/component_test.go`
has a matrix entry:

```
Test_38_SignedRulesNamespaceOverride,
Test_39_SignedRulesUntrustedSignerRejected,
Test_40_TrustPolicyFailClosed,
```

## What each new entry covers

| Test | Covers |
|---|---|
| `Test_38_SignedRulesNamespaceOverride` | A signed `overlay`-class Rules fragment overrides the `base`-class rule of the same ID where it is installed, does not leak elsewhere, and the same artifact bytes install into more than one place. |
| `Test_39_SignedRulesUntrustedSignerRejected` | A Rules fragment signed by a key no trust policy names is rejected whole (log + reason), and the rule it tried to redefine keeps the trusted baseline behaviour. |
| `Test_40_TrustPolicyFailClosed` | A trust policy signed by a NON-root key is refused, bundles stay disabled and no bundle is assembled even though every fragment is valid; restoring the shipped policy assembles and enforces the same fragments (positive control). |

## Runtime notes for whoever edits the matrix

- Each entry gets its own kind cluster, as today. All three mutate cluster state
  (they swap the `node-agent-bundle-policy` ConfigMap and restart the
  daemonset) and restore it afterwards, but they are only isolated from each
  other because the matrix gives each one a fresh cluster.
- Each restarts the node-agent daemonset two or three times and waits for
  ContainerProfile completion, so they are slower than the alert tests. They fit
  the existing `--timeout=20m`, but do not shorten it for these entries.
- They read the pre-signed fixtures in `tests/resources/signed` (see its
  README). Nothing is signed at test time and no signing key is deployed.
