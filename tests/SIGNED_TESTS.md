# Signature tests — scenario coverage & CI matrix

This maps every signed-artifact scenario to the exact test function that covers
it, and lists the component-test (CT) entries the `fork-ci` matrix must carry.

Two layers cover the design:

- **Component tests** (`tests/component_test.go`, build tag `component`) run the
  real node-agent against a kind cluster with the PRE-SIGNED fixtures under
  `tests/resources/signed`. Nothing is signed at run time.
- **Unit differential/oracle tests** (`pkg/signature/...`) compare the
  production code against an independent reference or invariant over many
  generated inputs. They cover the decision logic that cannot be induced
  in-cluster from a *good* fixture (a confinement/scope violation lives inside
  the signed content, so it cannot be produced by mutating a valid fixture — it
  would need a purpose-built *bad* signed fixture).

## CI matrix (`.github/workflows/component-tests.yaml`, `fork-ci` branch)

`component-tests.strategy.matrix.test` must list every signature CT:

```
Test_29_SignedContainerProfile,
Test_31_TamperDetectionAlert,
Test_37_SignedBundleOverlay,
Test_38_SignedRulesBundleOverlay,
Test_39_SignedRulesUntrustedSignerRejected,
Test_40_TrustPolicyFailClosed,
Test_41_SignedBundleNamespaceFreedom,
Test_42_SignatureStrippedFragmentRejected,
```

New entries to add to the matrix (continuing from the previous three that were
already flagged): **`Test_41_SignedBundleNamespaceFreedom`**,
**`Test_42_SignatureStrippedFragmentRejected`**.

## Scenario → test

| # | Scenario | Kind | Test function | Key assertion |
|---|---|---|---|---|
| 1 | Flat signed CP survives the storage round-trip, is loaded and enforced | CT | `Test_29_SignedContainerProfile` | an unlisted exec on a clean signed CP fires R0001 |
| 2 | Flat signed CP tampered in storage | CT | `Test_31_TamperDetectionAlert` | recomputed hash ≠ signature → R1016 |
| 3 | Signed CP bundle: multi-party fragments assemble (union), tamper, recover | CT | `Test_37_SignedBundleOverlay` | overlay-only exec quiet, no-fragment exec fires R0001; corrupt embedded → R1016; recover → enforced again |
| 4 | Signed rules overlay overrides the base rule of the same ID for bundle members | CT | `Test_38_SignedRulesBundleOverlay` | opted-in workload gets overlay severity/marker |
| 5 | **Bundle-override non-leak in-cluster** (two workloads, SAME namespace) | CT | `Test_38_SignedRulesBundleOverlay` | non-bundle workload keeps the base R0001; overlay marker never appears on it — same ns, so it cannot be namespace scoping |
| 6 | Untrusted-signer rules fragment rejected | CT | `Test_39_SignedRulesUntrustedSignerRejected` | rejection logged with reason; the rule keeps trusted-baseline behaviour |
| 7 | Trust policy signed by a NON-root key fails closed | CT | `Test_40_TrustPolicyFailClosed` | bundles stay disabled, nothing assembled; restoring the shipped policy assembles + enforces the same fragments (positive control) |
| 8 | **Namespace freedom** — same signed CP bundle bytes install into a RANDOM namespace and assemble + enforce | CT | `Test_41_SignedBundleNamespaceFreedom` | fixtures carry no namespace; composite assembles + enforces in a namespace the vendor never named |
| 9 | **Signature-stripped / re-created-unsigned fragment rejected** (delete-then-apply-unsigned vector) | CT | `Test_42_SignatureStrippedFragmentRejected` | stripping a fragment's signature fails the whole bundle closed with an unsigned-fragment error; NOT a tamper — R1016 does not fire |
| 10 | **Class confinement in-cluster** — a signed fragment setting a spec path its class forbids fails the whole bundle closed | UNIT | `TestAdmitDifferential_ContainerProfileMatrix` (`ErrPathNotAllowed`), `TestAssembleAndVerify_ClassConfinement`, `TestSeccompConfinement_EmptyDefaultAction` | see below |
| 11 | **Rules overlay with no bundle label rejected** | UNIT | `TestAdmitDifferential_RulesMatrix` (`ErrRuleBundleRequired`), `TestAdmitRulesFragment_OverlayWithoutBundle` | see below |
| 12 | **Rules fragment carrying a rule ID outside its class's `allowedRuleIDs` rejected** | UNIT | `TestAdmitDifferential_RulesMatrix` (`ErrRuleIDNotAllowed`), `TestAdmitRulesFragment_RuleIDNotAllowed` | see below |

### Why 10–12 are unit tests, not CTs

Class membership, bundle membership and the rule-ID set all live INSIDE the
signed content (`metadata.labels` / `spec`). A valid fixture therefore cannot be
turned into a confinement/scope violation by editing the stored object — the
embedded signed bytes stay authoritative, so the violation would need a
purpose-built *bad* signed fixture (an admission fragment that signs `execs`, an
overlay rules fragment signed with no bundle label, a rules fragment signed with
a disallowed ID). Authoring those requires the published signing keys and the
`sign-object` tool at fixture-build time, and the fail-closed DECISION they would
exercise is already pinned exhaustively by the admissibility oracle (every cell
of a signed×bundle×class×signer×path / signed×class×signer×ruleID×bundle matrix,
checked against an independent precedence model). Scenario 9 (`Test_42`) is the
one confinement-adjacent vector that CAN be induced from a good fixture —
stripping the signature makes the fragment `unsigned`, which is observable
in-cluster — so it is a CT.

## Differential / metamorphic oracle tests (unit)

| Oracle | Test function(s) | Independent reference / invariant |
|---|---|---|
| Independent verifier | `pkg/signature`: `TestDifferential_IndependentVerifierAgreesOnAccept` | stdlib PEM→`x509.ParseCertificate`→`ecdsa.VerifyASN1` over `sha256(contentHash)`, vs `VerifyObjectAllowUntrusted`; must agree on every freshly signed CP + Rules object, embed and non-embed |
| Mutation | `pkg/signature`: `TestDifferential_MutationOracle` | every mutation class (sig/cert byte flip, cert swap, truncation, dropped annotation, spec/label edit, embedded-content edit) must be rejected by BOTH the stdlib reference and production with the expected sentinel |
| Merkle root | `pkg/signature/bundle`: `TestMerkleDifferential_RefRootEqualsProduction`, `_LeafDigestChangeChangesRoot`, `_AddOrRemoveLeafChangesRoot`, `_AssemblyOrderIndependent` | independent domain-separated `crypto/sha256` reimplementation of the leaf/node scheme; plus order-independence, leaf-change and add/remove-leaf metamorphic properties |
| Admissibility decision | `pkg/signature/bundle`: `TestAdmitDifferential_ContainerProfileMatrix`, `TestAdmitDifferential_RulesMatrix` | independent precedence model of `admitFragment` / `AdmitRulesFragment` over the full property matrix |
| Policy round-trip | `pkg/signature/bundle`: `TestSignedPolicy_RandomRoundTripOracle`, `TestSignedPolicy_SingleByteMutationOracle` | `SignTrustPolicy`→`verifyAndPinPolicy` deep-equals the input over random policies; no single-byte mutation of the artifact yields a DIFFERENT accepted policy |

## Runtime notes for whoever edits the matrix

- Each entry gets its own kind cluster. `Test_41`/`Test_42` mutate cluster state
  (they ingest fixtures into a random namespace; `Test_42` also swaps a stored
  fragment) and use random namespaces, exactly like `Test_37`.
- `Test_42` waits out a settling period to assert the ABSENCE of R1016, so it is
  in the slower band with `Test_38`–`Test_40`. Both fit the existing
  `--timeout=20m`.
- They read the pre-signed fixtures in `tests/resources/signed` (see its
  README). Nothing is signed at test time and no signing key is deployed.
