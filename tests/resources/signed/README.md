# Pre-signed component-test fixtures

Signed AHEAD OF TIME and committed, so the signature tests verify FIXED bytes
instead of re-signing at run time. Signing keys are in `keys/` and are published
and worthless — read `keys/README.md` before doing anything with them.

Everything is signed with `--embed-content` (the default): the canonical signed
content travels in `signature.kubescape.io/content`, so a fixture keeps
verifying after the apiserver/storage normalises its spec.

`metadata.namespace` is deliberately NOT part of the signed content — a vendor
cannot know which namespace a customer installs into. What the signature binds
is the object NAME, the LABELS (bundle membership + fragment class) and the
SPEC. So the tests choose the install namespace at ingest time (`kubectl -n …`,
or setting `.Namespace` before Create) and can use random namespaces.

## Trust policies

| File | Signed by | Contents | Used by |
|---|---|---|---|
| `trust-policy.json` | — (plain source) | `classes` + `ruleClasses` | source of `trust-policy.signed.json` |
| `trust-policy.signed.json` | root | `classes` + `ruleClasses` | swapped in by the signed-rules tests |
| `trust-policy.profiles-only.json` | — (plain source) | `classes` only | source of the file below |
| `trust-policy.profiles-only.signed.json` | root | `classes` only | shipped verbatim by `tests/chart` — rule signing stays OFF so the UNSIGNED `Rules` objects other component tests apply (`r0002-files-access-enabled.yaml`, `exec-tty-rules.yaml`, the chart's own `kubescape-rules`) keep being accepted |
| `trust-policy.badsigner.signed.json` | `keys/ct-nonroot.pem` | `classes` + `ruleClasses` | fail-closed test: correctly formed, correctly signed, WRONG signer — bundles must stay disabled |

The root key is not in `keys/`: it is the published demo root key whose public
half is compiled into node-agent (`pkg/signature/bundle/root.go`), fingerprint
`key:d0cc7f2e82d99699d7a5f7078a9f30ec4847d13b6e41e91e224e0a47b32b9f9e`.

## ContainerProfile fragments — bundle `bundle37`

| File | Class | Signed by | Contributes |
|---|---|---|---|
| `fragments/bundle37-base-signed.yaml` | base | `ct-vendor.pem` | `/bin/sleep`, `/usr/bin/curl`, syscalls, label selector |
| `fragments/bundle37-admission-signed.yaml` | admission | `ct-operator.pem` | one ingress neighbour |
| `fragments/bundle37-overlay-signed.yaml` | overlay | `ct-operator.pem` | `/usr/bin/id` — in NO other fragment (the union proof) |

## Rules fragments

| File | Object | Class | Bundle | Signed by | Contents |
|---|---|---|---|---|---|
| `rules/cluster-baseline-signed.yaml` | `ct-base-rules` | base | — | `ct-vendor.pem` | the chart's full 29-rule baseline; R0001 severity 1 |
| `rules/namespace-override-signed.yaml` | `ct-bundle37-overlay-rules` | overlay | `bundle37` | `ct-operator.pem` | R0001 only, severity 9, distinct message |
| `rules/untrusted-signer-signed.yaml` | `ct-rogue-rules` | base | — | `ct-untrusted.pem` | R0001 severity 7 — must be REJECTED (signer named by no policy) |

An `overlay`-class rules fragment MUST carry `signature.kubescape.io/bundle`;
that label is inside the signed content, so an installer cannot re-target it.

## Regenerating

```
sign-object generate-keypair --output keys/<name>.pem
sign-object sign-policy --policy trust-policy.json --key <root>.pem --output trust-policy.signed.json
sign-object sign --file fragments/<f>.yaml --output fragments/<f>-signed.yaml --key keys/<k>.pem --type containerprofile
sign-object sign --file rules/<r>.yaml     --output rules/<r>-signed.yaml     --key keys/<k>.pem --type rules
```

Editing a `*.yaml` source means re-signing it. Replacing a `*.pem` means
re-deriving every fingerprint in `trust-policy.json` (and its profiles-only
twin) and re-signing everything that key signed.
