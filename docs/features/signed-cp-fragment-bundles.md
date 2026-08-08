# Signed ContainerProfile Fragment Bundles — Implementation Plan

Status: IMPLEMENTED on `signature-overlays` (node-agent; storage unchanged). Validated by
component tests: Test_29 (flat signed CP), Test_31 (tamper→R1016), Test_37 (multi-fragment
bundle: assembly/union, tamper→R1016 via reconciler re-assembly, recovery after re-sign) —
CT run 31244214794, 31/31 green. Two integration findings folded back into the code: storage
List is spec-stripped (fragments must be fetched via Get) and fragment signing must use the
storage-normalised form (sign-after-roundtrip, §5.2).

## 1. Goal

Let a single effective ContainerProfile (CP) be composed from **multiple, independently
signed fragments** authored by **different parties**, and have node-agent (a) verify each
fragment's own signature against the party allowed to author it, (b) deterministically
assemble the fragments into one CP, (c) bind the assembly to the exact set of admissible
leaves via a leaf-tree (Merkle) proof, and (d) re-sign the composite internally so the
existing tamper path protects it.

Concrete target (bob redis distros example):

- **Vendor** ships and signs the default server profile `cp-redis` (execs/opens/caps, **no
  ingress**).
- **A second party** (another vendor, or the platform operator) signs a *client-admission
  fragment* — the `spec.ingress` entry that admits `{app: redis-client}` on TCP-6379 (today
  applied by the `kubectl patch` in `bob/example/redis/distros/DEMO.md` §5).
- **The end-user** may add and sign a further overlay fragment.
- All three signatures are individually valid over their own fragment. node-agent assembles
  one `redis` CP from the bundle, proves it derives only from those admissible fragments,
  and signs the result with the cluster key.

## 2. Premise correction (read first — it changes the plan)

The request assumed "the code-base already has the basic signature/tamper functionality."
That is true **for the fork**, but **NOT for `mirrormain`**, which is the base of both
`signature-overlays` branches. `mirrormain` = `upstream/main + migrate/sbob`, and it contains
**no** signing, verification, R1016, `SetTamperAlertExporter`, `pkg/signature/`, or
`cmd/sign-object/`. Confirmed by full-tree search on both repos.

The signature/tamper base lives on other fork branches. The most recent and closest to
`mirrormain` is **`fix/sign-object-release-v0.0.3`** (2026-07-07; only 7 commits ahead of the
merge base; the substance is one commit `ccaebfbc "profile-compaction: CollapseConfig CRD +
projection overlay + user-managed lifecycle + signing/tamper detection"`). It carries:

- `pkg/signature/` — `interface.go` (`Signer`/`Verifier`/`SignableObject`/`Signature`),
  `cosign_adapter.go`, `sign.go`, `verify.go` (`VerifyObjectAllowUntrusted`), `signer.go`,
  `verifier.go`, `annotations.go`, and `profiles/` adapters for **ApplicationProfile /
  NetworkNeighborhood / rules / seccomp** (NOT ContainerProfile).
- `cmd/sign-object/` — the cosign signing CLI (built by `.github/workflows/sign-object.yaml`,
  image `k8sstormcenter/sign-object`).
- `pkg/objectcache/containerprofilecache/tamper_alert.go` — `SetTamperAlertExporter`,
  `verifyUserApplicationProfile` / `verifyUserNetworkNeighborhood` →
  `signature.VerifyObjectAllowUntrusted(adapter)` → `emitTamperAlert` (R1016 "Signed profile
  tampered"), de-duplicated to one alert per invalid transition.

Two consequences:

1. **The existing signing adapters are for the legacy ug-AP / ug-NN overlay pair, not for a
   ContainerProfile.** `feat/port-user-overlays-to-cp` began porting overlays to a single CP;
   verify that a CP adapter exists there before reusing.
2. `mirrormain`'s overlay model is a **single user-authored CP** that *replaces* the learned
   CP (`containerprofilecache.go:445` `if userDefinedCP != nil { cp = userDefinedCP }`), whereas
   the signature base still verifies ug-AP/ug-NN adapters. These must be reconciled.

### Phase 0 — reimplement for ContainerProfile only (DECIDED)

**Decision: do not merge/rebase/cherry-pick the old branch. Reimplement for CP only, reusing the
existing well-tested code, its tests, and the R1016 rule as the reference base.** AP/NN
deprecation simplifies the surface materially, so a fresh CP-only implementation is cleaner than
dragging the AP/NN machinery across a merge.

What is **copied ~verbatim** (generic, profile-agnostic, already well tested — no reason to
rewrite): `pkg/signature/` core — `interface.go`, `cosign_adapter.go`, `sign.go`, `verify.go`
(`VerifyObjectAllowUntrusted`), `signer.go`, `verifier.go`, `annotations.go` — plus their tests
(`sign_test.go`, `verify_test.go`, `cosign_adapter_test.go`), and `cmd/sign-object/`. The R1016
rule + its alert shape are kept as-is.

What **collapses / is reimplemented** thanks to AP/NN → CP:

- The `pkg/signature/profiles/` adapter set shrinks from **four** adapters
  (`applicationprofile_adapter.go`, `networkneighborhood_adapter.go`, `rules_adapter.go`,
  `seccompprofile_adapter.go`) to essentially **one** `containerprofile_adapter.go` (rules/seccomp
  fold into the CP spec). One `SignableObject` over the unified CP content, not an AP+NN pair.
- `tamper_alert.go` collapses `verifyUserApplicationProfile` **and**
  `verifyUserNetworkNeighborhood` into a single `verifyUserContainerProfile` — one fetch, one
  verify, one R1016 site, one dedup key (vs the previous two parallel paths, one per legacy
  object). The `cmd/main.go` `SetTamperAlertExporter` wiring is reused unchanged.
- The overlay adoption model is already single-CP on `mirrormain`
  (`containerprofilecache.go:445`), so no ug-AP+ug-NN merge to reconcile — the tamper check binds
  to the one user CP directly.

Reuse the *tests* by porting fixtures from AP/NN pairs to a single CP object (the assertions —
signed→accepted, tampered→R1016, unsigned→operational-no-alert — carry over unchanged). This
Phase-0 CP-only signing/tamper base is the foundation §5+ builds the fragment/bundle layer on.

## 3. What exists today (grounded map)

### 3.1 Signature primitives (`pkg/signature/`, base branch)

- `Signer.Sign(data []byte) (*Signature, error)`, `Verifier.Verify(data []byte, sig *Signature)
  error` (`interface.go`). Cosign-backed; keyless (`WithKeyless`) or key-based
  (`WithPrivateKey(*ecdsa.PrivateKey)`). Verify has `WithUntrusted(bool)` — trust model is
  **self-signed / allow-untrusted**, not a public CA.
- `SignableObject{ GetContent() interface{}; GetUpdatedObject() interface{} }` — the adapter
  decides **what bytes are signed**. Per `bob/pkg/doc/sbob-rc3/components/signatures.md`, the
  signed content is `metadata{name,namespace,labels}` + `spec`, and **excludes annotations**
  (because storage mutates annotations: managed-by, completion, size, sync-checksum).
- Signature is stored **as annotations** (`annotations.go`): `signature.kubescape.io/signature`,
  `/certificate`, `/rekor-bundle`, `/issuer`, `/identity`, `/timestamp`.
- Load-time re-verification + tamper: `tamper_alert.go`
  `VerifyObjectAllowUntrusted(adapter)` on every cache load → R1016 on first
  present-but-invalid transition; annotation/operational errors do **not** raise R1016.

### 3.2 Storage integrity + merge (`kubescape/storage`, `mirrormain`)

- **No signature/checksum/tamper struct fields** on `ContainerProfile`
  (`pkg/apis/softwarecomposition/types.go:335-410`). Integrity lives in annotations.
- **Canonical content hash**: `StorageImpl.CalculateChecksum` (`storage.go:1247-1273`) converts
  to v1beta1, `RemoveManagedFields`, `json.Marshal`, `utils.CanonicalHash` (order-independent
  SHA-256); stamped as `kubescape.io/sync-checksum` in `saveObject` (`storage.go:244-269`) on
  every write. **ManagedFields are zeroed** before hashing/persisting.
- **PreSave deflates the spec**: `ContainerProfileProcessor.PreSave`
  (`containerprofile_processor.go:122-223`) → `DeflateContainerProfileSpec`
  (`:889`) dedups/sorts/collapses (Execs order-preserving dedup; Caps/Syscalls/Arch dedup+sort;
  Opens/Endpoints dynamic-path collapse). **This mutates the stored bytes** relative to what an
  author submitted — critical constraint for signing (§5.2).
- **Three merge layers** (assembly analogs):
  - *TS merge* `mergeContainerProfileTS` (`:929-961`): append-everything, then deflate.
  - *ug- overlay merge* `buildMergedProfile` (`containerprofile_user_managed.go:79`): a **pure
    function of (observed, ug-AP, ug-NN)** — deterministic, engineered to keep sync-checksum
    stable across re-merges. This is the reconciliation model to copy.
  - *GNP union* (`networkpolicy/v2/networkpolicy.go:23`): workload-label grouping + ingress/egress
    union, hash-dedup, port coalescing.
  - **`ComputeAggregatedData` (`containerprofile_aggregator.go:26`)**: SHA-256 over child CPs'
    `sync-checksum` values **in sorted order** — a "checksum-of-checksums". **This is already a
    depth-1 Merkle root** and is the natural seed for the leaf-tree (§5.6).
- v1beta1 carries strategic-merge-patch keys: `Execs`/`Opens` mergeKey `path`, `Endpoints`
  mergeKey `endpoint`, `PolicyByRuleId` mergeKey `ruleId` (`v1beta1/types.go:293-318`).
- **Opaque-blob precedent**: `HTTPEndpoint.Headers json.RawMessage` is modeled in OpenAPI as
  `Type: string, Format: byte` (`zz_generated.openapi.go:2439-2444`) so the apiserver never
  prunes/type-checks it. A signed-bundle blob field would use the same trick.
- CPs keyed under **singular** `containerprofile`; merged CP under `containerprofile-merged`
  (`MergedKeyFor`); REST reads merged-first (`containerprofile_rest_storage.go:75`).

### 3.3 node-agent CP lifecycle (`mirrormain`)

- Load: `containerprofilecache.go` `tryPopulateEntry` (`:288`, storage GET at `:308`; overlay
  GETs `:347`/`:358`), terminal-status gate (`:404`), **`buildEntry` (`:536-579`)** — the single
  assembly/projection chokepoint (`userMerged := cp` `:556`; `Apply(spec, userMerged, tree)`
  `:567`). Overlay adoption: `:445` `if userDefinedCP != nil { cp = userDefinedCP }`.
- Refresh: `reconciler.go` `refreshOneEntry` (`:280-388`), RV fast-skip (`:382`).
- **Write/emit**: `containerprofilemanager/v1/monitoring.go` `saveContainerProfile`
  (`:138-231`) builds the CP and enqueues; sink `CreateContainerProfileDirect`
  (`pkg/storage/v1/containerprofile.go:16-26`). This is the candidate **internal re-sign** point.
- `sync-checksum` is read-only today (`projection_apply.go:36-38`), attached to alerts as
  provenance (`rule_manager.go:313,457`), never compared.
- No signature config/flags. Overlay driven by pod label
  `kubescape.io/user-defined-profile` (`containerprofilecache.go:329`).

### 3.4 bob test fixtures (`bob/example/redis/distros/`)

- `sbobs/cp-redis.yaml` — vendor default, `kind: ContainerProfile`, name `redis`, ns `redis`,
  `managed-by: User`, **no `ingress`**.
- `sbobs/cp-redis-client.yaml` — the client's **own** profile (separate workload; egress to
  redis-master + DNS). Not an overlay of `redis`.
- `DEMO.md` §5 patch (the later allowlist → our signable ingress fragment):
  ```
  kubectl -n redis patch $CP redis --type merge -p '{"spec":{"ingress":[{"type":"internal",
    "podSelector":{"matchLabels":{"app":"redis-client"}},
    "namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"redis"}},
    "ports":[{"name":"TCP-6379","port":6379,"protocol":"TCP"}]}]}}'
  ```
- No cosign signing of these YAMLs exists yet; `bobctl sign` (`bob/pkg/cmd/sign.go`) is HMAC and
  aspirational-cosign. They are exactly the raw fixtures this feature wraps.

## 4. The gap

Existing signing = **one** signature over **one** whole profile, verified as a unit, tamper →
R1016. It cannot: carry N independently-signed fragments; verify each leaf against a *different*
authorized signer; assemble fragments into one CP; prove the composite derives only from
admissible leaves and nothing else; or re-sign the composite. Every one of those is new.

## 5. Design

### 5.1 Model

- **Fragment** — a partial `ContainerProfile` (valid CP object; `spec` carries only the subset
  its author owns, e.g. the default's execs/opens, or just `spec.ingress`). Signed by its author.
- **Fragment class** — declares what the fragment is allowed to contribute and who may sign it.
  Proposed classes: `base` (full learned/vendor profile), `admission` (ingress/egress allowlist
  entries), `overlay` (end-user additions). Stored in a label, e.g.
  `signature.kubescape.io/fragment-class`.
- **Signer identity** — the cosign identity/issuer (from the `signature.kubescape.io/identity`
  and `/issuer` annotations), or a key id for key-based signing.
- **Trust policy** — cluster config (ConfigMap) mapping `class → {allowed signer identities}`
  plus which `spec` paths each class may set. E.g. `base → {vendor-key}`,
  `admission → {vendor-key, operator-key}`, `overlay → {end-user-key}`. This is the
  **admissibility** rule set.
- **Bundle** — the ordered set of fragments contributing to one effective CP, discovered for a
  workload (see §5.3). The composite (effective) CP is what the projection/rules see.

### 5.2 Fragment format & canonical signing (resolve the deflate hazard)

The signed bytes MUST equal the bytes that survive storage, or every leaf signature breaks on
round-trip. Storage **strips ManagedFields** and **deflates the spec** on `PreSave`. Therefore:

- Define the fragment's signed content as the **storage-canonical form**: v1beta1 object,
  ManagedFields removed, spec **already deflated** (dedup/sort/collapse identical to
  `DeflateContainerProfileSpec`), serialized via the same path `CalculateChecksum` uses, and the
  signed digest = `utils.CanonicalHash(bytes)` over `metadata{name,namespace,labels}+spec`.
- `cmd/sign-object` (and `bobctl sign`) must run the same normalization before signing, so an
  author signs the canonical form. This makes the fragment signature invariant under storage's
  save mutation. **Do not** additionally deflate a fragment after signing.
- Signature + provenance ride in the fragment's `signature.kubescape.io/*` annotations
  (unchanged from the base), which are **excluded** from the signed content (so re-annotation by
  storage never invalidates them).

### 5.3 Bundle discovery & transport

Reuse the existing label mechanism, extended from one overlay to a set:

- A workload references its bundle via labels/annotation, e.g.
  `kubescape.io/user-defined-profile: redis` selects **all** CPs carrying
  `signature.kubescape.io/bundle: redis` (each an independent, signed fragment CP). node-agent
  lists the fragment set for the workload (extend `tryPopulateEntry`'s overlay fetch at
  `containerprofilecache.go:347/358` from single-GET to a label LIST).
- Each fragment is a normal `ContainerProfile` object in the cluster → storage stores them
  as-is (fragments are NOT time-series; managed-by=User). No new CRD required for v1.
- The **composite** is materialized as a `containerprofile-merged` object (existing merged-key
  machinery) so REST/read stays merged-first.

Alternative (heavier, deferred): a dedicated `ContainerProfileBundle` CRD embedding fragments
verbatim. Rejected for v1 — the per-fragment-CP approach reuses storage keying, RV-refresh, and
the merged-first read path with no new type.

### 5.4 Admissibility

On load, for each fragment `F_i`:

1. It must be signed (`signature.kubescape.io/signature` present) — unsigned fragments are
   dropped under enforcement, or alert-only under detection (mirror the base's two switches:
   `enableSignatureVerification` vs always-on R1016 detection).
2. `VerifyObjectAllowUntrusted(cpAdapter(F_i))` must pass over the canonical content (§5.2).
3. The fragment's signer identity must be in `trustPolicy[class(F_i)].signers`.
4. Every `spec` path `F_i` sets must be permitted for `class(F_i)` (e.g. an `admission` fragment
   may set only `spec.ingress`/`spec.egress`; a `base` may set process/file/network; an `overlay`
   only additive paths). Reject/alert on out-of-class writes — this is what stops a client-class
   signer from smuggling execs into the server profile.

A fragment failing (1)–(4) is excluded from assembly and, if signed-but-tampered, raises R1016
via the existing dedup path.

### 5.5 Deterministic assembly

Port storage's `buildMergedProfile` discipline into node-agent (or keep it in storage and have
node-agent consume — see §5.8). Requirements:

- **Canonical fragment order**: sort by (class precedence `base < admission < overlay`, then
  signer identity, then fragment content digest). Deterministic order ⇒ deterministic composite
  ⇒ stable composite digest/signature across refreshes.
- **Merge semantics per field**: reuse the append-then-deflate model. Execs/Opens/Caps/Syscalls/
  Endpoints unioned then deflated; Ingress/Egress merged by `Identifier` (as
  `mergeUserNetworkNeighbors` `containerprofile_user_managed.go:387`); `PolicyByRuleId` via
  `mergePolicies`; LabelSelector override-merge. Later (higher-precedence) fragments win on
  scalar conflict, with the class/path guard from §5.4 preventing illegal overrides.
- The result is one `ContainerProfileSpec` = the effective profile.

### 5.6 Leaf-tree (Merkle) binding + verification

This is the "construct a leaf-tree signature verification" requirement.

- **Leaves**: `leaf_i = CanonicalHash(signed-content of F_i)` — i.e. the exact digest each
  author signed. (Not the signature bytes; the content digest, so the tree binds *what* was
  admitted.) Include the signer identity in the leaf pre-image:
  `leaf_i = H(class_i ‖ signer_i ‖ contentDigest_i)`.
- **Root**: Merkle root over the leaves in **canonical fragment order** (§5.5). Note storage's
  `ComputeAggregatedData` (`containerprofile_aggregator.go:94`) already computes a sorted
  hash-of-hashes — generalize it from a flat concat to a binary Merkle tree so we get inclusion
  proofs; keep the sorted-order determinism it already guarantees.
- **The composite commits to the tree**: the merged CP carries, in an opaque byte field / blob
  annotation (Headers-style, §3.2), a `bundle-manifest`:
  `{ root, [ {class, signer, contentDigest, sigRef} per leaf ] }`. This lets any verifier
  independently (a) re-verify each leaf signature, (b) recompute each leaf, (c) recompute the
  root, (d) confirm the composite's committed root matches — proving the composite is the
  assembly of exactly those admissible fragments, with none added or dropped.
- **Verification on refresh**: on every reconcile tick (`reconciler.go:280`), if the fragment
  set's resource-versions are unchanged, skip (existing RV fast-skip). If changed, re-run
  §5.4–§5.6. A fragment whose signature no longer verifies → excluded + R1016.

### 5.7 Internal re-sign + tamper integration

- After assembly, node-agent computes the composite's canonical content (§5.2) and **signs it
  with the cluster/node key** (a key provisioned to node-agent — new config, §6), writing the
  composite's `signature.kubescape.io/*` annotations plus the `bundle-manifest` blob. Natural
  site: the merged-CP write, adjacent to `saveContainerProfile`
  (`monitoring.go:138-231`) / `CreateContainerProfileDirect`.
- The composite is now a normally-signed CP from the cluster's trust root. The **existing** load
  path re-verifies it and the **existing** R1016 tamper alert protects it unchanged — no new
  tamper rule needed; we extend detection to the CP adapter (Phase 0 port) and to bundle-manifest
  mismatch (root recomputation failure → tamper).
- Two independent switches carried over from the base: `enableSignatureVerification`
  (enforcement: drop inadmissible/tampered) vs R1016 detection (always-on alerting).

### 5.8 Component placement

- **`cmd/sign-object` / `bobctl`**: author-side. Normalize (§5.2) + cosign-sign a fragment;
  optionally emit a bundle manifest for a set. No cluster needed.
- **node-agent**: the authority. Discover fragments (§5.3), admissibility (§5.4), assembly
  (§5.5), leaf-tree (§5.6), internal re-sign (§5.7), tamper (R1016). This matches the explicit
  requirement that *node-agent* assembles and signs the final thing.
- **storage**: stores fragment CPs + the merged CP; must **not** deflate/mutate in a way that
  breaks leaf sigs (guaranteed by §5.2 canonical-signing). Optionally, generalize
  `ComputeAggregatedData` → Merkle to share the tree code. No verification in storage (keeps the
  trust decision in the node's runtime).

## 6. Data-model & API changes

- **Annotations (reuse)**: `signature.kubescape.io/{signature,certificate,rekor-bundle,issuer,
  identity,timestamp}` on every fragment and on the composite.
- **New labels**: `signature.kubescape.io/bundle` (bundle id), `signature.kubescape.io/fragment-class`
  (`base|admission|overlay`).
- **New opaque field for the bundle manifest** on the composite CP: prefer a `spec` field
  `BundleManifest json.RawMessage` modeled `Type: string, Format: byte` (Headers-style,
  `zz_generated.openapi.go` pattern) so the apiserver won't prune it and it survives round-trip.
  If a spec field is too invasive for v1, carry it in an annotation (excluded from signed
  content, so it must itself be integrity-covered by the composite signature — prefer the spec
  field).
- **Trust policy ConfigMap**: `class → {signer identities}` + `class → {allowed spec paths}`.
- **node-agent config** (`pkg/config/config.go`): `enableSignatureVerification bool`,
  `signingKeyRef` (secret for the internal cluster key), `trustPolicyRef` (ConfigMap). All new.

## 7. node-agent changes (hook points)

1. Phase-0 (CP-only reimplementation, §2): copy `pkg/signature/` core + tests + `cmd/sign-object/`
   verbatim; add the single **ContainerProfile adapter**
   (`pkg/signature/profiles/containerprofile_adapter.go`) exposing the canonical signed content of
   a CP; reimplement `tamper_alert.go` as one `verifyUserContainerProfile` (collapsing the AP/NN
   pair); wire `SetTamperAlertExporter` in `cmd/main.go` (reused). Port the AP/NN test fixtures to
   single-CP.
2. `pkg/signature/bundle/` (new): fragment normalization, admissibility check against trust
   policy, deterministic assembly, Merkle leaf-tree build/verify, manifest (de)serialization.
3. `containerprofilecache.go`: extend overlay fetch (`:347/:358`) to LIST the fragment set;
   in `buildEntry` (`:536`) replace single-overlay adoption with `bundle.AssembleAndVerify(...)`
   → verified composite before `Apply`.
4. `reconciler.go` (`:280-388`): re-verify on fragment-set RV change.
5. Internal re-sign at composite-write (near `monitoring.go` / `pkg/storage/v1/containerprofile.go`).
6. `pkg/config/config.go`: new keys (§6).

## 8. storage changes

- Optional `BundleManifest` opaque field on `ContainerProfileSpec` (+ `zz_generated.openapi.go`
  hand-edit Headers-style; **no codegen** — hand-edit only, per repo rule).
- Ensure fragment CPs (managed-by=User) are not spec-deflated in a way that diverges from the
  author's canonical form — align `DeflateContainerProfileSpec` with the sign-side normalization
  (§5.2), or exempt already-canonical user fragments.
- Optional: generalize `ComputeAggregatedData` (`containerprofile_aggregator.go`) to a Merkle
  tree shared with node-agent.

## 9. The test (bob redis distros — end to end)

Fixtures + flow, added under `bob/example/redis/distros/` and a node-agent component test:

1. **Sign the vendor default**: normalize + cosign-sign `sbobs/cp-redis.yaml` (class `base`,
   vendor key) → `cp-redis.signed.yaml`.
2. **Build + sign the admission fragment**: turn the `DEMO.md` §5 patch into a standalone CP
   manifest `cp-redis-ingress-client.yaml` (name `redis`, `spec.ingress` = the one entry, class
   `admission`), sign with a *second* key (operator/other-vendor).
3. **(optional) end-user overlay**: a third fragment + third key.
4. Apply all fragments (labeled `signature.kubescape.io/bundle: redis`), plus the trust policy
   ConfigMap mapping `base→vendor`, `admission→{vendor,operator}`, `overlay→enduser`.
5. Assert: node-agent assembles one `redis` CP whose `spec.ingress` admits `{app: redis-client}`,
   the composite carries a valid cluster signature + bundle manifest, and connecting the client
   raises **no R0012** (admitted). Before the admission fragment, R0012 fires (baseline).
6. **Negative cases** (the point of the feature):
   - Tamper a fragment's spec after signing → that leaf fails verify → excluded + **R1016**;
     ingress not admitted → R0012 returns.
   - Sign the admission fragment with an **untrusted** key (not in `admission` signers) →
     inadmissible → excluded; R0012.
   - A `client`/`overlay`-class fragment that tries to set `spec.execs` on `redis` → out-of-class
     path → rejected (proves class confinement).
   - Drop/add a fragment without updating the manifest → root mismatch → composite tamper.

This mirrors the existing `Test_31_TamperDetectionAlert` / `Test_29_SignedApplicationProfile`
shape so the component harness and R1016 alert plumbing are reused.

## 10. Phasing

- **P0** — land + port the signature base to CP on `signature-overlays` (§2, §7.1). Green: an
  existing single signed CP verifies + tampers (R1016) on `mirrormain` lineage.
- **P1** — fragment model + canonical signing (§5.2) + `cmd/sign-object`/`bobctl` normalize.
  Green: a single fragment CP signs and round-trips through storage without breaking its sig.
- **P2** — discovery + admissibility + deterministic assembly (§5.3–§5.5). Green: two admissible
  fragments assemble into the expected composite; inadmissible ones are excluded.
- **P3** — leaf-tree binding + internal re-sign + tamper-on-root-mismatch (§5.6–§5.7). Green: the
  §9 redis test incl. all negative cases.
- **P4** — the multi-repo release (storage + node-agent `signature-overlays` → CT → chart) via the
  proven chain; see `reference_multirepo_release_chain` memory.

## 11. Reuse summary (don't reinvent)

- Signing/verify/cosign, annotations, tamper R1016 → `pkg/signature/` + `tamper_alert.go` (port).
- Deterministic idempotent merge → storage `buildMergedProfile` /
  `mergeUserNetworkNeighbors` semantics.
- Hash-of-hashes root → storage `ComputeAggregatedData` (generalize to Merkle).
- Opaque round-trip-safe blob field → `HTTPEndpoint.Headers` OpenAPI pattern.
- Overlay discovery → `kubescape.io/user-defined-profile` label mechanism (extend to a set).
- Merged-first read + merged key → `containerprofile-merged` / `MergedKeyFor`.

## 12. Open decisions for you

1. **Phase-0 integration** (§2): RESOLVED — reimplement for CP only, reuse the tested
   `pkg/signature` core + tests + R1016 rule, single CP adapter, no merge.
2. **Bundle manifest location**: new opaque `spec.BundleManifest` field (survives round-trip,
   preferred) vs annotation-only (lighter, but must be covered by the composite signature).
3. **Assembly site**: node-agent-only (matches your requirement literally) vs storage-assisted
   (reuse `buildMergedProfile`, node-agent verifies + re-signs). Recommend node-agent-authoritative.
4. **Trust model**: keep cosign self-signed / allow-untrusted (as today) vs introduce a real
   trust root / CA per class. v1 recommend self-signed + explicit signer-identity allowlist per
   class.
5. **Bundle CRD**: per-fragment CP objects (v1, recommended) vs a dedicated
   `ContainerProfileBundle` CRD (later).

## 13. Key code references (absolute)

- node-agent load/assemble: `pkg/objectcache/containerprofilecache/containerprofilecache.go`
  (`:288,:347,:445,:536`), `reconciler.go` (`:280-388`), `projection_apply.go:36`.
- node-agent emit/re-sign: `pkg/containerprofilemanager/v1/monitoring.go:138-231`,
  `pkg/storage/v1/containerprofile.go:16-26`.
- signature base (branch `fix/sign-object-release-v0.0.3`): `pkg/signature/interface.go`,
  `annotations.go`, `verify.go`, `cosign_adapter.go`, `cmd/sign-object/main.go`,
  `pkg/objectcache/containerprofilecache/tamper_alert.go`.
- storage integrity/merge: `pkg/registry/file/storage.go:1247-1273,244-269`,
  `containerprofile_processor.go:889,929-961`, `containerprofile_user_managed.go:79,218,387`,
  `containerprofile_aggregator.go:26,94`, `networkpolicy/v2/networkpolicy.go:23`.
- storage types/openapi: `pkg/apis/softwarecomposition/types.go:335-410`,
  `v1beta1/types.go:293-318,641`, `pkg/generated/openapi/zz_generated.openapi.go:2439-2444`.
- bob fixtures: `example/redis/distros/sbobs/cp-redis.yaml`,
  `example/redis/distros/sbobs/cp-redis-client.yaml`, `example/redis/distros/DEMO.md` §5,
  `pkg/doc/sbob-rc3/components/signatures.md`, `pkg/cmd/sign.go`.
