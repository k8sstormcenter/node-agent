# PUBLISHED COMPONENT-TEST KEYS — COMPROMISED BY DESIGN. DO NOT TRUST.

Every private key here is committed to a public repository. Anyone can read
them. They exist so the signed-bundle / signed-rules component tests are
reproducible from a clean checkout, and for nothing else.

**A signature made by these keys authenticates nothing.** Treat any object they
sign as unsigned.

| Key | Role in the fixtures |
|---|---|
| `ct-vendor.pem` | Signs the `base`-class ContainerProfile fragment and the `base`-class rules fragment. |
| `ct-operator.pem` | Signs the `admission`/`overlay`-class ContainerProfile fragments and the `overlay`-class rules fragment. |
| `ct-untrusted.pem` | Named by NO trust policy. Signs the fragment the rejection test expects node-agent to refuse. |
| `ct-nonroot.pem` | Not the root key. Signs `trust-policy.badsigner.signed.json` for the fail-closed test. |

The ROOT key that signs the valid trust policies is **not** in this directory —
it is the equally published demo root key whose public half is compiled into
node-agent (`pkg/signature/bundle/root.go`).

## Never do this in a real cluster

- Do not run real workloads against a node-agent image that embeds this root
  public key: anyone can then sign a trust policy naming their own signing key,
  and policy, fragments and enforced profile all become attacker-controlled.
- Do not copy these keys into a production trust policy, values file or Secret.
- A green test run is evidence that the plumbing works, not that a deployment
  is signed.

Real deployments generate their own keys, keep the private halves offline, and
rebuild node-agent with their own root public key. No signing key ever reaches
the cluster — only public-key fingerprints (in the trust policy) and the root
public key (in the binary).

## Fingerprints

```
openssl ec -in <key>.pem -pubout | openssl pkey -pubin -outform DER | sha256sum
```

| Key | `key:<sha256(PKIX(pub))>` |
|---|---|
| `ct-vendor.pem` | `key:162a08d59135652ee095ad2e0d927104c9e4eefe94f4ae844e7387ba1a7352d2` |
| `ct-operator.pem` | `key:58fd31c363a8fac06d6eb596c2e8c63d5913b4dc4b971ee62579ec41fff78826` |
| `ct-untrusted.pem` | `key:9dbd23e8819ac29ecac1ab99fed196f4cb2e57890f1ca85d5a5a654d577e5bbf` |
| `ct-nonroot.pem` | `key:e48442a29374d921ef0530366aa9d2c7bb41fe2d06f6dad6d6cddce0d914a3a8` |
| embedded root | `key:d0cc7f2e82d99699d7a5f7078a9f30ec4847d13b6e41e91e224e0a47b32b9f9e` |
