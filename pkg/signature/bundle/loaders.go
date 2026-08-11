package bundle

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadTrustPolicy reads a JSON bundle trust policy from disk (typically a
// mounted ConfigMap). The JSON shape matches TrustPolicy:
//
//	{"classes":{"base":{"signers":["key:..."],"allowedSpecPaths":["execs","opens"]},
//	            "admission":{"signers":["key:..."],"allowedSpecPaths":["ingress","egress"]}}}
func LoadTrustPolicy(path string) (*TrustPolicy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust policy %q: %w", path, err)
	}
	var p TrustPolicy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse trust policy %q: %w", path, err)
	}
	if len(p.Classes) == 0 {
		return nil, fmt.Errorf("trust policy %q has no classes", path)
	}
	return &p, nil
}

// LoadSignedTrustPolicy reads a ROOT-signed trust policy artifact from disk
// (typically a mounted ConfigMap) and returns it ONLY if it verifies against the
// compile-time embedded root public key. The artifact JSON is
// {"policy": <TrustPolicy>, "annotations": {signature.kubescape.io/...}}; the
// signature covers the canonical policy content, and the signer's public-key
// fingerprint must equal the embedded root fingerprint. Fails closed on any
// error (unreadable, unparseable, bad signature, wrong signer, empty policy) so
// callers leave bundle overlays disabled. This is the loader main.go uses; a
// cluster-admin editing the ConfigMap cannot forge a policy without the offline
// root private key.
func LoadSignedTrustPolicy(path string) (*TrustPolicy, error) {
	rootFp, err := rootFingerprint()
	if err != nil {
		return nil, fmt.Errorf("compute embedded root fingerprint: %w", err)
	}
	return loadSignedTrustPolicyWithRoot(path, rootFp)
}

// loadSignedTrustPolicyWithRoot reads and verifies a signed policy file, pinning
// to expectedRootFp. LoadSignedTrustPolicy passes the embedded root fingerprint;
// tests pass their own generated key's fingerprint so no private key is needed.
func loadSignedTrustPolicyWithRoot(path, expectedRootFp string) (*TrustPolicy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signed trust policy %q: %w", path, err)
	}
	p, err := verifyAndPinPolicy(b, expectedRootFp)
	if err != nil {
		return nil, fmt.Errorf("signed trust policy %q: %w", path, err)
	}
	return p, nil
}
