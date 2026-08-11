package bundle

import (
	"crypto/ecdsa"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/kubescape/node-agent/pkg/signature"
)

func demoPolicy() *TrustPolicy {
	return &TrustPolicy{
		Classes: map[FragmentClass]ClassPolicy{
			ClassBase: {
				Signers:          []string{"key:vendorfingerprint"},
				AllowedSpecPaths: []string{"execs", "opens"},
			},
			ClassAdmission: {
				Signers:          []string{"key:operatorfingerprint"},
				AllowedSpecPaths: []string{"ingress", "egress"},
			},
		},
	}
}

// signPolicyWithFingerprint signs a policy with key and returns the artifact
// bytes plus the signer's fingerprint. Tests pin against this fingerprint, so
// they never need the embedded root's private key on disk — the verify+pin logic
// (verifyAndPinPolicy) is identical to the production path, only the trusted
// fingerprint is supplied by the test instead of rootFingerprint().
func signPolicyWithFingerprint(t *testing.T, policy *TrustPolicy, key *ecdsa.PrivateKey) (signed []byte, fingerprint string) {
	t.Helper()
	signed, err := SignTrustPolicy(policy, key)
	if err != nil {
		t.Fatalf("SignTrustPolicy: %v", err)
	}
	var artifact signedTrustPolicyArtifact
	if err := json.Unmarshal(signed, &artifact); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	it := newPolicySignable(artifact.Policy, artifact.Annotations)
	sig, err := signature.GetObjectSignature(it)
	if err != nil {
		t.Fatalf("get signature: %v", err)
	}
	fp, err := signerIdentity(sig)
	if err != nil {
		t.Fatalf("signer identity: %v", err)
	}
	return signed, fp
}

// A policy signed by a key and pinned to that key's fingerprint round-trips.
func TestSignedPolicy_RoundTrip(t *testing.T) {
	signed, fp := signPolicyWithFingerprint(t, demoPolicy(), genKey(t))

	got, err := verifyAndPinPolicy(signed, fp)
	if err != nil {
		t.Fatalf("verifyAndPinPolicy: %v", err)
	}
	if len(got.Classes) != 2 {
		t.Fatalf("expected 2 classes, got %d", len(got.Classes))
	}
	if _, ok := got.Classes[ClassBase]; !ok {
		t.Fatal("missing base class")
	}
	if _, ok := got.Classes[ClassAdmission]; !ok {
		t.Fatal("missing admission class")
	}
}

// The file-path loader (used by main.go) round-trips too.
func TestSignedPolicy_RoundTripFile(t *testing.T) {
	signed, fp := signPolicyWithFingerprint(t, demoPolicy(), genKey(t))
	path := t.TempDir() + "/trust-policy.signed.json"
	if err := os.WriteFile(path, signed, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := loadSignedTrustPolicyWithRoot(path, fp)
	if err != nil {
		t.Fatalf("loadSignedTrustPolicyWithRoot: %v", err)
	}
	if len(got.Classes) != 2 {
		t.Fatalf("expected 2 classes, got %d", len(got.Classes))
	}
}

// A policy whose signature is valid but was made by a key OTHER than the pinned
// root is rejected — the pin, not just signature validity, is what protects the
// policy from being re-signed by an attacker.
func TestSignedPolicy_WrongSignerRejected(t *testing.T) {
	signed, _ := signPolicyWithFingerprint(t, demoPolicy(), genKey(t))
	// Pin to a DIFFERENT key's fingerprint.
	_, otherFp := signPolicyWithFingerprint(t, demoPolicy(), genKey(t))

	_, err := verifyAndPinPolicy(signed, otherFp)
	if err == nil {
		t.Fatal("expected rejection: policy not signed by the pinned root")
	}
	if !strings.Contains(err.Error(), "not signed by the embedded root key") {
		t.Fatalf("expected root-pin error, got: %v", err)
	}
}

// Mutating the policy object in the artifact after signing (adding a rogue
// class) is rejected: the signature no longer matches the canonical content.
func TestSignedPolicy_TamperedRejected(t *testing.T) {
	signed, fp := signPolicyWithFingerprint(t, demoPolicy(), genKey(t))

	var artifact signedTrustPolicyArtifact
	if err := json.Unmarshal(signed, &artifact); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	artifact.Policy.Classes[ClassAdmission] = ClassPolicy{
		Signers:          []string{"key:attackerfingerprint"},
		AllowedSpecPaths: []string{"execs", "opens", "ingress", "egress"},
	}
	tampered, err := json.Marshal(artifact)
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}

	_, err = verifyAndPinPolicy(tampered, fp)
	if err == nil {
		t.Fatal("expected rejection for tampered policy")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("expected signature-verification error, got: %v", err)
	}
}

// An unsigned / annotation-less artifact is rejected (fail closed).
func TestSignedPolicy_MissingSignatureRejected(t *testing.T) {
	artifact := signedTrustPolicyArtifact{Policy: demoPolicy(), Annotations: nil}
	data, err := json.Marshal(artifact)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, err = verifyAndPinPolicy(data, "key:whatever")
	if err == nil {
		t.Fatal("expected rejection for missing signature annotations")
	}
}

// The embedded root public key parses and yields a stable key:<hex> fingerprint.
// This exercises the production anchor without needing any private key.
func TestEmbeddedRootFingerprint_Parses(t *testing.T) {
	fp, err := rootFingerprint()
	if err != nil {
		t.Fatalf("rootFingerprint: %v", err)
	}
	if !strings.HasPrefix(fp, "key:") || len(fp) != len("key:")+64 {
		t.Fatalf("embedded root fingerprint malformed: %q", fp)
	}
}
