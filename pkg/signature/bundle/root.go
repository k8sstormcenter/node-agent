package bundle

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// DefaultRootPublicKeyPEM is the compile-time embedded ROOT public key that
// anchors the entire signed-bundle trust chain. node-agent trusts a trust
// policy ONLY if it is signed by the corresponding root PRIVATE key (held
// offline, never on the cluster). There is deliberately NO runtime override:
// the root of trust is baked into the binary so a cluster-admin who can edit
// the mounted trust-policy ConfigMap still cannot forge a policy — they would
// need the offline root private key to produce a signature that verifies here.
//
// Rotation is a binary rebuild, on purpose: the root key is the one secret
// whose compromise must not be recoverable by editing in-cluster config.
const DefaultRootPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwIIkPTD5rGPP/bYmjRHxefAoCI1m
wIiQMRA78xdS5rTT3zl06ygpY9D4A1zRrQjq2CkF5ciwO2kSJGe3h64jEw==
-----END PUBLIC KEY-----
`

// rootFingerprint returns the trust-policy signer identity of the embedded
// root public key: "key:" + hex(sha256(PKIX(pub))). This is computed EXACTLY as
// signerIdentity(sig) derives an identity from a signature's certificate, so a
// trust policy signed by the root key yields a signerIdentity equal to this
// value — that equality is the pin LoadSignedTrustPolicy enforces.
func rootFingerprint() (string, error) {
	block, _ := pem.Decode([]byte(DefaultRootPublicKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to PEM-decode embedded root public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse embedded root public key: %w", err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to marshal embedded root public key: %w", err)
	}
	sum := sha256.Sum256(pkix)
	return "key:" + hex.EncodeToString(sum[:]), nil
}
