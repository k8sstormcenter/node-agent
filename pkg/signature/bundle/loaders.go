package bundle

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

// LoadSigningKey reads a PEM-encoded ECDSA private key (mounted Secret) used to
// internally re-sign assembled bundle composites. Accepts SEC1 ("EC PRIVATE
// KEY") and PKCS#8 ("PRIVATE KEY") encodings.
func LoadSigningKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key %q: %w", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("signing key %q is not PEM-encoded", path)
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if ec, ok := k.(*ecdsa.PrivateKey); ok {
			return ec, nil
		}
		return nil, fmt.Errorf("signing key %q is not an ECDSA key", path)
	}
	return nil, fmt.Errorf("failed to parse ECDSA private key from %q", path)
}
