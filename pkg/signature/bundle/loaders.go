package bundle

import (
	"encoding/json"
	"fmt"
	"os"
)

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

func LoadSignedTrustPolicy(policyPath, rootKeyPath string) (*TrustPolicy, error) {
	rootFp, _, err := ResolveRootFingerprint(rootKeyPath)
	if err != nil {
		return nil, fmt.Errorf("resolve root fingerprint: %w", err)
	}
	return loadSignedTrustPolicyWithRoot(policyPath, rootFp)
}

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
