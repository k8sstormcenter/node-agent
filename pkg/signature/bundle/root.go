package bundle

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

const DefaultRootPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwIIkPTD5rGPP/bYmjRHxefAoCI1m
wIiQMRA78xdS5rTT3zl06ygpY9D4A1zRrQjq2CkF5ciwO2kSJGe3h64jEw==
-----END PUBLIC KEY-----
`

func fingerprintFromPublicKeyPEM(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", fmt.Errorf("failed to PEM-decode root public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse root public key: %w", err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to marshal root public key: %w", err)
	}
	sum := sha256.Sum256(pkix)
	return "key:" + hex.EncodeToString(sum[:]), nil
}

func rootFingerprint() (string, error) {
	return fingerprintFromPublicKeyPEM([]byte(DefaultRootPublicKeyPEM))
}

func rootFingerprintFromKeyFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read root public key %q: %w", path, err)
	}
	return fingerprintFromPublicKeyPEM(b)
}

func ResolveRootFingerprint(mountedKeyPath string) (fingerprint string, mounted bool, err error) {
	if mountedKeyPath != "" {
		fp, ferr := rootFingerprintFromKeyFile(mountedKeyPath)
		if ferr != nil {
			return "", true, ferr
		}
		return fp, true, nil
	}
	fp, ferr := rootFingerprint()
	return fp, false, ferr
}
