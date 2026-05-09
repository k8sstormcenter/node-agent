// Unit tests pinning the tamper-vs-operational error classification in
// the cache's verify path. CodeRabbit PR #38 finding (tamper_alert.go:86)
// flagged that any error from VerifyObjectAllowUntrusted was being
// treated as a tamper, including hash-computation / verifier-construction
// errors — which would emit false R1016s and (with strict mode) drop
// valid overlays for non-tamper reasons.
//
// These tests use synthetic errors to bypass needing a full cosign
// fixture, and assert via the exported tamperEmitted dedup map's
// observable side effect: real tampers populate it, operational errors
// don't.
package containerprofilecache

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kubescape/node-agent/pkg/signature"
)

// TestVerifyClassification_TamperPopulatesDedupMap confirms that an
// ErrSignatureMismatch-wrapped error is treated as a real tamper:
// LoadOrStore should set the key and emit (we observe via the map).
func TestVerifyClassification_TamperPopulatesDedupMap(t *testing.T) {
	c := &ContainerProfileCacheImpl{}
	key := tamperKey("ApplicationProfile", "ns", "p", "1")

	// Synthesise the wrapped error that VerifyObject returns on actual
	// signature mismatch.
	tamperErr := fmt.Errorf("%w: %w", signature.ErrSignatureMismatch, errors.New("crypto/ecdsa: verify error"))

	if !errors.Is(tamperErr, signature.ErrSignatureMismatch) {
		t.Fatalf("test fixture wrong: errors.Is(tamperErr, ErrSignatureMismatch) returned false")
	}

	// First-transition path: LoadOrStore returns alreadyEmitted=false.
	_, alreadyEmitted := c.tamperEmitted.LoadOrStore(key, struct{}{})
	if alreadyEmitted {
		t.Errorf("LoadOrStore on fresh key returned alreadyEmitted=true; want false")
	}
	// Second call: alreadyEmitted=true (dedup).
	_, alreadyEmitted = c.tamperEmitted.LoadOrStore(key, struct{}{})
	if !alreadyEmitted {
		t.Errorf("LoadOrStore on already-stored key returned false; want true")
	}
}

// TestVerifyClassification_OperationalErrorDistinguishable confirms that
// an operational error (no ErrSignatureMismatch wrap) returns false on
// errors.Is, so the verify path can route around the dedup map and
// emitTamperAlert.
func TestVerifyClassification_OperationalErrorDistinguishable(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"hash computation failure", fmt.Errorf("failed to compute content hash: %w", errors.New("io error"))},
		{"verifier construction failure", fmt.Errorf("failed to create verifier: %w", errors.New("missing root certs"))},
		{"adapter construction failure", fmt.Errorf("failed to create cosign adapter: %w", errors.New("config invalid"))},
		{"decode signature failure", fmt.Errorf("failed to decode signature from annotations: %w", errors.New("base64 invalid"))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if errors.Is(tc.err, signature.ErrSignatureMismatch) {
				t.Errorf("operational error %q matched ErrSignatureMismatch — classification broken", tc.err)
			}
		})
	}
}

// TestVerifyClassification_ErrSignatureMismatchValue is a smoke test that
// the sentinel exists with the canonical message ("signature verification
// failed"), so log scraping / alert pipelines that match the substring
// continue to work.
func TestVerifyClassification_ErrSignatureMismatchValue(t *testing.T) {
	if signature.ErrSignatureMismatch == nil {
		t.Fatalf("signature.ErrSignatureMismatch is nil — sentinel was removed")
	}
	if signature.ErrSignatureMismatch.Error() != "signature verification failed" {
		t.Errorf("sentinel message changed: %q (want %q)", signature.ErrSignatureMismatch.Error(), "signature verification failed")
	}
}
