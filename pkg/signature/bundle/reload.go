package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"
)

// DefaultPolicyReloadInterval is how often the mounted trust policy is re-read.
// A ConfigMap update reaches the pod within about a minute, so polling is enough
// and avoids an inotify watch on a kubelet-managed symlink farm.
const DefaultPolicyReloadInterval = 30 * time.Second

// PolicyReloadEvent reports the outcome of one reload attempt.
type PolicyReloadEvent struct {
	Applied *TrustPolicy // non-nil when a new policy verified and should be applied
	Err     error        // non-nil when the changed artifact was refused
	Mounted bool
	RootFP  string
	// ArtifactDigest is the sha256 (hex) of the candidate artifact bytes;
	// InForceDigest identifies the policy still (or now) in force, so a
	// refusal names both and `sha256sum` on the mounted file can be matched.
	ArtifactDigest string
	InForceDigest  string
	Unchanged      bool
}

// PolicyReloader re-reads a mounted trust policy and reports verified changes.
// A changed artifact that does NOT verify is refused and the caller keeps the
// policy it already has: a swapped-in bad policy must never downgrade or
// disable enforcement.
type PolicyReloader struct {
	path string
	// lastSeenHash dedups reporting (set even for refused content);
	// inForceHash identifies the applied policy and only moves on apply.
	lastSeenHash string
	inForceHash  string
	// resolveRoot is the trusted-anchor resolver; production uses the fixed
	// mount or the compiled root, tests substitute a fingerprint.
	resolveRoot    func() (fingerprint string, mounted bool, err error)
	inForceVersion int64
}

// ErrPolicyRollback is a replay of an older, still-validly-signed trust policy:
// hash dedup only detects change, so the monotonic policyVersion inside the
// signed content is what refuses a downgrade to a previously valid artifact.
var ErrPolicyRollback = errors.New("policy version is below the version in force (rollback)")

func NewPolicyReloader(path string, initial []byte, inForceVersion int64) *PolicyReloader {
	r := &PolicyReloader{path: path, resolveRoot: ResolveTrustedRootFingerprint, inForceVersion: inForceVersion}
	if len(initial) > 0 {
		h := hashBytes(initial)
		r.lastSeenHash = h
		r.inForceHash = h
	}
	return r
}

func hashBytes(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Poll reads the policy once and reports what changed.
func (r *PolicyReloader) Poll() PolicyReloadEvent {
	b, err := os.ReadFile(r.path)
	if err != nil {
		return PolicyReloadEvent{Err: err}
	}
	h := hashBytes(b)
	if h == r.lastSeenHash {
		return PolicyReloadEvent{Unchanged: true}
	}
	// Record the hash even on failure so a persistently bad artifact is reported
	// once per distinct content rather than every tick.
	r.lastSeenHash = h

	rootFP, mounted, rerr := r.resolveRoot()
	if rerr != nil {
		return PolicyReloadEvent{Err: rerr, Mounted: mounted, ArtifactDigest: h, InForceDigest: r.inForceHash}
	}
	p, verr := verifyAndPinPolicy(b, rootFP)
	if verr != nil {
		return PolicyReloadEvent{Err: verr, Mounted: mounted, RootFP: rootFP, ArtifactDigest: h, InForceDigest: r.inForceHash}
	}
	if gerr := GuardRootAnchor(p, rootFP, mounted); gerr != nil {
		return PolicyReloadEvent{Err: gerr, Mounted: mounted, RootFP: rootFP, ArtifactDigest: h, InForceDigest: r.inForceHash}
	}
	if p.PolicyVersion < r.inForceVersion {
		return PolicyReloadEvent{Err: fmt.Errorf("%w: refused version %d, in force %d", ErrPolicyRollback, p.PolicyVersion, r.inForceVersion), Mounted: mounted, RootFP: rootFP, ArtifactDigest: h, InForceDigest: r.inForceHash}
	}
	r.inForceVersion = p.PolicyVersion
	r.inForceHash = h
	return PolicyReloadEvent{Applied: p, Mounted: mounted, RootFP: rootFP, ArtifactDigest: h, InForceDigest: h}
}

// Watch polls until ctx is done, handing each event to onEvent.
func (r *PolicyReloader) Watch(ctx context.Context, every time.Duration, onEvent func(PolicyReloadEvent)) {
	if every <= 0 {
		every = DefaultPolicyReloadInterval
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ev := r.Poll()
			if ev.Unchanged {
				continue
			}
			onEvent(ev)
		}
	}
}

// HashArtifact is the digest served by /policyz and logged on reload events:
// plain sha256 hex of the artifact bytes, so `sha256sum` on the mounted file
// matches it directly.
func HashArtifact(b []byte) string { return hashBytes(b) }
