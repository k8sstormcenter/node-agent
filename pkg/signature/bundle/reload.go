package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"time"
)

// DefaultPolicyReloadInterval is how often the mounted trust policy is re-read.
// A ConfigMap update reaches the pod within about a minute, so polling is enough
// and avoids an inotify watch on a kubelet-managed symlink farm.
const DefaultPolicyReloadInterval = 30 * time.Second

// PolicyReloadEvent reports the outcome of one reload attempt.
type PolicyReloadEvent struct {
	Applied   *TrustPolicy // non-nil when a new policy verified and should be applied
	Err       error        // non-nil when the changed artifact was refused
	Mounted   bool
	RootFP    string
	Unchanged bool
}

// PolicyReloader re-reads a mounted trust policy and reports verified changes.
// A changed artifact that does NOT verify is refused and the caller keeps the
// policy it already has: a swapped-in bad policy must never downgrade or
// disable enforcement.
type PolicyReloader struct {
	path     string
	lastHash string
	// resolveRoot is the trusted-anchor resolver; production uses the fixed
	// mount or the compiled root, tests substitute a fingerprint.
	resolveRoot func() (fingerprint string, mounted bool, err error)
}

func NewPolicyReloader(path string, initial []byte) *PolicyReloader {
	r := &PolicyReloader{path: path, resolveRoot: ResolveTrustedRootFingerprint}
	if len(initial) > 0 {
		r.lastHash = hashBytes(initial)
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
	if h == r.lastHash {
		return PolicyReloadEvent{Unchanged: true}
	}
	// Record the hash even on failure so a persistently bad artifact is reported
	// once per distinct content rather than every tick.
	r.lastHash = h

	rootFP, mounted, rerr := r.resolveRoot()
	if rerr != nil {
		return PolicyReloadEvent{Err: rerr, Mounted: mounted}
	}
	p, verr := verifyAndPinPolicy(b, rootFP)
	if verr != nil {
		return PolicyReloadEvent{Err: verr, Mounted: mounted, RootFP: rootFP}
	}
	if gerr := GuardRootAnchor(p, rootFP, mounted); gerr != nil {
		return PolicyReloadEvent{Err: gerr, Mounted: mounted, RootFP: rootFP}
	}
	return PolicyReloadEvent{Applied: p, Mounted: mounted, RootFP: rootFP}
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
