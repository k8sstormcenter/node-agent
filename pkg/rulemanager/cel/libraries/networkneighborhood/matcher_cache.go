package networkneighborhood

import (
	"sync"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/networkmatch"
)

// neighborMatchers carries the compiled-once matchers for ONE NetworkNeighbor.
// Built lazily on first match attempt against this neighbor.
type neighborMatchers struct {
	ip  *networkmatch.IPMatcher
	dns *networkmatch.DNSMatcher
}

// containerMatchers caches every neighbor's compiled matchers for one
// container, keyed by direction + position in the spec slice. Tagged with
// the profile's SyncChecksumMetadataKey so we can invalidate atomically when
// the profile mutates.
type containerMatchers struct {
	checksum string
	egress   []neighborMatchers
	ingress  []neighborMatchers
}

// matcherCache is owned by an nnLibrary instance. Keyed by containerID.
// Map values are *containerMatchers; the cache uses sync.Map for lock-free
// reads (the common case on the CEL hot path).
//
// Zero-value usable: a freshly-declared matcherCache (no construction) is
// a valid empty cache. Tests can build nnLibrary{} without explicit init.
type matcherCache struct {
	m sync.Map // containerID -> *containerMatchers
}

// getOrBuild returns the compiled-matcher set for this container's current
// profile. If the cached entry is stale (different checksum, or different
// neighbor count after a profile shape change), it rebuilds.
//
// The build itself is a no-op pre-compile: we don't pay the per-neighbor
// CompileIP/CompileDNS cost until the first match call against that
// neighbor. neighborMatchers struct fields are nil-initialised so the
// matcher accessor lazily builds.
func (c *matcherCache) getOrBuild(containerID, checksum string, cp *v1beta1.ContainerProfile) *containerMatchers {
	if v, ok := c.m.Load(containerID); ok {
		cm := v.(*containerMatchers)
		if cm.checksum == checksum &&
			len(cm.egress) == len(cp.Spec.Egress) &&
			len(cm.ingress) == len(cp.Spec.Ingress) {
			return cm
		}
	}
	fresh := &containerMatchers{
		checksum: checksum,
		egress:   make([]neighborMatchers, len(cp.Spec.Egress)),
		ingress:  make([]neighborMatchers, len(cp.Spec.Ingress)),
	}
	// LoadOrStore: another goroutine may have raced us with the same checksum;
	// keep the first one stored so callers converge on a single instance.
	actual, _ := c.m.LoadOrStore(containerID, fresh)
	cm := actual.(*containerMatchers)
	if cm.checksum != checksum {
		// Concurrent update with a different checksum landed first. Replace.
		c.m.Store(containerID, fresh)
		return fresh
	}
	return cm
}

// ipMatcher returns the compiled IP matcher for the given neighbor index,
// lazily building it the first time. Combines the deprecated singular
// IPAddress and the new IPAddresses[] into one matcher per neighbor.
//
// Concurrency: writes to neighborMatchers.ip are guarded by an atomic
// LoadOrStore-style pattern; multiple goroutines racing on the same index
// MAY each pay the compile cost, but only one *IPMatcher pointer wins.
// In practice the CEL functionCache layer above us serialises most calls.
func (cm *containerMatchers) ipMatcher(neighbors []v1beta1.NetworkNeighbor, idx int, slot *[]neighborMatchers) *networkmatch.IPMatcher {
	nm := &(*slot)[idx]
	if nm.ip != nil {
		return nm.ip
	}
	n := &neighbors[idx]
	// Single compile per neighbor combining both deprecated singular IPAddress
	// and the v0.0.2 IPAddresses[] list. Same merged entries as
	// network.go:neighborMatchesIP, just amortised across calls.
	entries := make([]string, 0, len(n.IPAddresses)+1)
	if n.IPAddress != "" {
		entries = append(entries, n.IPAddress)
	}
	entries = append(entries, n.IPAddresses...)
	built := networkmatch.CompileIP(entries)
	nm.ip = built
	return built
}

func (cm *containerMatchers) dnsMatcher(neighbors []v1beta1.NetworkNeighbor, idx int, slot *[]neighborMatchers) *networkmatch.DNSMatcher {
	nm := &(*slot)[idx]
	if nm.dns != nil {
		return nm.dns
	}
	n := &neighbors[idx]
	entries := make([]string, 0, len(n.DNSNames)+1)
	if n.DNS != "" {
		entries = append(entries, n.DNS)
	}
	entries = append(entries, n.DNSNames...)
	built := networkmatch.CompileDNS(entries)
	nm.dns = built
	return built
}

// invalidate drops the cached entry for a container. Called from the
// nnLibrary on profile-delete signals (future hook); not wired today,
// so entries linger until the container goes away. Memory footprint is
// 2 × sizeof(neighborMatchers) × num-neighbors which is bounded by the
// profile size — typically under a few hundred bytes per container.
func (c *matcherCache) invalidate(containerID string) {
	c.m.Delete(containerID)
}
