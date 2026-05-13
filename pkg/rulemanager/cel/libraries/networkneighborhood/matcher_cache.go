package networkneighborhood

import (
	"sync"
	"sync/atomic"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/networkmatch"
)

// neighborMatchers carries the compiled-once matchers for ONE NetworkNeighbor.
// Built lazily on first match attempt against this neighbor.
//
// Concurrency: both fields are atomic pointers. Multiple goroutines may
// race on the first build for a given index; CompileIP/CompileDNS are
// pure (no shared state), so duplicate builds are wasteful but correct.
// Only one resulting *matcher pointer wins via CompareAndSwap.
type neighborMatchers struct {
	ip  atomic.Pointer[networkmatch.IPMatcher]
	dns atomic.Pointer[networkmatch.DNSMatcher]
}

// containerMatchers caches every neighbor's compiled matchers for one
// container, keyed by direction + position in the spec slice. Tagged with
// the profile's SyncChecksumMetadataKey so we can invalidate atomically when
// the profile mutates.
//
// containerMatchers is treated as immutable once published into matcherCache.m:
// callers MUST NOT mutate egress/ingress slices in place. Stale entries are
// REPLACED wholesale (via Store), never patched.
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
// profile. If the cached entry is stale — by checksum OR by neighbor-count
// shape — it builds a fresh entry and replaces unconditionally.
//
// Always-Store-on-staleness avoids a subtle race: with LoadOrStore, two
// goroutines racing past a stale entry could "agree" on whichever lost the
// store, even if its shape didn't match the current profile. That would
// later panic in ipMatcher/dnsMatcher when indexed past the cached slice.
//
// The build itself is a no-op pre-allocation: we don't pay the per-neighbor
// CompileIP/CompileDNS cost until the first match call against that
// neighbor. neighborMatchers fields are atomic.Pointer-zero so the matcher
// accessor builds them lazily and concurrently-safely.
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
	// Store unconditionally on the staleness path: replaces any
	// concurrently-stored entry. Worst case under contention: a few
	// goroutines all compile fresh shape-correct entries and one Store wins,
	// other goroutines hold a now-orphaned but still-shape-correct fresh.
	// All callers see a shape-correct entry; orphans get GC'd.
	c.m.Store(containerID, fresh)
	return fresh
}

// ipMatcher returns the compiled IP matcher for the given neighbor index,
// lazily building it the first time. Combines the deprecated singular
// IPAddress and the new IPAddresses[] into one matcher per neighbor.
//
// Concurrency: atomic.Pointer.CompareAndSwap publishes the matcher.
// Concurrent first-build callers may each compile, but only one pointer
// wins; everyone returns the winning pointer.
func (cm *containerMatchers) ipMatcher(neighbors []v1beta1.NetworkNeighbor, idx int, slot *[]neighborMatchers) *networkmatch.IPMatcher {
	nm := &(*slot)[idx]
	if existing := nm.ip.Load(); existing != nil {
		return existing
	}
	n := &neighbors[idx]
	entries := make([]string, 0, len(n.IPAddresses)+1)
	if n.IPAddress != "" {
		entries = append(entries, n.IPAddress)
	}
	entries = append(entries, n.IPAddresses...)
	built := networkmatch.CompileIP(entries)
	if !nm.ip.CompareAndSwap(nil, built) {
		// Lost the race. Return the winning matcher.
		return nm.ip.Load()
	}
	return built
}

func (cm *containerMatchers) dnsMatcher(neighbors []v1beta1.NetworkNeighbor, idx int, slot *[]neighborMatchers) *networkmatch.DNSMatcher {
	nm := &(*slot)[idx]
	if existing := nm.dns.Load(); existing != nil {
		return existing
	}
	n := &neighbors[idx]
	entries := make([]string, 0, len(n.DNSNames)+1)
	if n.DNS != "" {
		entries = append(entries, n.DNS)
	}
	entries = append(entries, n.DNSNames...)
	built := networkmatch.CompileDNS(entries)
	if !nm.dns.CompareAndSwap(nil, built) {
		return nm.dns.Load()
	}
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
