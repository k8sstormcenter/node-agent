package networkneighborhood

import (
	"sync"
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/goradd/maps"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestMatcherCache_ConcurrentFirstBuild pins the atomic-pointer race
// contract on neighborMatchers. Concurrent first-build callers may each
// compile, but they MUST all return the same *IPMatcher / *DNSMatcher
// pointer (the CompareAndSwap winner), and the cached entry MUST be
// reusable thereafter without rebuild.
//
// Run with `go test -race` to catch unsynchronised writes.
func TestMatcherCache_ConcurrentFirstBuild(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{helpers.SyncChecksumMetadataKey: "csum-1"},
		},
	}
	cp.Spec.Egress = []v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"10.0.0.0/8"}, DNSNames: []string{"*.example.com."}},
	}

	objCache := objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	objCache.SetSharedContainerData("cid", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: "c"}},
		},
	})
	objCache.SetContainerProfile(cp)
	lib := &nnLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	const goroutines = 64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			// Both functions race on the same neighborMatchers slot.
			_ = lib.wasAddressInEgress(types.String("cid"), types.String("10.1.2.3"))
			_ = lib.isDomainInEgress(types.String("cid"), types.String("api.example.com."))
		}()
	}
	wg.Wait()

	// Post-condition: cached entry exists, has the right shape, and
	// per-neighbor matchers are populated.
	cm := lib.matcherCache.getOrBuild("cid", "csum-1", cp)
	require.Equal(t, 1, len(cm.egress), "egress shape must match profile")
	require.NotNil(t, cm.egress[0].ip.Load(), "ip matcher must be built after concurrent access")
	require.NotNil(t, cm.egress[0].dns.Load(), "dns matcher must be built after concurrent access")
}

// TestMatcherCache_StaleEntryReplaced confirms that shape-mismatched
// cached entries are unconditionally replaced — never returned to a
// caller whose profile has a different shape (which would later index-
// panic in ipMatcher/dnsMatcher).
func TestMatcherCache_StaleEntryReplaced(t *testing.T) {
	mc := &matcherCache{}
	cpV1 := &v1beta1.ContainerProfile{}
	cpV1.Spec.Egress = []v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"10.0.0.0/8"}},
	}
	// Seed with a v1 entry.
	cm1 := mc.getOrBuild("cid", "csum-v1", cpV1)
	require.Equal(t, 1, len(cm1.egress))

	// Now the profile grows to 3 egress entries; new call should NOT
	// return the stale 1-entry cm1.
	cpV2 := &v1beta1.ContainerProfile{}
	cpV2.Spec.Egress = []v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"10.0.0.0/8"}},
		{IPAddresses: []string{"192.168.0.0/16"}},
		{IPAddresses: []string{"172.16.0.0/12"}},
	}
	cm2 := mc.getOrBuild("cid", "csum-v2", cpV2)
	require.Equal(t, 3, len(cm2.egress), "shape-mismatched stale entry must be replaced")
	require.NotEqual(t, cm1, cm2, "must be a different containerMatchers instance")
}

// TestMatcherCache_ChecksumPreservedAcrossCalls confirms that repeated
// getOrBuild calls with the SAME checksum return the SAME instance,
// proving the cache is doing what we want it to do.
func TestMatcherCache_ChecksumPreservedAcrossCalls(t *testing.T) {
	mc := &matcherCache{}
	cp := &v1beta1.ContainerProfile{}
	cp.Spec.Egress = []v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"10.0.0.0/8"}},
	}
	a := mc.getOrBuild("cid", "csum", cp)
	b := mc.getOrBuild("cid", "csum", cp)
	c := mc.getOrBuild("cid", "csum", cp)
	require.Same(t, a, b, "same checksum must hit cache on second call")
	require.Same(t, b, c, "same checksum must hit cache on third call")
}
