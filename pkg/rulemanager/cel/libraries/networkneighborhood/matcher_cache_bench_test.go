package networkneighborhood

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/goradd/maps"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Benchmarks that measure the production-realistic call shape:
// a CEL function (e.g. nn.was_address_in_egress) is invoked on a cache miss,
// walks the profile's egress neighbors, compiles+matches each one.
//
// Two axes:
//   - profile size (small: 1 neighbor / 1 entry  vs  realistic: 5 neighbors / 3 entries)
//   - cache state    (cold: every call recompiles  vs  hot: matcherCache reuses)
//
// The "cold" baseline simulates what the previous feat/network-wildcards
// branch did before this PR (re-compile on every CEL function-cache miss).
// The "hot" measures the actual code path of this PR (compile-once amortised).

func buildProfile(neighbors int, entriesPerNeighbor int) *v1beta1.ContainerProfile {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bench-pod",
			Annotations: map[string]string{
				helpers.SyncChecksumMetadataKey: "bench-checksum-v1",
			},
		},
	}
	cp.Spec.Egress = make([]v1beta1.NetworkNeighbor, neighbors)
	for i := 0; i < neighbors; i++ {
		ips := make([]string, entriesPerNeighbor)
		// Mix of CIDR + literal so neither path has trivial work.
		for j := 0; j < entriesPerNeighbor; j++ {
			if j%2 == 0 {
				ips[j] = "10.0.0.0/8"
			} else {
				ips[j] = "192.168.1.1"
			}
		}
		cp.Spec.Egress[i] = v1beta1.NetworkNeighbor{
			Identifier:  "n",
			IPAddresses: ips,
			DNSNames:    []string{"*.example.com.", "api.partner.io."},
		}
	}
	return cp
}

func buildBenchLib(b *testing.B, cp *v1beta1.ContainerProfile) *nnLibrary {
	b.Helper()
	objCache := objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	objCache.SetSharedContainerData("bench-cid", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: "bench"}},
		},
	})
	objCache.SetContainerProfile(cp)
	return &nnLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}
}

func runEgressIPMatch(b *testing.B, lib *nnLibrary, address ref.Val) {
	cid := types.String("bench-cid")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lib.wasAddressInEgress(cid, address)
	}
}

// Small profile: 1 neighbor, 1 IP. Establishes the floor cost.
func BenchmarkCEL_EgressIP_Small_Hot(b *testing.B) {
	lib := buildBenchLib(b, buildProfile(1, 1))
	// Prime the matcher cache: one call before the timed loop so the
	// per-CEL-invocation cost is amortised.
	_ = lib.wasAddressInEgress(types.String("bench-cid"), types.String("10.1.2.3"))
	runEgressIPMatch(b, lib, types.String("10.1.2.3"))
}

// Realistic profile: 5 neighbors × 3 entries (mix of CIDR + literal).
// Hot path = matcherCache reused. This is what production looks like
// AFTER the first CEL function-cache miss within a profile lifetime.
func BenchmarkCEL_EgressIP_Realistic_Hot(b *testing.B) {
	lib := buildBenchLib(b, buildProfile(5, 3))
	_ = lib.wasAddressInEgress(types.String("bench-cid"), types.String("8.8.8.8"))
	runEgressIPMatch(b, lib, types.String("8.8.8.8")) // worst case: miss every neighbor
}

// Cold path: simulate the pre-cache pattern by wiping the matcher cache
// each iteration. This is what the previous feat/network-wildcards branch
// did on EVERY CEL function-cache miss (a unique containerID,address pair).
func BenchmarkCEL_EgressIP_Realistic_Cold(b *testing.B) {
	cp := buildProfile(5, 3)
	lib := buildBenchLib(b, cp)
	addr := types.String("8.8.8.8")
	cid := types.String("bench-cid")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Drop the entire cache entry to force recompile on the next call.
		lib.matcherCache.invalidate("bench-cid")
		_ = lib.wasAddressInEgress(cid, addr)
	}
}

// DNS variants.

func BenchmarkCEL_EgressDNS_Realistic_Hot(b *testing.B) {
	lib := buildBenchLib(b, buildProfile(5, 3))
	_ = lib.isDomainInEgress(types.String("bench-cid"), types.String("ignored.fake.tld."))
	cid := types.String("bench-cid")
	dom := types.String("ignored.fake.tld.")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lib.isDomainInEgress(cid, dom)
	}
}

func BenchmarkCEL_EgressDNS_Realistic_Cold(b *testing.B) {
	cp := buildProfile(5, 3)
	lib := buildBenchLib(b, cp)
	cid := types.String("bench-cid")
	dom := types.String("ignored.fake.tld.")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lib.matcherCache.invalidate("bench-cid")
		_ = lib.isDomainInEgress(cid, dom)
	}
}

// Profile churn: simulate a learning-mode profile that gets updated
// frequently (checksum changes), so cache lookups are mostly invalidated.
// Validates that the cache invalidation path itself isn't catastrophic.
func BenchmarkCEL_EgressIP_ChurningProfile(b *testing.B) {
	cp := buildProfile(5, 3)
	lib := buildBenchLib(b, cp)
	cid := types.String("bench-cid")
	addr := types.String("8.8.8.8")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Bump checksum each iteration to force rebuild via getOrBuild.
		if i%2 == 0 {
			cp.Annotations[helpers.SyncChecksumMetadataKey] = "bench-checksum-v1"
		} else {
			cp.Annotations[helpers.SyncChecksumMetadataKey] = "bench-checksum-v2"
		}
		_ = lib.wasAddressInEgress(cid, addr)
	}
}
