package networkneighborhood

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
)

// BenchmarkMatchIPField covers the per-call cost of the IP-address
// matcher with three representative profile shapes:
//
//   - values_only_hit:  observed IP is a Values byte-equal hit
//   - patterns_cidr_hit: observed IP falls in a Patterns CIDR
//   - any_sentinel:     Patterns contains `*` — everything matches
//
// The matcher itself is cold-path (CEL functionCache memoises per
// (containerID, observed) per TTL), but these numbers ARE relevant on
// cache misses and at TTL refresh boundaries.
func BenchmarkMatchIPField(b *testing.B) {
	values := map[string]struct{}{
		"10.0.0.1": {}, "10.0.0.2": {}, "10.0.0.3": {},
		"192.168.1.1": {}, "172.16.0.1": {},
	}

	cases := []struct {
		name     string
		field    objectcache.ProjectedField
		observed string
	}{
		{
			name:     "values_only_hit",
			field:    objectcache.ProjectedField{Values: values},
			observed: "10.0.0.2",
		},
		{
			name: "patterns_cidr_hit",
			field: objectcache.ProjectedField{
				Values:   values,
				Patterns: []string{"10.0.0.0/8", "172.16.0.0/12"},
			},
			observed: "10.20.30.40",
		},
		{
			name: "any_sentinel",
			field: objectcache.ProjectedField{
				Values:   values,
				Patterns: []string{"*"},
			},
			observed: "203.0.113.99",
		},
		{
			name:     "miss",
			field:    objectcache.ProjectedField{Values: values},
			observed: "8.8.8.8",
		},
	}
	for _, c := range cases {
		field := c.field
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = matchIPField(&field, c.observed)
			}
		})
	}
}

// BenchmarkMatchDNSField mirrors the IP bench for DNS-name matching.
// Includes the FQDN trailing-dot normalisation path.
func BenchmarkMatchDNSField(b *testing.B) {
	values := map[string]struct{}{
		"api.example.com":      {},
		"api.example.com.":     {},
		"cdn.example.com":      {},
		"login.corp.local":     {},
		"prometheus.monitoring": {},
	}

	cases := []struct {
		name     string
		field    objectcache.ProjectedField
		observed string
	}{
		{
			name:     "values_exact_hit",
			field:    objectcache.ProjectedField{Values: values},
			observed: "api.example.com",
		},
		{
			name:     "values_trailing_dot_canon_hit",
			field:    objectcache.ProjectedField{Values: values},
			observed: "api.example.com.",
		},
		{
			name: "patterns_leading_wildcard_hit",
			field: objectcache.ProjectedField{
				Values:   values,
				Patterns: []string{"*.svc.cluster.local."},
			},
			observed: "kube-dns.svc.cluster.local.",
		},
		{
			name:     "miss",
			field:    objectcache.ProjectedField{Values: values},
			observed: "evil.attacker.example",
		},
	}
	for _, c := range cases {
		field := c.field
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = matchDNSField(&field, c.observed)
			}
		})
	}
}

// BenchmarkWasAddressPortProtocolInEgress measures the full CEL-side
// matcher cost: parses port + protocol from ref.Val, then dispatches
// to matchIPField.
//
// NOTE: port + protocol are currently NOT consulted in the match
// (address-only — pending the projection-v2 `AddressPortsByAddr`
// surface). Pinned by TestWasAddressPortProtocol_PortIgnored_*; bench
// here captures the CEL-conversion cost the matcher pays even though
// the port/protocol bits don't reach the match itself.
func BenchmarkWasAddressPortProtocolInEgress(b *testing.B) {
	pcp := &objectcache.ProjectedContainerProfile{
		EgressAddresses: objectcache.ProjectedField{
			Values:   map[string]struct{}{"10.0.0.1": {}, "10.0.0.2": {}},
			Patterns: []string{"10.0.0.0/8"},
		},
	}
	lib := &nnLibrary{objectCache: &mockNNObjectCache{pcp: pcp}}

	cases := []struct {
		name     string
		address  string
		port     int64
		protocol string
	}{
		{"hit_via_values", "10.0.0.1", 443, "TCP"},
		{"hit_via_cidr", "10.20.30.40", 443, "TCP"},
		{"miss", "8.8.8.8", 53, "UDP"},
	}
	cid := types.String("bench-cid")
	for _, c := range cases {
		addr := types.String(c.address)
		port := types.Int(c.port)
		proto := types.String(c.protocol)
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = lib.wasAddressPortProtocolInEgress(cid, addr, port, proto)
			}
		})
	}
}

// mockNNObjectCache is a minimal ObjectCache stub: only the
// ContainerProfileCache path needs to work for these benches.
type mockNNObjectCache struct {
	objectcache.ObjectCache
	pcp *objectcache.ProjectedContainerProfile
}

func (m *mockNNObjectCache) ContainerProfileCache() objectcache.ContainerProfileCache {
	return &mockNNCPC{pcp: m.pcp}
}

type mockNNCPC struct {
	objectcache.ContainerProfileCache
	pcp *objectcache.ProjectedContainerProfile
}

func (m *mockNNCPC) GetProjectedContainerProfile(_ string) *objectcache.ProjectedContainerProfile {
	return m.pcp
}
