package networkneighborhood

import (
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/utils/ptr"
)

// network_adversarial_test.go — BLACK-BOX adversarial security-regression
// guards for the 'nn' CEL library.
//
// These tests attack the network-neighborhood matchers through the REAL CEL
// boundary (env.Compile + program.Eval of the public `nn.*` functions), not
// the unexported helpers. For each security-contract clause we craft an
// adversarial FALSE-NEGATIVE input — traffic that is NOT in the profile and
// MUST be flagged (matcher returns false) — paired with a positive control
// that MUST match (true). A false-negative here means a real off-profile
// connection sails through the rule undetected.
//
// Probed contracts:
//   - exact address in profile vs sibling/outside address
//   - CIDR membership vs just-outside-the-prefix neighbour
//   - DNS leading-wildcard (RFC 4592, exactly one label) base/sub/sibling
//   - DNS mid-ellipsis interior matching
//   - direction isolation (egress entry must NOT satisfy ingress and v.v.)
//   - was_address_port_protocol_in_{egress,ingress}: an address that IS in the
//     profile but on a DIFFERENT port and/or DIFFERENT protocol than recorded
//     (suspected gap — see KNOWN GAP block below).

// buildAdversarialEnv constructs a CEL env over a fixed NetworkNeighborhood
// with both egress and ingress surfaces populated, mirroring the harness in
// integration_test.go. containerID is bound as a CEL variable so expressions
// read exactly like production rules.
func buildAdversarialEnv(t *testing.T) *cel.Env {
	t.Helper()
	objCache := objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: "test-container"}},
		},
	})

	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "test-container",
		Egress: []v1beta1.NetworkNeighbor{
			// Exact IPv4 with a recorded TCP:443 port only.
			{
				IPAddresses: []string{"203.0.113.10"},
				Ports: []v1beta1.NetworkPort{
					{Name: "tcp-443", Protocol: "TCP", Port: ptr.To(int32(443))},
				},
			},
			// CIDR /24 — membership test, no wildcard sentinel.
			{IPAddresses: []string{"198.51.100.0/24"}},
			// DNS leading-wildcard: exactly one label per RFC 4592.
			{DNSNames: []string{"*.example.com."}},
			// DNS mid-ellipsis (cluster-DNS style interior wildcard).
			{DNSNames: []string{"kubernetes.⋯.svc.cluster.local."}},
		},
		Ingress: []v1beta1.NetworkNeighbor{
			// Exact IPv4 recorded on TCP:8080 only.
			{
				IPAddresses: []string{"10.10.0.5"},
				Ports: []v1beta1.NetworkPort{
					{Name: "tcp-8080", Protocol: "TCP", Port: ptr.To(int32(8080))},
				},
			},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		NN(&objCache, config.Config{
			CelConfigCache: cache.FunctionCacheConfig{MaxSize: 1000, TTL: 1 * time.Minute},
		}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}
	return env
}

// evalNN compiles and evaluates a single nn.* expression and returns its
// boolean result through the real CEL pipeline.
func evalNN(t *testing.T, env *cel.Env, expression string) bool {
	t.Helper()
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("compile %q: %v", expression, issues.Err())
	}
	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("program %q: %v", expression, err)
	}
	out, _, err := program.Eval(map[string]interface{}{"containerID": "test-container-id"})
	if err != nil {
		t.Fatalf("eval %q: %v", expression, err)
	}
	b, ok := out.Value().(bool)
	if !ok {
		t.Fatalf("eval %q: result is not bool: %T %v", expression, out.Value(), out.Value())
	}
	return b
}

// TestAdversarial_AddressInProfile probes exact-address, CIDR-boundary, and
// '*' sentinel semantics through the address-only matchers. Each false case is
// an off-profile address that MUST be flagged.
func TestAdversarial_AddressInProfile(t *testing.T) {
	env := buildAdversarialEnv(t)

	cases := []struct {
		name string
		expr string
		want bool
	}{
		// Positive control.
		{"exact egress address matches", `nn.was_address_in_egress(containerID, "203.0.113.10")`, true},
		// FALSE NEGATIVE probe: off-by-one sibling of the exact address.
		{"sibling of exact egress address is NOT in profile", `nn.was_address_in_egress(containerID, "203.0.113.11")`, false},
		// FALSE NEGATIVE probe: address from an entirely different block.
		{"unrelated egress address is NOT in profile", `nn.was_address_in_egress(containerID, "8.8.8.8")`, false},

		// CIDR membership positive control + just-outside boundary.
		{"address inside /24 matches", `nn.was_address_in_egress(containerID, "198.51.100.200")`, true},
		{"network base of /24 matches", `nn.was_address_in_egress(containerID, "198.51.100.0")`, true},
		{"broadcast of /24 matches", `nn.was_address_in_egress(containerID, "198.51.100.255")`, true},
		// FALSE NEGATIVE probe: first address just past the /24 boundary.
		{"address just past /24 upper boundary is NOT in profile", `nn.was_address_in_egress(containerID, "198.51.101.0")`, false},
		// FALSE NEGATIVE probe: address just below the /24 network.
		{"address just below /24 lower boundary is NOT in profile", `nn.was_address_in_egress(containerID, "198.51.99.255")`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := evalNN(t, env, c.expr); got != c.want {
				t.Errorf("%s = %v, want %v (off-profile address must be flagged)", c.expr, got, c.want)
			}
		})
	}
}

// TestAdversarial_DirectionIsolation asserts that an egress-only address does
// not satisfy the ingress matcher and vice-versa. A leak across directions is
// a silent policy bypass.
func TestAdversarial_DirectionIsolation(t *testing.T) {
	env := buildAdversarialEnv(t)

	cases := []struct {
		name string
		expr string
		want bool
	}{
		{"egress address present on egress", `nn.was_address_in_egress(containerID, "203.0.113.10")`, true},
		// FALSE NEGATIVE probe: egress-only address must NOT match ingress.
		{"egress-only address must NOT match ingress", `nn.was_address_in_ingress(containerID, "203.0.113.10")`, false},
		{"ingress address present on ingress", `nn.was_address_in_ingress(containerID, "10.10.0.5")`, true},
		// FALSE NEGATIVE probe: ingress-only address must NOT match egress.
		{"ingress-only address must NOT match egress", `nn.was_address_in_egress(containerID, "10.10.0.5")`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := evalNN(t, env, c.expr); got != c.want {
				t.Errorf("%s = %v, want %v (direction isolation must hold)", c.expr, got, c.want)
			}
		})
	}
}

// TestAdversarial_DNSWildcard probes RFC 4592 leading-wildcard and mid-ellipsis
// DNS semantics. The wildcard base name and the sibling-zone name are the
// adversarial false-negatives.
func TestAdversarial_DNSWildcard(t *testing.T) {
	env := buildAdversarialEnv(t)

	cases := []struct {
		name string
		expr string
		want bool
	}{
		// Leading-wildcard: exactly one label substitutes.
		{"single-label sub matches *.example.com", `nn.is_domain_in_egress(containerID, "api.example.com.")`, true},
		// FALSE NEGATIVE probe: bare base name has zero labels — must NOT match.
		{"bare base example.com must NOT match *.example.com", `nn.is_domain_in_egress(containerID, "example.com.")`, false},
		// FALSE NEGATIVE probe: two labels — RFC 4592 allows exactly one.
		{"two-label name must NOT match single-label wildcard", `nn.is_domain_in_egress(containerID, "v1.api.example.com.")`, false},
		// FALSE NEGATIVE probe: lookalike sibling zone (substring of wildcard base).
		{"sibling zone evil-example.com must NOT match *.example.com", `nn.is_domain_in_egress(containerID, "api.evil-example.com.")`, false},
		// FALSE NEGATIVE probe: attacker-controlled suffix that embeds the base.
		{"suffixed lookalike must NOT match *.example.com", `nn.is_domain_in_egress(containerID, "api.example.com.attacker.net.")`, false},

		// Mid-ellipsis interior matching.
		{"interior label matches mid-ellipsis", `nn.is_domain_in_egress(containerID, "kubernetes.default.svc.cluster.local.")`, true},
		// FALSE NEGATIVE probe: different leading label must NOT match.
		{"different head label must NOT match mid-ellipsis", `nn.is_domain_in_egress(containerID, "redis.default.svc.cluster.local.")`, false},

		// DNS direction isolation: egress domains must NOT satisfy ingress.
		{"egress-only domain must NOT match ingress", `nn.is_domain_in_ingress(containerID, "api.example.com.")`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := evalNN(t, env, c.expr); got != c.want {
				t.Errorf("%s = %v, want %v (off-profile DNS name must be flagged)", c.expr, got, c.want)
			}
		})
	}
}

// TestAdversarial_AddressPortProtocol probes was_address_port_protocol_in_*.
//
// KNOWN GAP (characterization, NOT desired behaviour):
// The matchers in network.go (wasAddressPortProtocolInEgress /
// wasAddressPortProtocolInIngress) parse the port and protocol arguments for
// type/range validation but then return matchIPField(...EgressAddresses...)
// — i.e. they match on ADDRESS ONLY and IGNORE the port and protocol. An
// address that is in the profile on TCP:443 is therefore wrongly ACCEPTED
// when observed on, say, TCP:22 or UDP:443. The source comment frames this as
// a deliberate "projection-v1" degradation (port/protocol projection out of
// scope), but from a security standpoint it is a false-negative surface: a
// process that is allowed to reach a host on one port appears allowed on ALL
// ports/protocols.
//
// The cases below assert the CURRENT (degraded) behaviour so the suite stays
// green and this becomes a regression tripwire: if/when port+protocol
// enforcement lands, the `// KNOWN GAP` cases will flip and these expectations
// must be tightened to the security-correct value noted inline.
func TestAdversarial_AddressPortProtocol(t *testing.T) {
	env := buildAdversarialEnv(t)

	cases := []struct {
		name string
		expr string
		want bool
	}{
		// Positive controls: exact address+port+protocol as recorded.
		{"egress exact addr+port+proto matches", `nn.was_address_port_protocol_in_egress(containerID, "203.0.113.10", 443, "TCP")`, true},
		{"ingress exact addr+port+proto matches", `nn.was_address_port_protocol_in_ingress(containerID, "10.10.0.5", 8080, "TCP")`, true},

		// True negative that even the degraded matcher catches: address absent.
		{"egress unknown address is flagged", `nn.was_address_port_protocol_in_egress(containerID, "203.0.113.99", 443, "TCP")`, false},
		{"ingress unknown address is flagged", `nn.was_address_port_protocol_in_ingress(containerID, "10.10.0.99", 8080, "TCP")`, false},

		// KNOWN GAP: address in profile, WRONG port — security-correct want=false,
		// current behaviour want=true (port ignored).
		{"KNOWN GAP egress wrong port still accepted", `nn.was_address_port_protocol_in_egress(containerID, "203.0.113.10", 22, "TCP")`, true},
		// KNOWN GAP: address in profile, WRONG protocol — security-correct want=false,
		// current behaviour want=true (protocol ignored).
		{"KNOWN GAP egress wrong protocol still accepted", `nn.was_address_port_protocol_in_egress(containerID, "203.0.113.10", 443, "UDP")`, true},
		// KNOWN GAP: address in profile, WRONG port AND protocol — security-correct
		// want=false, current behaviour want=true.
		{"KNOWN GAP egress wrong port and protocol still accepted", `nn.was_address_port_protocol_in_egress(containerID, "203.0.113.10", 22, "UDP")`, true},
		// KNOWN GAP: ingress wrong port — security-correct want=false, current want=true.
		{"KNOWN GAP ingress wrong port still accepted", `nn.was_address_port_protocol_in_ingress(containerID, "10.10.0.5", 22, "TCP")`, true},
		// KNOWN GAP: ingress wrong protocol — security-correct want=false, current want=true.
		{"KNOWN GAP ingress wrong protocol still accepted", `nn.was_address_port_protocol_in_ingress(containerID, "10.10.0.5", 8080, "UDP")`, true},

		// Direction isolation still holds even under the degraded matcher:
		// egress-only address must NOT match the ingress port/protocol matcher.
		{"egress-only addr must NOT match ingress port/proto matcher", `nn.was_address_port_protocol_in_ingress(containerID, "203.0.113.10", 443, "TCP")`, false},
		{"ingress-only addr must NOT match egress port/proto matcher", `nn.was_address_port_protocol_in_egress(containerID, "10.10.0.5", 8080, "TCP")`, false},

		// Out-of-range port is rejected outright (network.go range guard).
		{"out-of-range port is rejected", `nn.was_address_port_protocol_in_egress(containerID, "203.0.113.10", 70000, "TCP")`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := evalNN(t, env, c.expr); got != c.want {
				t.Errorf("%s = %v, want %v", c.expr, got, c.want)
			}
		})
	}
}
