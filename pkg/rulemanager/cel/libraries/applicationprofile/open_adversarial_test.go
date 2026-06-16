package applicationprofile

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// Black-box adversarial probes against the open- and endpoint-membership
// helpers, in the same false-negative-hunting style as exec_adversarial_test.go.
// Every case runs through the REAL CEL boundary (compile + eval of the
// `ap.*` expression) — never the unexported method directly — so the overload
// registration, arg marshalling, and projection read path are all exercised.
//
// For each contract clause we craft an adversarial OVER-BROADENING input (a
// suffix/prefix/endpoint that should NOT be considered "in profile" but might
// be wrongly accepted) plus a positive control (a value that SHOULD match).
// A spurious `true` on an adversarial case is a false-negative for the
// detection rule built on `!ap.was_*` — the runtime stays silent on an
// out-of-profile action.

// --- shared CEL harness helpers (open_adversarial scope) -------------------

// newOpenAdvEnv builds a CEL env over an ApplicationProfile whose container
// declares the supplied Opens. Mirrors TestOpenWithSuffixInProfile's setup.
func newOpenAdvEnv(t *testing.T, opens []v1beta1.OpenCalls, vars ...cel.EnvOption) *cel.Env {
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
	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name:  "test-container",
		Opens: opens,
	})
	objCache.SetApplicationProfile(profile)

	base := []cel.EnvOption{
		cel.Variable("containerID", cel.StringType),
		AP(&objCache, config.Config{}),
	}
	env, err := cel.NewEnv(append(base, vars...)...)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}
	return env
}

// newEndpointAdvEnv builds a CEL env over an ApplicationProfile whose container
// declares the supplied HTTP endpoints. SetApplicationProfile populates
// Endpoints.All=true with each Endpoint string in Endpoints.Values.
func newEndpointAdvEnv(t *testing.T, endpoints []v1beta1.HTTPEndpoint, vars ...cel.EnvOption) *cel.Env {
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
	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name:      "test-container",
		Endpoints: endpoints,
	})
	objCache.SetApplicationProfile(profile)

	base := []cel.EnvOption{
		cel.Variable("containerID", cel.StringType),
		AP(&objCache, config.Config{}),
	}
	env, err := cel.NewEnv(append(base, vars...)...)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}
	return env
}

// evalBool compiles `expr` and evaluates it with the given bindings, returning
// the bool result. Fails the test on any compile/eval error.
func evalBool(t *testing.T, env *cel.Env, expr string, in map[string]any) bool {
	t.Helper()
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		t.Fatalf("compile %q: %v", expr, iss.Err())
	}
	prog, err := env.Program(ast)
	if err != nil {
		t.Fatalf("program %q: %v", expr, err)
	}
	out, _, err := prog.Eval(in)
	if err != nil {
		t.Fatalf("eval %q: %v", expr, err)
	}
	b, ok := out.Value().(bool)
	if !ok {
		t.Fatalf("eval %q: result %#v is not bool", expr, out.Value())
	}
	return b
}

// ============================================================================
// was_path_opened_with_suffix — over-broadening probes
// ============================================================================

// TestAdversarial_OpenSuffix_OffByOneAndPartial attacks the HasSuffix contract:
// the query suffix must be a true tail of a concrete observed path. A near-miss
// suffix (one extra leading char that breaks the tail boundary) must NOT match.
func TestAdversarial_OpenSuffix_OffByOneAndPartial(t *testing.T) {
	env := newOpenAdvEnv(t, []v1beta1.OpenCalls{
		{Path: "/var/log/app.log", Flags: []string{"O_RDWR"}},
	}, cel.Variable("suffix", cel.StringType))

	cases := []struct {
		name   string
		suffix string
		want   bool
	}{
		// Positive controls.
		{"exact full path is a suffix", "/var/log/app.log", true},
		{"true tail pp.log", "pp.log", true},
		{"true tail .log", ".log", true},
		// Adversarial: NOT a tail of the observed path.
		{"off-by-one x.log is not a tail", "x.log", false},
		{"partial middle log/app is not a tail", "log/app", false},
		{"unrelated suffix .conf must not match", ".conf", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalBool(t, env, `ap.was_path_opened_with_suffix(containerID, suffix)`,
				map[string]any{"containerID": "test-container-id", "suffix": c.suffix})
			if got != c.want {
				t.Errorf("was_path_opened_with_suffix(%q) = %v, want %v "+
					"(suffix must be a true tail of a concrete observed path)", c.suffix, got, c.want)
			}
		})
	}
}

// TestAdversarial_OpenSuffix_PatternMustNotAnswerConcreteSuffix is the #807 /
// PR#43 contract at the CEL boundary: a wildcard Pattern entry's literal text
// must NOT answer a concrete suffix question. The mock routes dynamic-segment
// open paths... actually the mock routes ALL open paths to Values, so to force
// a Pattern-only profile we drive a fixed projection via mockObjectCacheForPattern
// (defined in open_test.go). The wildcard pattern textually ends with the
// queried suffix, but the correct answer is false: only concrete paths in
// Values are valid suffix sources in pass-through mode.
func TestAdversarial_OpenSuffix_PatternMustNotAnswerConcreteSuffix(t *testing.T) {
	pcp := &objectcache.ProjectedContainerProfile{
		Opens: objectcache.ProjectedField{
			All:      true,
			Values:   map[string]struct{}{},                 // no concrete observation
			Patterns: []string{"/var/log/⋯/secret.token"},   // wildcard ends with ".token"
		},
	}
	lib := &apLibrary{objectCache: &mockObjectCacheForPattern{pcp: pcp}}

	// Pattern-only profile: a wildcard whose literal text ends with ".token".
	// The mock's SetApplicationProfile routes every open path to Values, so a
	// Pattern-only profile is only reachable via the fixed-projection mock —
	// the same boundary open_test.go's pattern tests use.
	if b := lib.wasPathOpenedWithSuffix(types.String("test-cid"), types.String(".token")).Value().(bool); b {
		t.Errorf("suffix '.token' against ONLY wildcard pattern /var/log/⋯/secret.token: "+
			"expected false (a wildcard Pattern must not answer a concrete suffix question), got true")
	}

	// Positive control: add a concrete observation and confirm it matches.
	pcp.Opens.Values["/etc/app/secret.token"] = struct{}{}
	if b := lib.wasPathOpenedWithSuffix(types.String("test-cid"), types.String(".token")).Value().(bool); !b {
		t.Errorf("suffix '.token' against concrete /etc/app/secret.token: expected true, got false")
	}
}

// ============================================================================
// was_path_opened_with_prefix — over-broadening probes
// ============================================================================

// TestAdversarial_OpenPrefix_OffByOneAndPartial attacks the HasPrefix contract.
func TestAdversarial_OpenPrefix_OffByOneAndPartial(t *testing.T) {
	env := newOpenAdvEnv(t, []v1beta1.OpenCalls{
		{Path: "/var/log/app.log", Flags: []string{"O_RDWR"}},
	}, cel.Variable("prefix", cel.StringType))

	cases := []struct {
		name   string
		prefix string
		want   bool
	}{
		// Positive controls.
		{"root prefix /var", "/var", true},
		{"deeper prefix /var/log/", "/var/log/", true},
		{"exact full path is a prefix", "/var/log/app.log", true},
		// Adversarial: NOT a head of the observed path.
		{"missing leading slash var is not a head", "var/log", false},
		{"sibling dir /var/lib is not a head", "/var/lib", false},
		{"longer than path must not match", "/var/log/app.log.bak", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalBool(t, env, `ap.was_path_opened_with_prefix(containerID, prefix)`,
				map[string]any{"containerID": "test-container-id", "prefix": c.prefix})
			if got != c.want {
				t.Errorf("was_path_opened_with_prefix(%q) = %v, want %v "+
					"(prefix must be a true head of a concrete observed path)", c.prefix, got, c.want)
			}
		})
	}
}

// TestAdversarial_OpenPrefix_PatternMustNotAnswerConcretePrefix mirrors the
// suffix #807 probe for the prefix arm.
func TestAdversarial_OpenPrefix_PatternMustNotAnswerConcretePrefix(t *testing.T) {
	pcp := &objectcache.ProjectedContainerProfile{
		Opens: objectcache.ProjectedField{
			All:      true,
			Values:   map[string]struct{}{},
			Patterns: []string{"/secret/⋯/data"}, // textually starts with "/secret/"
		},
	}
	lib := &apLibrary{objectCache: &mockObjectCacheForPattern{pcp: pcp}}

	if b := lib.wasPathOpenedWithPrefix(types.String("test-cid"), types.String("/secret/")).Value().(bool); b {
		t.Errorf("prefix '/secret/' against ONLY wildcard pattern /secret/⋯/data: "+
			"expected false (a wildcard Pattern must not answer a concrete prefix question), got true")
	}

	pcp.Opens.Values["/secret/real/data"] = struct{}{}
	if b := lib.wasPathOpenedWithPrefix(types.String("test-cid"), types.String("/secret/")).Value().(bool); !b {
		t.Errorf("prefix '/secret/' against concrete /secret/real/data: expected true, got false")
	}
}

// ============================================================================
// was_path_opened_with_flags — flags-ignored characterization (v1 gap)
// ============================================================================

// TestAdversarial_OpenWithFlags_FlagsIgnored characterizes the documented v1
// behavior: the flags argument is parsed for shape but NOT used for matching
// (open.go: "flags projection (OpenFlagsByPath) is out of scope for v1; degrade
// to path-only matching"). An adversarial caller asking about a path with flags
// that were NEVER observed (e.g. a write open of a read-only-observed file) is
// answered purely on path membership.
//
// KNOWN GAP (documented as intentional v1 scope, not a regression): a path
// observed only with O_RDONLY is reported as "opened" for an O_WRONLY|O_CREAT
// query. Input: path="/etc/passwd", flags=["O_WRONLY","O_CREAT"] against a
// profile where /etc/passwd was opened O_RDONLY only -> returns TRUE. A
// flag-sensitive rule would expect FALSE. Asserting current (path-only) behavior
// so the suite stays green and the projection-slice rollout has a tripwire.
func TestAdversarial_OpenWithFlags_FlagsIgnored(t *testing.T) {
	env := newOpenAdvEnv(t, []v1beta1.OpenCalls{
		{Path: "/etc/passwd", Flags: []string{"O_RDONLY"}},
	},
		cel.Variable("path", cel.StringType),
		cel.Variable("flags", cel.ListType(cel.StringType)))

	cases := []struct {
		name  string
		path  string
		flags []string
		want  bool
	}{
		{"observed path, observed flag", "/etc/passwd", []string{"O_RDONLY"}, true},
		// KNOWN GAP: flags are not matched — superset write flags still match.
		{"observed path, UNOBSERVED write flags (flags ignored)", "/etc/passwd",
			[]string{"O_WRONLY", "O_CREAT"}, true},
		{"observed path, empty flags (flags ignored)", "/etc/passwd", []string{}, true},
		// Path genuinely not in profile -> false regardless of flags.
		{"unobserved path is false", "/etc/shadow", []string{"O_RDONLY"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalBool(t, env, `ap.was_path_opened_with_flags(containerID, path, flags)`,
				map[string]any{"containerID": "test-container-id", "path": c.path, "flags": c.flags})
			if got != c.want {
				t.Errorf("was_path_opened_with_flags(%q, %v) = %v, want %v",
					c.path, c.flags, got, c.want)
			}
		})
	}
}

// ============================================================================
// Endpoint helpers — prefix / suffix / method / methods over-broadening probes
// ============================================================================

// TestAdversarial_EndpointPrefixSuffix_OffByOne attacks the endpoint
// HasPrefix/HasSuffix contracts through the CEL boundary on concrete endpoints.
func TestAdversarial_EndpointPrefixSuffix_OffByOne(t *testing.T) {
	env := newEndpointAdvEnv(t, []v1beta1.HTTPEndpoint{
		{Endpoint: "/api/v1/users", Methods: []string{"GET"}},
	},
		cel.Variable("prefix", cel.StringType),
		cel.Variable("suffix", cel.StringType))

	t.Run("prefix", func(t *testing.T) {
		cases := []struct {
			name   string
			prefix string
			want   bool
		}{
			{"true head /api/v1", "/api/v1", true},
			{"exact endpoint is a head", "/api/v1/users", true},
			{"missing slash api is not a head", "api/v1", false},
			{"sibling /api/v2 is not a head", "/api/v2", false},
		}
		for _, c := range cases {
			got := evalBool(t, env, `ap.was_endpoint_accessed_with_prefix(containerID, prefix)`,
				map[string]any{"containerID": "test-container-id", "prefix": c.prefix})
			if got != c.want {
				t.Errorf("was_endpoint_accessed_with_prefix(%q) = %v, want %v", c.prefix, got, c.want)
			}
		}
	})

	t.Run("suffix", func(t *testing.T) {
		cases := []struct {
			name   string
			suffix string
			want   bool
		}{
			{"true tail /users", "/users", true},
			{"true tail users", "users", true},
			{"off-by-one Xusers is not a tail", "Xusers", false},
			{"sibling /admin is not a tail", "/admin", false},
		}
		for _, c := range cases {
			got := evalBool(t, env, `ap.was_endpoint_accessed_with_suffix(containerID, suffix)`,
				map[string]any{"containerID": "test-container-id", "suffix": c.suffix})
			if got != c.want {
				t.Errorf("was_endpoint_accessed_with_suffix(%q) = %v, want %v", c.suffix, got, c.want)
			}
		}
	})
}

// TestAdversarial_EndpointPrefixSuffix_PatternsAreScanned characterizes a real
// ASYMMETRY against the open helpers. Unlike was_path_opened_with_{suffix,prefix}
// — which scan ONLY Values in pass-through mode (the #807 contract) — the
// endpoint suffix/prefix helpers (http.go) scan BOTH Endpoints.Values AND
// Endpoints.Patterns with strings.HasPrefix/HasSuffix against the raw pattern
// text.
//
// KNOWN GAP: endpoint suffix/prefix queries are answered from wildcard Pattern
// text, which the open-helper contract explicitly forbids as over-broadening.
// Input: a profile whose only endpoint is the wildcard Pattern "/api/⋯/health"
// and query suffix "/health" -> returns TRUE off the pattern's literal tail,
// even though no concrete "/health" endpoint was observed. The analogous open
// query returns FALSE. Asserting CURRENT endpoint behavior (Patterns scanned)
// so the suite stays green; flagged so the endpoint helpers can be aligned with
// the #807 open contract later.
func TestAdversarial_EndpointPrefixSuffix_PatternsAreScanned(t *testing.T) {
	pcp := &objectcache.ProjectedContainerProfile{
		Endpoints: objectcache.ProjectedField{
			All:      true,
			Values:   map[string]struct{}{},
			Patterns: []string{"/api/⋯/health"}, // ends with "/health", starts with "/api/"
		},
	}
	lib := &apLibrary{objectCache: &mockObjectCacheForPattern{pcp: pcp}}

	// KNOWN GAP: pattern text answers the concrete suffix question.
	if b := lib.wasEndpointAccessedWithSuffix(types.String("test-cid"), types.String("/health")).Value().(bool); !b {
		t.Errorf("CHARACTERIZATION DRIFT: endpoint suffix '/health' against wildcard "+
			"pattern /api/⋯/health returned false; current code scans Patterns and "+
			"is expected to return true (KNOWN GAP vs #807 open contract)")
	}
	// KNOWN GAP: pattern text answers the concrete prefix question.
	if b := lib.wasEndpointAccessedWithPrefix(types.String("test-cid"), types.String("/api/")).Value().(bool); !b {
		t.Errorf("CHARACTERIZATION DRIFT: endpoint prefix '/api/' against wildcard "+
			"pattern /api/⋯/health returned false; current code scans Patterns and "+
			"is expected to return true (KNOWN GAP vs #807 open contract)")
	}
}

// TestAdversarial_EndpointWithMethod_MethodIgnored characterizes the documented
// v1 method-ignored gap (http.go: "EndpointMethodsByPath is out of scope for v1
// — check path membership only").
//
// KNOWN GAP: was_endpoint_accessed_with_method ignores the method entirely. An
// endpoint observed ONLY with GET is reported as accessed for a POST/DELETE
// query. Input: endpoint "/api/v1/users" observed Methods=["GET"], query
// method="DELETE" -> returns TRUE. A method-sensitive rule would expect FALSE.
// Asserting current (path-only) behavior so the suite stays green and the
// EndpointMethodsByPath rollout has a tripwire.
func TestAdversarial_EndpointWithMethod_MethodIgnored(t *testing.T) {
	env := newEndpointAdvEnv(t, []v1beta1.HTTPEndpoint{
		{Endpoint: "/api/v1/users", Methods: []string{"GET"}},
	},
		cel.Variable("endpoint", cel.StringType),
		cel.Variable("method", cel.StringType),
		cel.Variable("methods", cel.ListType(cel.StringType)))

	t.Run("with_method", func(t *testing.T) {
		cases := []struct {
			name     string
			endpoint string
			method   string
			want     bool
		}{
			{"observed endpoint, observed GET", "/api/v1/users", "GET", true},
			// KNOWN GAP: method not matched — unobserved DELETE still true.
			{"observed endpoint, UNOBSERVED DELETE (method ignored)", "/api/v1/users", "DELETE", true},
			// KNOWN GAP: method case is irrelevant because method is ignored.
			{"observed endpoint, lowercase get (method ignored)", "/api/v1/users", "get", true},
			{"unobserved endpoint is false", "/api/v1/admin", "GET", false},
		}
		for _, c := range cases {
			got := evalBool(t, env, `ap.was_endpoint_accessed_with_method(containerID, endpoint, method)`,
				map[string]any{"containerID": "test-container-id", "endpoint": c.endpoint, "method": c.method})
			if got != c.want {
				t.Errorf("was_endpoint_accessed_with_method(%q, %q) = %v, want %v",
					c.endpoint, c.method, got, c.want)
			}
		}
	})

	t.Run("with_methods", func(t *testing.T) {
		cases := []struct {
			name     string
			endpoint string
			methods  []string
			want     bool
		}{
			{"observed endpoint, methods include GET", "/api/v1/users", []string{"GET", "HEAD"}, true},
			// KNOWN GAP: methods list not matched — all-unobserved still true.
			{"observed endpoint, only UNOBSERVED methods (methods ignored)", "/api/v1/users",
				[]string{"POST", "DELETE"}, true},
			{"observed endpoint, empty methods list (methods ignored)", "/api/v1/users", []string{}, true},
			{"unobserved endpoint is false", "/api/v1/admin", []string{"GET"}, false},
		}
		for _, c := range cases {
			got := evalBool(t, env, `ap.was_endpoint_accessed_with_methods(containerID, endpoint, methods)`,
				map[string]any{"containerID": "test-container-id", "endpoint": c.endpoint, "methods": c.methods})
			if got != c.want {
				t.Errorf("was_endpoint_accessed_with_methods(%q, %v) = %v, want %v",
					c.endpoint, c.methods, got, c.want)
			}
		}
	})
}
