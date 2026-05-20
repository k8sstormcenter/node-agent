package applicationprofile

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
)


// BenchmarkWasExecutedWithArgs covers the R0040 hot path in the four
// representative shapes:
//
//   - exact_path_args_match:    literal path in Values + matching argv
//   - exact_path_args_mismatch: literal path in Values + mismatching argv
//                               (post-tier-2 fix: returns false without
//                                falling through to pattern matching)
//   - pattern_path_args_match:  path absent from Values, matches a Pattern,
//                               ExecsByPath has the matching argv
//   - no_match:                 path absent from Values AND no Pattern
//                               matches (terminal false)
//
// Reports allocs/op for the steady-state matcher. The CEL value-wrapping
// floor is unchanged by this PR — only the exec.go control flow changed
// (no fall-through on exact-path strict-args mismatch).
func BenchmarkWasExecutedWithArgs(b *testing.B) {
	values := map[string]struct{}{
		"/usr/bin/curl":   {},
		"/usr/sbin/sshd":  {},
		"/bin/ls":         {},
		"/usr/bin/python": {},
	}
	patterns := []string{
		"/usr/local/bin/⋯",
		"/opt/⋯/bin/⋯",
	}
	execsByPath := map[string][]string{
		"/usr/bin/curl":   {"-X", "GET", "*"},
		"/usr/sbin/sshd":  {"-D"},
		"/bin/ls":         {"-la", "⋯"},
		"/usr/bin/python": {"⋯", "*"},
		"/usr/local/bin/⋯": {"*"},
		"/opt/⋯/bin/⋯":     {"*"},
	}
	pcp := &objectcache.ProjectedContainerProfile{
		Execs: objectcache.ProjectedField{
			All:      true,
			Values:   values,
			Patterns: patterns,
		},
		ExecsByPath: execsByPath,
	}
	lib := &apLibrary{objectCache: &mockObjectCacheForPattern{pcp: pcp}}

	cases := []struct {
		name, path string
		args       []string
	}{
		{"exact_path_args_match", "/usr/bin/curl", []string{"-X", "GET", "https://api.example.com"}},
		{"exact_path_args_mismatch", "/usr/bin/curl", []string{"-X", "DELETE", "https://api.example.com"}},
		{"pattern_path_args_match", "/usr/local/bin/myhelper", []string{"--config", "/etc/myhelper.yaml"}},
		// `no_match` would fall through to isExecInPodSpec which needs
		// K8sObjectCache wiring — out of scope for a matcher bench.
	}
	cid := types.String("bench-cid")
	for _, c := range cases {
		path := types.String(c.path)
		// Encode argv as a CEL list — let the matcher parse it like
		// the real CEL call site does.
		argsRefVal := types.NewStringList(types.DefaultTypeAdapter, c.args)
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = lib.wasExecutedWithArgs(cid, path, argsRefVal)
			}
		})
	}
}
