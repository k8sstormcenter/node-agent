package applicationprofile

import (
	"testing"

	"github.com/google/cel-go/cel"
	corev1 "k8s.io/api/core/v1"
)

func evalWasExecutedPathOnly(t *testing.T, env *cel.Env, path string) bool {
	t.Helper()
	ast, iss := env.Compile(`ap.was_executed(containerID, path)`)
	if iss != nil && iss.Err() != nil {
		t.Fatalf("compile: %v", iss.Err())
	}
	prog, err := env.Program(ast)
	if err != nil {
		t.Fatalf("program: %v", err)
	}
	out, _, err := prog.Eval(map[string]any{"containerID": "test-container-id", "path": path})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	return out.Value().(bool)
}

// TestWasExecuted_PodSpecPathFallback covers isExecInPodSpec — the path-only
// pod-spec fallback of was_executed (R0001). With an empty profile, was_executed
// falls through to the pod spec: a path declared in the container Command or a
// lifecycle Exec hook is "expected" (no R0001), anything else is not. This arm
// was at ~12% unit coverage (CT-only).
func TestWasExecuted_PodSpecPathFallback(t *testing.T) {
	// NOTE: the preStop branch of isExecInPodSpec is deliberately NOT exercised
	// here — matching a preStop hook marks the container in a process-shared
	// preStopCache, which would leak into other tests (was_executed then
	// short-circuits to true for that container ID). preStop behaviour is
	// covered by prestop_cache_test.go. This test pins the Command-vector arm.
	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{{
			Name:    "test-container",
			Command: []string{"/bin/bash", "-c", "sleep infinity"},
		}},
	}
	env := newPodSpecExecEnv(t, podSpec)

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"command path is in pod spec", "/bin/bash", true},
		{"unknown path is not in pod spec", "/usr/bin/evil", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := evalWasExecutedPathOnly(t, env, c.path); got != c.want {
				t.Errorf("was_executed(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}
