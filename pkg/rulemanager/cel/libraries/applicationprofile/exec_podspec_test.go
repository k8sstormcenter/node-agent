package applicationprofile

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

// newPodSpecExecEnv builds an apLibrary CEL env whose object cache carries an
// EMPTY application profile (so was_executed_with_args is forced down to the
// pod-spec fallback) plus the supplied pod spec, for the main container named
// "test-container".
func newPodSpecExecEnv(t *testing.T, podSpec *corev1.PodSpec) *cel.Env {
	t.Helper()
	return newPodSpecExecEnvTyped(t, objectcache.Container, "test-container", podSpec)
}

// newPodSpecExecEnvTyped is newPodSpecExecEnv parameterised by container type
// (Container / InitContainer / EphemeralContainer) and name, so the pod-spec
// fallback can be exercised for init and ephemeral containers too.
func newPodSpecExecEnvTyped(t *testing.T, ctype objectcache.ContainerType, cname string, podSpec *corev1.PodSpec) *cel.Env {
	t.Helper()
	objCache := objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: ctype,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			ctype: {{Name: cname}},
		},
	})
	// Empty Execs → no Values/Patterns/ExecsByPath entry for the path, so
	// wasExecutedWithArgs skips argv matching and reaches the pod-spec fallback.
	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: cname,
	})
	objCache.SetApplicationProfile(profile)
	objCache.SetPodSpec(podSpec)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("args", cel.ListType(cel.StringType)),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}
	return env
}

func evalWasExecutedWithArgs(t *testing.T, env *cel.Env, path string, args []string) bool {
	t.Helper()
	ast, issues := env.Compile(`ap.was_executed_with_args(containerID, path, args)`)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}
	prog, err := env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}
	out, _, err := prog.Eval(map[string]any{
		"containerID": "test-container-id",
		"path":        path,
		"args":        args,
	})
	if err != nil {
		t.Fatalf("failed to evaluate expression: %v", err)
	}
	return out.Value().(bool)
}

// TestExecWithArgs_PodSpecFallbackFullVector pins the contract flagged in the
// node-agent#805 review (2026-06-04): the pod-spec fallback in
// was_executed_with_args must compare the FULL runtime argv vector against the
// declared command vector, not just the executable path. Otherwise an exec of
// a declared binary with UNEXPECTED arguments is silently treated as allowed
// and R0040 ("Unexpected process arguments") never fires.
//
// expectedResult: true  = silent (argv matches the declared command — allowed)
//
//	false = R0040 must fire (argv differs from anything declared)
func TestExecWithArgs_PodSpecFallbackFullVector(t *testing.T) {
	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:    "test-container",
				Command: []string{"/bin/bash", "-c", "sleep infinity"},
			},
		},
	}
	env := newPodSpecExecEnv(t, podSpec)

	testCases := []struct {
		name           string
		path           string
		args           []string
		expectedResult bool
	}{
		{
			// The exact declared startup command is legitimately expected.
			name:           "exact declared command argv is allowed",
			path:           "/bin/bash",
			args:           []string{"/bin/bash", "-c", "sleep infinity"},
			expectedResult: true,
		},
		{
			// Review repro: extra -x flag. argv != declared command.
			name:           "extra -x flag must fire R0040",
			path:           "/bin/bash",
			args:           []string{"/bin/bash", "-x", "-c", "sleep infinity"},
			expectedResult: false,
		},
		{
			// Same binary, different trailing argument.
			name:           "different trailing arg must fire R0040",
			path:           "/bin/bash",
			args:           []string{"/bin/bash", "-c", "whoami"},
			expectedResult: false,
		},
		{
			// Bare binary, no args — declared command has args, so mismatch.
			name:           "bare binary (declared command has args) must fire R0040",
			path:           "/bin/bash",
			args:           []string{"/bin/bash"},
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalWasExecutedWithArgs(t, env, tc.path, tc.args)
			assert.Equal(t, tc.expectedResult, got,
				"was_executed_with_args(%s, %v): pod-spec fallback must match the full argv vector",
				tc.path, tc.args)
		})
	}
}

// TestExecWithArgs_PodSpecCommandArgsSplit covers the kubelet semantics where a
// container declares Command and Args separately: the executed argv is
// Command ++ Args, and the fallback must match against that concatenation.
func TestExecWithArgs_PodSpecCommandArgsSplit(t *testing.T) {
	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:    "test-container",
				Command: []string{"/bin/bash"},
				Args:    []string{"-c", "sleep infinity"},
			},
		},
	}
	env := newPodSpecExecEnv(t, podSpec)

	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"command++args concatenation is allowed", []string{"/bin/bash", "-c", "sleep infinity"}, true},
		{"extra flag must fire R0040", []string{"/bin/bash", "-x", "-c", "sleep infinity"}, false},
		{"only command part must fire R0040", []string{"/bin/bash"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, evalWasExecutedWithArgs(t, env, "/bin/bash", tc.args), tc.args)
		})
	}
}

// TestExecWithArgs_PodSpecImageEntrypointNoMatch pins that when a container
// declares NO Command (the image ENTRYPOINT, invisible from the pod spec), the
// fallback must NOT claim a match — otherwise it would silently allow arbitrary
// argv it cannot actually verify.
func TestExecWithArgs_PodSpecImageEntrypointNoMatch(t *testing.T) {
	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "test-container"}, // no Command/Args → image entrypoint
		},
	}
	env := newPodSpecExecEnv(t, podSpec)
	assert.False(t, evalWasExecutedWithArgs(t, env, "/bin/bash",
		[]string{"/bin/bash", "-c", "sleep infinity"}),
		"no declared Command → fallback must not claim a match")
}

// TestExecWithArgs_PodSpecLifecycleHooks covers PreStop / PostStart exec hooks:
// the declared hook command vector is allowed, anything else fires R0040.
func TestExecWithArgs_PodSpecLifecycleHooks(t *testing.T) {
	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:    "test-container",
				Command: []string{"/bin/bash", "-c", "sleep infinity"},
				Lifecycle: &corev1.Lifecycle{
					PreStop: &corev1.LifecycleHandler{
						Exec: &corev1.ExecAction{Command: []string{"/bin/sh", "-c", "nginx -s quit"}},
					},
					PostStart: &corev1.LifecycleHandler{
						Exec: &corev1.ExecAction{Command: []string{"/bin/sh", "-c", "echo started"}},
					},
				},
			},
		},
	}
	env := newPodSpecExecEnv(t, podSpec)

	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"prestop exact command allowed", []string{"/bin/sh", "-c", "nginx -s quit"}, true},
		{"poststart exact command allowed", []string{"/bin/sh", "-c", "echo started"}, true},
		{"prestop binary with different args fires R0040", []string{"/bin/sh", "-c", "rm -rf /"}, false},
		{"undeclared command fires R0040", []string{"/bin/sh", "-c", "curl evil"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, evalWasExecutedWithArgs(t, env, "/bin/sh", tc.args), tc.args)
		})
	}
}

// TestExecWithArgs_PodSpecInitContainer exercises the fallback for an init
// container (separate pod-spec list, resolved via shared-data ContainerType).
func TestExecWithArgs_PodSpecInitContainer(t *testing.T) {
	podSpec := &corev1.PodSpec{
		InitContainers: []corev1.Container{
			{
				Name:    "test-init",
				Command: []string{"/bin/sh", "-c", "init-setup"},
			},
		},
	}
	env := newPodSpecExecEnvTyped(t, objectcache.InitContainer, "test-init", podSpec)
	assert.True(t, evalWasExecutedWithArgs(t, env, "/bin/sh", []string{"/bin/sh", "-c", "init-setup"}),
		"init container declared command must be allowed")
	assert.False(t, evalWasExecutedWithArgs(t, env, "/bin/sh", []string{"/bin/sh", "-x", "-c", "init-setup"}),
		"init container argv mismatch must fire R0040")
}

// TestExecWithArgs_PodSpecEphemeralContainer exercises the fallback for an
// ephemeral container (debug container injected at runtime).
func TestExecWithArgs_PodSpecEphemeralContainer(t *testing.T) {
	podSpec := &corev1.PodSpec{
		EphemeralContainers: []corev1.EphemeralContainer{
			{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name:    "test-ephemeral",
					Command: []string{"/bin/sh", "-c", "debug"},
				},
			},
		},
	}
	env := newPodSpecExecEnvTyped(t, objectcache.EphemeralContainer, "test-ephemeral", podSpec)
	assert.True(t, evalWasExecutedWithArgs(t, env, "/bin/sh", []string{"/bin/sh", "-c", "debug"}),
		"ephemeral container declared command must be allowed")
	assert.False(t, evalWasExecutedWithArgs(t, env, "/bin/sh", []string{"/bin/sh", "-c", "exfiltrate"}),
		"ephemeral container argv mismatch must fire R0040")
}
