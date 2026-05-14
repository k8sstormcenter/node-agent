package containerprofilecache

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/callstackcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestT32_UserOverlayExecsReachProjectedValues pins the contract that
// Test_32_UnexpectedProcessArguments depends on end-to-end: when a user-
// defined ApplicationProfile overlay supplies Execs entries for a
// container, those paths MUST appear in the projected ContainerProfile's
// Execs.Values so ap.was_executed lookups succeed and R0001 stays
// silent on user-allowed paths.
//
// Test_32 has been failing on the R0001-silence precondition even after
// the bare-name path enumeration in the test's profile. That can only
// happen if one of these projection steps drops the entries:
//
//  1. projectUserProfiles → mergeApplicationProfile fails to copy
//     userAP.Spec.Containers[i].Execs into projected.Spec.Execs
//  2. Apply → extractExecsPaths walks projected.Spec.Execs[i].Path but
//     misses entries
//  3. projectField → entries end up in Patterns or get filtered out
//     instead of landing in Values
//
// This test stresses (1)+(2)+(3) end-to-end with an empty baseline
// (mirrors the real Test_32 scenario where the agent's recording side
// correctly skips learning for user-defined-profile containers).
func TestT32_UserOverlayExecsReachProjectedValues(t *testing.T) {
	// Empty baseline ContainerProfile (matches what the reconciler
	// synthesises when no baseline exists for a user-defined-profile-
	// labelled container).
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replicaset-curl-32-6d44f5f86b",
			Namespace: "ns",
		},
	}

	// User-defined AP with the same Execs shape Test_32 uses
	// (post-c3b692ed, both full-path and bare-name variants).
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "curl-32-overlay", Namespace: "ns"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name: "curl",
					Execs: []v1beta1.ExecCalls{
						{Path: "/bin/sh", Args: []string{"sh", "-c", "*"}},
						{Path: "sh", Args: []string{"sh", "-c", "*"}},
						{Path: "/bin/echo", Args: []string{"echo", "hello", "*"}},
					},
				},
			},
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "curl"}},
		},
	}

	merged, _ := projectUserProfiles(cp, userAP, nil, pod, "curl")
	if merged == nil {
		t.Fatalf("projectUserProfiles returned nil")
	}

	// After merge, projected.Spec.Execs must contain all 3 user-overlay
	// Execs paths.
	gotPaths := map[string]bool{}
	for _, e := range merged.Spec.Execs {
		gotPaths[e.Path] = true
	}
	wantPaths := []string{"/bin/sh", "sh", "/bin/echo"}
	for _, p := range wantPaths {
		if !gotPaths[p] {
			t.Errorf("merge failed: path %q missing from merged.Spec.Execs (got: %v)", p, gotPaths)
		}
	}

	// Apply with a default RuleProjectionSpec (InUse=false → All=true →
	// pass-through; matches what R0001 hits when no rule declares a
	// specific Execs requirement).
	spec := &objectcache.RuleProjectionSpec{}
	tree := callstackcache.NewCallStackSearchTree()
	projected := Apply(spec, merged, tree)

	if projected == nil {
		t.Fatal("Apply returned nil")
	}
	if projected.Execs.Values == nil {
		t.Fatalf("projected.Execs.Values is nil — projection dropped all entries")
	}
	for _, p := range wantPaths {
		if _, ok := projected.Execs.Values[p]; !ok {
			t.Errorf("projection dropped %q: projected.Execs.Values=%v", p, projected.Execs.Values)
		}
	}

	// ExecsByPath is the path → args map used by R0040's
	// was_executed_with_args. Must also carry all 3 user paths.
	for _, p := range wantPaths {
		if _, ok := projected.ExecsByPath[p]; !ok {
			t.Errorf("ExecsByPath missing path %q (got keys: %v)", p, mapKeys(projected.ExecsByPath))
		}
	}
}

func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
