package profiles

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testContainerProfile() *v1beta1.ContainerProfile {
	// A clean user-managed ContainerProfile per the migration contract:
	// metadata carries ONLY name + namespace. No lifecycle annotations,
	// no labels — the signature must cover identity + spec and nothing else.
	return &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user-cp",
			Namespace: "test-ns",
			UID:       "cp-uid-1",
		},
		Spec: v1beta1.ContainerProfileSpec{
			Architectures: []string{"amd64"},
			Execs: []v1beta1.ExecCalls{
				{Path: "/usr/bin/curl", Args: []string{"/usr/bin/curl"}},
			},
			Syscalls: []string{"connect", "socket"},
			LabelSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "curl"},
			},
			Egress: []v1beta1.NetworkNeighbor{
				{
					Identifier: "vendor",
					Type:       "external",
					DNSNames:   []string{"example.com."},
				},
			},
		},
	}
}

func TestContainerProfileAdapter(t *testing.T) {
	cp := testContainerProfile()
	adapter := NewContainerProfileAdapter(cp)

	if adapter.GetName() != "user-cp" || adapter.GetNamespace() != "test-ns" || adapter.GetUID() != "cp-uid-1" {
		t.Fatalf("identity getters wrong: %s/%s uid=%s", adapter.GetNamespace(), adapter.GetName(), adapter.GetUID())
	}

	content, ok := adapter.GetContent().(map[string]interface{})
	if !ok {
		t.Fatalf("GetContent did not return a map")
	}
	if content["kind"] != "ContainerProfile" {
		t.Errorf("content kind = %v, want ContainerProfile", content["kind"])
	}
	if content["apiVersion"] != "spdx.softwarecomposition.kubescape.io/v1beta1" {
		t.Errorf("content apiVersion = %v", content["apiVersion"])
	}
	// Annotations must NOT appear in the signed content — they carry the
	// signature itself plus storage bookkeeping (sync-checksum etc.).
	if _, present := content["annotations"]; present {
		t.Errorf("annotations leaked into signed content")
	}
	meta, _ := content["metadata"].(map[string]interface{})
	if meta == nil {
		t.Fatalf("content metadata missing")
	}
	if _, present := meta["annotations"]; present {
		t.Errorf("metadata.annotations leaked into signed content")
	}

	// GetContent must not mutate the wrapped profile (PolicyByRuleId is
	// normalized on a deep copy only).
	if cp.Spec.PolicyByRuleId != nil {
		t.Errorf("GetContent mutated the wrapped profile's PolicyByRuleId")
	}
}

func TestContainerProfileAdapterSignAndVerify(t *testing.T) {
	cp := testContainerProfile()
	adapter := NewContainerProfileAdapter(cp)

	if signature.IsSigned(adapter) {
		t.Fatalf("unsigned profile reported as signed")
	}
	if err := signature.SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("SignObjectDisableKeyless failed: %v", err)
	}
	if !signature.IsSigned(adapter) {
		t.Fatalf("post-Sign IsSigned returned false")
	}
	if err := signature.VerifyObjectAllowUntrusted(adapter); err != nil {
		t.Fatalf("VerifyObjectAllowUntrusted failed on untampered profile: %v", err)
	}

	// Tamper with the spec — verification must fail with the mismatch
	// sentinel (the only error class that raises R1016).
	cp.Spec.Egress[0].DNSNames = []string{"evil.example."}
	err := signature.VerifyObjectAllowUntrusted(adapter)
	if err == nil {
		t.Fatalf("verification passed on tampered profile")
	}
}

// TestContainerProfileAdapter_AnnotationsDoNotAffectSignature pins the
// robustness contract that makes clean user-managed CPs signable for good:
// annotations added AFTER signing — storage bookkeeping (sync-checksum,
// resource-size) or anything else — must never invalidate the signature,
// because the signed content excludes annotations entirely.
func TestContainerProfileAdapter_AnnotationsDoNotAffectSignature(t *testing.T) {
	cp := testContainerProfile()
	adapter := NewContainerProfileAdapter(cp)
	if err := signature.SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Simulate the storage apiserver's write-path additions.
	annotations := cp.GetAnnotations()
	annotations["kubescape.io/sync-checksum"] = "cec313bd6f0f47fa9d6b3b7c38482256"
	annotations["kubescape.io/resource-size"] = "33"
	cp.SetAnnotations(annotations)

	if err := signature.VerifyObjectAllowUntrusted(adapter); err != nil {
		t.Fatalf("storage-added annotations broke the signature: %v", err)
	}

	// Labels, by contrast, ARE part of the signed identity — adding one
	// after signing must fail verification.
	cp.Labels = map[string]string{"injected": "true"}
	if err := signature.VerifyObjectAllowUntrusted(adapter); err == nil {
		t.Fatalf("post-sign label injection went undetected — labels must be signature-covered")
	}
}
