package bundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return k
}

// fragment builds a class-labeled ContainerProfile and signs it with key.
// Labels are set BEFORE signing because they are part of the signed content
// (metadata.labels), so the signature binds the fragment's class.
func fragment(t *testing.T, name, class string, spec v1beta1.ContainerProfileSpec, key *ecdsa.PrivateKey) *v1beta1.ContainerProfile {
	t.Helper()
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "redis",
			Labels: map[string]string{
				LabelBundle:        "redis",
				LabelFragmentClass: class,
			},
		},
		Spec: spec,
	}
	if err := signature.SignObject(profiles.NewContainerProfileAdapter(cp), signature.WithPrivateKey(key)); err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	return cp
}

func signerIDOf(t *testing.T, cp *v1beta1.ContainerProfile) string {
	t.Helper()
	sig, err := signature.GetObjectSignature(profiles.NewContainerProfileAdapter(cp))
	if err != nil {
		t.Fatalf("get signature: %v", err)
	}
	id, err := signerIdentity(sig)
	if err != nil {
		t.Fatalf("signer identity: %v", err)
	}
	return id
}

// baseSpec is a vendor default: execs/opens, no ingress (cp-redis.yaml shape).
func baseSpec() v1beta1.ContainerProfileSpec {
	return v1beta1.ContainerProfileSpec{
		Architectures: []string{"amd64"},
		Execs:         []v1beta1.ExecCalls{{Path: "/opt/bitnami/redis/bin/redis-server", Args: []string{"redis-server"}}},
		Opens:         []v1beta1.OpenCalls{{Path: "/data/dump.rdb", Flags: []string{"O_RDWR"}}},
	}
}

// admissionSpec is the "allowlist a client later" ingress fragment (DEMO.md §5).
func admissionSpec() v1beta1.ContainerProfileSpec {
	port := int32(6379)
	return v1beta1.ContainerProfileSpec{
		Ingress: []v1beta1.NetworkNeighbor{{
			Identifier:        "allowed-client",
			Type:              "internal",
			PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "redis-client"}},
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "redis"}},
			Ports:             []v1beta1.NetworkPort{{Name: "TCP-6379", Port: &port, Protocol: "TCP"}},
		}},
	}
}

func redisPolicy(vendorID, operatorID string) TrustPolicy {
	return TrustPolicy{Classes: map[FragmentClass]ClassPolicy{
		ClassBase:      {Signers: []string{vendorID}, AllowedSpecPaths: []string{"architectures", "capabilities", "execs", "opens", "syscalls", "rulePolicies", "endpoints", "seccompProfile", "imageID", "imageTag", "identifiedCallStacks", "labelSelector"}},
		ClassAdmission: {Signers: []string{operatorID}, AllowedSpecPaths: []string{"ingress", "egress"}},
	}}
}

func TestAssembleAndVerify_HappyPath(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	base := fragment(t, "redis", "base", baseSpec(), vendor)
	adm := fragment(t, "redis-ingress-client", "admission", admissionSpec(), operator)
	policy := redisPolicy(signerIDOf(t, base), signerIDOf(t, adm))

	composite, manifest, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	// Composite carries the base's execs AND the admission's ingress.
	if len(composite.Spec.Execs) != 1 || composite.Spec.Execs[0].Path != "/opt/bitnami/redis/bin/redis-server" {
		t.Errorf("composite missing base execs: %+v", composite.Spec.Execs)
	}
	if len(composite.Spec.Ingress) != 1 || composite.Spec.Ingress[0].Identifier != "allowed-client" {
		t.Errorf("composite missing admission ingress: %+v", composite.Spec.Ingress)
	}
	if len(manifest.Leaves) != 2 {
		t.Fatalf("manifest has %d leaves; want 2", len(manifest.Leaves))
	}
	if err := VerifyManifestRoot(manifest); err != nil {
		t.Errorf("manifest root: %v", err)
	}
	// Round-trip the manifest from the composite annotation.
	got, err := ManifestFromComposite(composite)
	if err != nil {
		t.Fatalf("ManifestFromComposite: %v", err)
	}
	if got.Root != manifest.Root {
		t.Errorf("round-tripped root %s != %s", got.Root, manifest.Root)
	}

	// Internal re-sign: node-agent signs the composite with the cluster key, and
	// it then verifies as a normal signed CP (the R1016 tamper path input).
	cluster := genKey(t)
	if err := SignComposite(composite, signature.WithPrivateKey(cluster)); err != nil {
		t.Fatalf("SignComposite: %v", err)
	}
	if err := signature.VerifyObjectAllowUntrusted(profiles.NewContainerProfileAdapter(composite)); err != nil {
		t.Errorf("composite does not verify after internal re-sign: %v", err)
	}
}

func TestAssembleAndVerify_OrderIndependent(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	base := fragment(t, "redis", "base", baseSpec(), vendor)
	adm := fragment(t, "redis-ingress-client", "admission", admissionSpec(), operator)
	policy := redisPolicy(signerIDOf(t, base), signerIDOf(t, adm))

	_, m1, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if err != nil {
		t.Fatal(err)
	}
	_, m2, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{adm, base}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if m1.Root != m2.Root {
		t.Errorf("root depends on input order: %s vs %s", m1.Root, m2.Root)
	}
}

func TestAssembleAndVerify_Tampered(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	base := fragment(t, "redis", "base", baseSpec(), vendor)
	adm := fragment(t, "redis-ingress-client", "admission", admissionSpec(), operator)
	policy := redisPolicy(signerIDOf(t, base), signerIDOf(t, adm))

	// Tamper the base fragment's spec after signing.
	base.Spec.Execs[0].Path = "/bin/evil"

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if !errors.Is(err, ErrFragmentTampered) {
		t.Errorf("want ErrFragmentTampered, got %v", err)
	}
}

func TestAssembleAndVerify_UntrustedSigner(t *testing.T) {
	vendor, operator, attacker := genKey(t), genKey(t), genKey(t)
	base := fragment(t, "redis", "base", baseSpec(), vendor)
	// Policy trusts the operator for admission fragments.
	operatorID := signerIDOf(t, fragment(t, "op-probe", "admission", admissionSpec(), operator))
	policy := redisPolicy(signerIDOf(t, base), operatorID)
	// But the admission fragment is signed by an attacker key not in the policy.
	adm := fragment(t, "redis-ingress-client", "admission", admissionSpec(), attacker)

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if !errors.Is(err, ErrSignerNotTrusted) {
		t.Errorf("want ErrSignerNotTrusted, got %v", err)
	}
}

func TestAssembleAndVerify_ClassConfinement(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	base := fragment(t, "redis", "base", baseSpec(), vendor)
	// An admission-class fragment that illegally sets execs (server-side code),
	// signed by the trusted operator key — must still be rejected on path.
	badSpec := admissionSpec()
	badSpec.Execs = []v1beta1.ExecCalls{{Path: "/bin/backdoor", Args: []string{"backdoor"}}}
	adm := fragment(t, "redis-ingress-client", "admission", badSpec, operator)
	policy := redisPolicy(signerIDOf(t, base), signerIDOf(t, adm))

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if !errors.Is(err, ErrPathNotAllowed) {
		t.Errorf("want ErrPathNotAllowed, got %v", err)
	}
}

func TestAssembleAndVerify_Unsigned(t *testing.T) {
	vendor := genKey(t)
	base := fragment(t, "redis", "base", baseSpec(), vendor)
	// Unsigned admission fragment.
	adm := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-ingress-client", Namespace: "redis",
			Labels: map[string]string{LabelBundle: "redis", LabelFragmentClass: "admission"}},
		Spec: admissionSpec(),
	}
	policy := redisPolicy(signerIDOf(t, base), "unused")

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if !errors.Is(err, ErrFragmentUnsigned) {
		t.Errorf("want ErrFragmentUnsigned, got %v", err)
	}
}
