package containerprofilecache

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func bkey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func bfrag(t *testing.T, name, class string, spec v1beta1.ContainerProfileSpec, key *ecdsa.PrivateKey) *v1beta1.ContainerProfile {
	t.Helper()
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "redis",
			Labels: map[string]string{
				bundle.LabelBundle:        "redis",
				bundle.LabelFragmentClass: class,
			},
		},
		Spec: spec,
	}
	if err := signature.SignObject(profiles.NewContainerProfileAdapter(cp), signature.WithPrivateKey(key)); err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	return cp
}

func newBundleCacheClient(mock storage.ProfileClient, policy *bundle.TrustPolicy, key *ecdsa.PrivateKey, strict bool) *ContainerProfileCacheImpl {
	c := &ContainerProfileCacheImpl{
		storageClient: mock,
		rpcBudget:     time.Second,
		cfg:           config.Config{EnableSignatureVerification: strict},
	}
	c.SetBundleConfig(policy, key)
	return c
}

// end-to-end runtime path: list fragments from the (mock) store, verify,
// assemble, internally re-sign, and hand back a usable composite.
func TestAssembleUserBundle_Runtime_HappyPath(t *testing.T) {
	vendor, operator, cluster := bkey(t), bkey(t), bkey(t)

	port := int32(6379)
	base := bfrag(t, "redis", "base", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/opt/bitnami/redis/bin/redis-server", Args: []string{"redis-server"}}},
	}, vendor)
	adm := bfrag(t, "redis-ingress-client", "admission", v1beta1.ContainerProfileSpec{
		Ingress: []v1beta1.NetworkNeighbor{{
			Identifier:  "allowed-client",
			Type:        "internal",
			PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "redis-client"}},
			Ports:       []v1beta1.NetworkPort{{Name: "TCP-6379", Port: &port, Protocol: "TCP"}},
		}},
	}, operator)

	vendorID, err := bundle.SignerID(base)
	if err != nil {
		t.Fatal(err)
	}
	operatorID, err := bundle.SignerID(adm)
	if err != nil {
		t.Fatal(err)
	}
	policy := &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase:      {Signers: []string{vendorID}, AllowedSpecPaths: []string{"execs"}},
		bundle.ClassAdmission: {Signers: []string{operatorID}, AllowedSpecPaths: []string{"ingress"}},
	}}

	mock := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{base, adm}}
	c := newBundleCacheClient(mock, policy, cluster, true)

	composite, err := c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis")
	if err != nil {
		t.Fatalf("assembleUserBundle: %v", err)
	}
	if composite == nil {
		t.Fatal("expected a composite, got nil")
	}
	if len(composite.Spec.Execs) != 1 || len(composite.Spec.Ingress) != 1 {
		t.Errorf("composite not assembled: execs=%d ingress=%d", len(composite.Spec.Execs), len(composite.Spec.Ingress))
	}
	// The composite is internally re-signed and passes the flat verify gate.
	if !c.verifyUserContainerProfile(composite, "wlid://c/cluster/redis/Pod/redis") {
		t.Errorf("re-signed composite failed the flat verify gate")
	}
	// The composite's ResourceVersion is the bundle's Merkle root (stable content
	// hash) so the reconciler RV fast-skip works; re-assembly of unchanged
	// fragments must yield the same RV.
	if composite.ResourceVersion == "" {
		t.Error("composite.ResourceVersion must carry the bundle Merkle root")
	}
	again, err := c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis")
	if err != nil || again == nil {
		t.Fatalf("re-assembly failed: %v", err)
	}
	if again.ResourceVersion != composite.ResourceVersion {
		t.Errorf("re-assembly of unchanged fragments changed the root RV: %s vs %s", again.ResourceVersion, composite.ResourceVersion)
	}
}

// A single (non-fragment) user CP → assembleUserBundle returns (nil,nil) so the
// caller falls back to the single-CP path.
func TestAssembleUserBundle_Runtime_NotABundle(t *testing.T) {
	cluster := bkey(t)
	single := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "redis", Namespace: "redis"}, // no bundle/class labels
	}
	mock := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{single}}
	c := newBundleCacheClient(mock, &bundle.TrustPolicy{}, cluster, false)

	composite, err := c.assembleUserBundle(context.Background(), "redis", "redis", "wlid")
	if err != nil || composite != nil {
		t.Errorf("want (nil,nil) for a non-bundle; got (%v,%v)", composite, err)
	}
}

// A tampered fragment → error + R1016 emitted.
func TestAssembleUserBundle_Runtime_TamperedEmitsR1016(t *testing.T) {
	vendor, operator, cluster := bkey(t), bkey(t), bkey(t)
	base := bfrag(t, "redis", "base", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/bin/redis-server", Args: []string{"redis-server"}}},
	}, vendor)
	adm := bfrag(t, "redis-ingress-client", "admission", v1beta1.ContainerProfileSpec{
		Ingress: []v1beta1.NetworkNeighbor{{Identifier: "allowed-client", Type: "internal"}},
	}, operator)
	vendorID, _ := bundle.SignerID(base)
	operatorID, _ := bundle.SignerID(adm)
	policy := &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase:      {Signers: []string{vendorID}, AllowedSpecPaths: []string{"execs"}},
		bundle.ClassAdmission: {Signers: []string{operatorID}, AllowedSpecPaths: []string{"ingress"}},
	}}

	// Tamper base after signing.
	base.Spec.Execs[0].Path = "/bin/evil"

	mock := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{base, adm}}
	exporter := &captureExporter{}
	c := newBundleCacheClient(mock, policy, cluster, true)
	c.SetTamperAlertExporter(exporter)

	composite, err := c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis")
	if err == nil || composite != nil {
		t.Fatalf("want error + nil composite on tamper; got (%v,%v)", composite, err)
	}
	if got := len(exporter.ruleAlerts()); got != 1 {
		t.Errorf("want 1 R1016 alert on tampered bundle; got %d", got)
	}
}

// strippedListClient simulates the real storage server: List serves items from
// the metadata table WITHOUT the payload (spec-stripped); only Get returns the
// full object. Regression for the bug where assembly hashed the stripped items
// and flagged every signed fragment as tampered.
type strippedListClient struct {
	*storage.StorageHttpClientMock
}

func (s *strippedListClient) ListContainerProfiles(ctx context.Context, namespace string, opts metav1.ListOptions) (*v1beta1.ContainerProfileList, error) {
	full, err := s.StorageHttpClientMock.ListContainerProfiles(ctx, namespace, opts)
	if err != nil {
		return nil, err
	}
	out := &v1beta1.ContainerProfileList{}
	for _, item := range full.Items {
		stripped := v1beta1.ContainerProfile{ObjectMeta: *item.ObjectMeta.DeepCopy()}
		out.Items = append(out.Items, stripped)
	}
	return out, nil
}

func TestAssembleUserBundle_Runtime_SpecStrippedList(t *testing.T) {
	vendor, operator, cluster := bkey(t), bkey(t), bkey(t)
	base := bfrag(t, "redis", "base", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/bin/redis-server", Args: []string{"redis-server"}}},
	}, vendor)
	adm := bfrag(t, "redis-ingress-client", "admission", v1beta1.ContainerProfileSpec{
		Ingress: []v1beta1.NetworkNeighbor{{Identifier: "allowed-client", Type: "internal"}},
	}, operator)
	vendorID, _ := bundle.SignerID(base)
	operatorID, _ := bundle.SignerID(adm)
	policy := &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase:      {Signers: []string{vendorID}, AllowedSpecPaths: []string{"execs"}},
		bundle.ClassAdmission: {Signers: []string{operatorID}, AllowedSpecPaths: []string{"ingress"}},
	}}

	mock := &strippedListClient{&storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{base, adm}}}
	c := newBundleCacheClient(mock, policy, cluster, true)

	composite, err := c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis")
	if err != nil {
		t.Fatalf("assembly must survive a spec-stripped List (fetch full fragments via Get): %v", err)
	}
	if composite == nil || len(composite.Spec.Execs) != 1 || len(composite.Spec.Ingress) != 1 {
		t.Fatalf("composite not assembled from full fragments: %+v", composite)
	}
}

// selectorIgnoringClient simulates the real storage server's List, which
// IGNORES the label selector and returns every CP in the namespace. Regression
// for the cross-bundle pickup bug: without client-side membership filtering,
// any bundle name assembled ALL class-labeled fragments in the namespace.
type selectorIgnoringClient struct {
	*storage.StorageHttpClientMock
}

func (s *selectorIgnoringClient) ListContainerProfiles(ctx context.Context, namespace string, _ metav1.ListOptions) (*v1beta1.ContainerProfileList, error) {
	return s.StorageHttpClientMock.ListContainerProfiles(ctx, namespace, metav1.ListOptions{})
}

func TestAssembleUserBundle_Runtime_SelectorIgnoredByStorage(t *testing.T) {
	vendor, operator, cluster := bkey(t), bkey(t), bkey(t)
	base := bfrag(t, "redis", "base", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/bin/redis-server", Args: []string{"redis-server"}}},
	}, vendor)
	adm := bfrag(t, "redis-ingress-client", "admission", v1beta1.ContainerProfileSpec{
		Ingress: []v1beta1.NetworkNeighbor{{Identifier: "allowed-client", Type: "internal"}},
	}, operator)
	vendorID, _ := bundle.SignerID(base)
	operatorID, _ := bundle.SignerID(adm)
	policy := &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase:      {Signers: []string{vendorID}, AllowedSpecPaths: []string{"execs"}},
		bundle.ClassAdmission: {Signers: []string{operatorID}, AllowedSpecPaths: []string{"ingress"}},
	}}

	mock := &selectorIgnoringClient{&storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{base, adm}}}
	c := newBundleCacheClient(mock, policy, cluster, true)

	// Looking up a DIFFERENT bundle name in the same namespace must find NO
	// fragments (fall back to the single-CP path), not assemble redis's.
	composite, err := c.assembleUserBundle(context.Background(), "redis", "redis-client", "wlid://c/cluster/redis/Pod/client")
	if err != nil || composite != nil {
		t.Fatalf("foreign bundle name must resolve to no fragments; got (%v, %v)", composite, err)
	}

	// The real bundle still assembles from exactly its own fragments.
	composite, err = c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis")
	if err != nil || composite == nil {
		t.Fatalf("redis bundle must assemble: %v", err)
	}
	m, err := bundle.ManifestFromComposite(composite)
	if err != nil || len(m.Leaves) != 2 {
		t.Fatalf("composite must contain exactly redis's 2 fragments, got %v (%v)", m, err)
	}
}

// TestAssembleUserBundle_R1016_ReAlertsAfterRecovery pins that R1016 re-fires
// on a NEW tamper after a clean recovery — even when the tampered fragment set
// fingerprint recurs (delete/recreate resets resourceVersions). Regression for
// the dedup bug where a fingerprint key was stored but never cleared.
func TestAssembleUserBundle_R1016_ReAlertsAfterRecovery(t *testing.T) {
	vendor, cluster := bkey(t), bkey(t)
	mkOverlay := func(rv, path string) *v1beta1.ContainerProfile {
		cp := bfrag(t, "redis", "base", v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: path}}}, vendor)
		cp.ResourceVersion = rv
		return cp
	}
	base := mkOverlay("1", "/bin/ok")
	vendorID, _ := bundle.SignerID(base)
	policy := &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase: {Signers: []string{vendorID}, AllowedSpecPaths: []string{"execs"}},
	}}
	exporter := &captureExporter{}

	tamper := func(cp *v1beta1.ContainerProfile) {
		cp.Spec.Execs = append(cp.Spec.Execs, v1beta1.ExecCalls{Path: "/bin/evil"}) // break the signature
	}

	assembleWith := func(cp *v1beta1.ContainerProfile, c *ContainerProfileCacheImpl) {
		mock := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{cp}}
		c.storageClient = mock
		c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis")
	}

	c := &ContainerProfileCacheImpl{rpcBudget: time.Second, cfg: config.Config{EnableSignatureVerification: true}}
	c.SetBundleConfig(policy, cluster)
	c.SetTamperAlertExporter(exporter)

	// tamper (RV=1) → 1 alert
	t1 := mkOverlay("1", "/bin/ok")
	tamper(t1)
	assembleWith(t1, c)
	if got := len(exporter.ruleAlerts()); got != 1 {
		t.Fatalf("first tamper: want 1 R1016, got %d", got)
	}
	// clean recovery (RV=2) → state cleared, no new alert
	assembleWith(mkOverlay("2", "/bin/ok"), c)
	// NEW tamper whose fingerprint RECURS (RV back to 1 via delete/recreate) → must re-alert
	t2 := mkOverlay("1", "/bin/ok")
	tamper(t2)
	assembleWith(t2, c)
	if got := len(exporter.ruleAlerts()); got != 2 {
		t.Fatalf("re-tamper after recovery with recurring fingerprint: want 2 R1016, got %d", got)
	}
}
