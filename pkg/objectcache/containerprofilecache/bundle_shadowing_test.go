package containerprofilecache

import (
	"context"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// classicalCP builds a user-defined ContainerProfile of the pre-bundle kind: no
// bundle label, no fragment-class label, no signature.
func classicalCP(name, ns, exec string) *v1beta1.ContainerProfile {
	return &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: v1beta1.ContainerProfileSpec{
			Architectures: []string{"amd64"},
			Execs:         []v1beta1.ExecCalls{{Path: exec}},
		},
	}
}

func bindToProfile(t *testing.T, c *ContainerProfileCacheImpl, id, profile string) {
	t.Helper()
	ev := eventContainer(id)
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: profile}
	require.NoError(t, c.addContainer(ev, context.Background()))
}

func execEnforced(c *ContainerProfileCacheImpl, id, path string) bool {
	p := c.GetProjectedContainerProfile(id)
	if p == nil {
		return false
	}
	_, ok := p.Execs.Values[path]
	return ok
}

// With bundles enabled but no fragment carrying the name, the label must still
// resolve the ContainerProfile of that name. This is the compatibility path for
// every user-defined profile that predates bundles.
func TestClassicalProfile_ResolvedByName_WhenNoBundleFragmentsExist(t *testing.T) {
	solo := classicalCP("solo-nginx", "default", "/bin/classical-only")

	mock := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{solo}}
	c, k8s := newTestCache(t, mock)
	c.SetBundleConfig(&bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase: {Signers: []string{"key:absent"}, AllowedSpecPaths: []string{"execs"}},
	}})

	id := "container-solo"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-solo")
	bindToProfile(t, c, id, "solo")

	require.True(t, execEnforced(c, id, "/bin/classical-only"),
		"a classical profile must still be resolved by name when no bundle of that name exists")
}

// When verifying fragments carry the same name, the composite is used and the
// identically named classical ContainerProfile is never read.
func TestClassicalProfile_ShadowedByVerifyingBundle(t *testing.T) {
	vendor := bkey(t)
	base := bfragIn(t, "shadow-base", "base", "default", "shadowed", v1beta1.ContainerProfileSpec{
		Architectures: []string{"amd64"},
		Execs:         []v1beta1.ExecCalls{{Path: "/bin/from-fragment"}},
	}, vendor)
	vendorID, err := bundle.SignerID(base)
	require.NoError(t, err)

	classical := classicalCP("shadowed-nginx", "default", "/bin/classical-only")

	mock := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{classical, base}}
	c, k8s := newTestCache(t, mock)
	c.SetBundleConfig(&bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase: {Signers: []string{vendorID}, AllowedSpecPaths: []string{"architectures", "execs"}},
	}})

	id := "container-shadowed"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-shadowed")
	bindToProfile(t, c, id, "shadowed")

	require.True(t, execEnforced(c, id, "/bin/from-fragment"),
		"the composite assembled from the bundle must be enforced")
	require.False(t, execEnforced(c, id, "/bin/classical-only"),
		"the identically named classical profile must not be read while the bundle assembles")
}

// A fragment set that fails verification must not fall back to the identically
// named classical ContainerProfile. A container with no prior projection is left
// without a user-defined profile rather than silently dropping to the unsigned
// object, so the create verb on containerprofiles can deny a profile but never
// substitute one.
func TestUnverifiableBundle_DoesNotFallBackToClassicalProfile(t *testing.T) {
	unsigned := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "denied-fragment",
			Namespace: "default",
			Labels: map[string]string{
				bundle.LabelBundle:        "denied",
				bundle.LabelFragmentClass: "base",
			},
		},
		Spec: v1beta1.ContainerProfileSpec{
			Execs: []v1beta1.ExecCalls{{Path: "/bin/injected"}},
		},
	}
	classical := classicalCP("denied-nginx", "default", "/bin/classical-only")

	mock := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{classical, unsigned}}
	c, k8s := newTestCache(t, mock)
	c.SetBundleConfig(&bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase: {Signers: []string{"key:absent"}, AllowedSpecPaths: []string{"execs"}},
	}})

	id := "container-denied"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-denied")
	bindToProfile(t, c, id, "denied")

	require.False(t, execEnforced(c, id, "/bin/classical-only"),
		"an unverifiable fragment set must not fall back to the identically named classical profile")
	require.False(t, execEnforced(c, id, "/bin/injected"),
		"the unverifiable fragment's own content must never be enforced")
}
