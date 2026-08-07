package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Admissibility failure sentinels. ErrFragmentTampered is the one the caller
// should surface as an R1016 tamper alert; the rest are policy rejections.
var (
	ErrNoClass          = errors.New("fragment has no fragment-class label")
	ErrClassNotAllowed  = errors.New("fragment class not present in trust policy")
	ErrFragmentUnsigned = errors.New("fragment is not signed")
	ErrFragmentTampered = errors.New("fragment signature does not verify (tampered)")
	ErrSignerNotTrusted = errors.New("signer not permitted for this fragment class")
	ErrPathNotAllowed   = errors.New("fragment sets a spec path not permitted for its class")
	ErrEmptyBundle      = errors.New("bundle has no fragments")
)

type verifiedFragment struct {
	cp     *v1beta1.ContainerProfile
	class  FragmentClass
	signer string
	digest string
}

// admitFragment runs the full admissibility check on one fragment: it must be
// class-labeled, signed, verify cleanly, be signed by a class-trusted signer,
// and set only spec paths its class is allowed to contribute.
func admitFragment(cp *v1beta1.ContainerProfile, policy TrustPolicy) (verifiedFragment, error) {
	class := FragmentClass(cp.Labels[LabelFragmentClass])
	if class == "" {
		return verifiedFragment{}, fmt.Errorf("%w: %q", ErrNoClass, cp.Name)
	}
	cpol, ok := policy.Classes[class]
	if !ok {
		return verifiedFragment{}, fmt.Errorf("%w: class %q (fragment %q)", ErrClassNotAllowed, class, cp.Name)
	}

	adapter := profiles.NewContainerProfileAdapter(cp)
	if !signature.IsSigned(adapter) {
		return verifiedFragment{}, fmt.Errorf("%w: %q", ErrFragmentUnsigned, cp.Name)
	}
	if err := signature.VerifyObjectAllowUntrusted(adapter); err != nil {
		if errors.Is(err, signature.ErrSignatureMismatch) {
			return verifiedFragment{}, fmt.Errorf("%w: %q: %v", ErrFragmentTampered, cp.Name, err)
		}
		return verifiedFragment{}, fmt.Errorf("verify fragment %q: %w", cp.Name, err)
	}

	sig, err := signature.GetObjectSignature(adapter)
	if err != nil {
		return verifiedFragment{}, fmt.Errorf("read signature of %q: %w", cp.Name, err)
	}
	signer, err := signerIdentity(sig)
	if err != nil {
		return verifiedFragment{}, fmt.Errorf("signer identity of %q: %w", cp.Name, err)
	}
	if !cpol.allowsSigner(signer) {
		return verifiedFragment{}, fmt.Errorf("%w: signer %q, class %q (fragment %q)", ErrSignerNotTrusted, signer, class, cp.Name)
	}

	for _, p := range setSpecPaths(&cp.Spec) {
		if !cpol.allowsPath(p) {
			return verifiedFragment{}, fmt.Errorf("%w: class %q may not set spec.%s (fragment %q)", ErrPathNotAllowed, class, p, cp.Name)
		}
	}

	digest, err := contentDigest(cp)
	if err != nil {
		return verifiedFragment{}, fmt.Errorf("digest of %q: %w", cp.Name, err)
	}
	return verifiedFragment{cp: cp, class: class, signer: signer, digest: digest}, nil
}

// AssembleAndVerify verifies every fragment against the trust policy,
// deterministically assembles the admissible fragments into one composite
// ContainerProfile, and stamps the composite with a Merkle-bound bundle
// manifest. It fails closed: a single inadmissible or tampered fragment rejects
// the whole bundle (the returned error wraps the relevant sentinel).
//
// The composite is NOT yet internally signed — call SignComposite afterward with
// the cluster key so the R1016 tamper path protects the assembled result.
func AssembleAndVerify(name, namespace string, fragments []*v1beta1.ContainerProfile, policy TrustPolicy) (*v1beta1.ContainerProfile, *BundleManifest, error) {
	if len(fragments) == 0 {
		return nil, nil, ErrEmptyBundle
	}

	verified := make([]verifiedFragment, 0, len(fragments))
	for _, f := range fragments {
		vf, err := admitFragment(f, policy)
		if err != nil {
			return nil, nil, err
		}
		verified = append(verified, vf)
	}

	// Canonical order: class precedence, then signer, then content digest. This
	// makes the composite (and its Merkle root) independent of input order.
	sort.SliceStable(verified, func(i, j int) bool {
		if pi, pj := classPrecedence(verified[i].class), classPrecedence(verified[j].class); pi != pj {
			return pi < pj
		}
		if verified[i].signer != verified[j].signer {
			return verified[i].signer < verified[j].signer
		}
		return verified[i].digest < verified[j].digest
	})

	spec := assembleSpec(verified)

	leaves := make([]LeafRef, len(verified))
	for i, vf := range verified {
		leaves[i] = LeafRef{Class: vf.class, Signer: vf.signer, Name: vf.cp.Name, ContentDigest: vf.digest}
	}
	manifest := &BundleManifest{Root: rootFromLeaves(leaves), Leaves: leaves}
	mb, err := json.Marshal(manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal manifest: %w", err)
	}

	composite := &v1beta1.ContainerProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "spdx.softwarecomposition.kubescape.io/v1beta1",
			Kind:       "ContainerProfile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      map[string]string{LabelBundle: name},
			Annotations: map[string]string{ManifestAnnotation: string(mb)},
		},
		Spec: spec,
	}
	return composite, manifest, nil
}

// SignComposite signs the assembled composite with the supplied key (the
// node-agent/cluster key) so the composite becomes a normally-signed CP that the
// R1016 tamper path re-verifies on every load.
func SignComposite(composite *v1beta1.ContainerProfile, opts ...signature.SignOption) error {
	return signature.SignObject(profiles.NewContainerProfileAdapter(composite), opts...)
}

// VerifyManifestRoot recomputes the Merkle root from a manifest's own leaves and
// checks it against the committed Root. A mismatch means the manifest's leaf set
// was altered (a fragment added/dropped/reordered) — a composite-tamper event.
func VerifyManifestRoot(manifest *BundleManifest) error {
	if manifest == nil {
		return fmt.Errorf("nil manifest")
	}
	if got := rootFromLeaves(manifest.Leaves); got != manifest.Root {
		return fmt.Errorf("bundle manifest root mismatch: committed %s, recomputed %s", manifest.Root, got)
	}
	return nil
}

// ManifestFromComposite extracts and parses the bundle manifest annotation.
func ManifestFromComposite(composite *v1beta1.ContainerProfile) (*BundleManifest, error) {
	if composite == nil || composite.Annotations == nil {
		return nil, fmt.Errorf("composite has no annotations")
	}
	raw, ok := composite.Annotations[ManifestAnnotation]
	if !ok {
		return nil, fmt.Errorf("composite has no %s annotation", ManifestAnnotation)
	}
	var m BundleManifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("parse bundle manifest: %w", err)
	}
	return &m, nil
}
