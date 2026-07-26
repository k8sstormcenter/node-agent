package profiles

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// ContainerProfileAdapter makes a v1beta1.ContainerProfile signable — the
// migrated "new way" user-authored profile (kubescape/node-agent#862), which
// replaces the legacy ApplicationProfile + NetworkNeighborhood pair.
//
// Signed content is the established shape shared by every profile adapter:
// {apiVersion, kind, metadata:{name, namespace, labels}, spec}. Annotations
// are deliberately EXCLUDED from the hash: they carry the signature itself
// (signature.kubescape.io/*) plus storage bookkeeping the apiserver adds on
// write (kubescape.io/sync-checksum, kubescape.io/resource-size). That
// exclusion is what makes clean user-managed ContainerProfiles — name +
// namespace only, per the migration contract — robustly signable: the hash
// covers exactly identity (name/namespace/labels) and behaviour (spec, which
// embeds the matchLabels workload selector), and nothing volatile.
type ContainerProfileAdapter struct {
	profile *v1beta1.ContainerProfile
}

func NewContainerProfileAdapter(profile *v1beta1.ContainerProfile) *ContainerProfileAdapter {
	return &ContainerProfileAdapter{
		profile: profile,
	}
}

func (a *ContainerProfileAdapter) GetAnnotations() map[string]string {
	// Read-only: must not mutate the wrapped object on read (see
	// ApplicationProfileAdapter.GetAnnotations).
	return a.profile.Annotations
}

func (a *ContainerProfileAdapter) SetAnnotations(annotations map[string]string) {
	a.profile.Annotations = annotations
}

func (a *ContainerProfileAdapter) GetUID() string {
	return string(a.profile.UID)
}

func (a *ContainerProfileAdapter) GetNamespace() string {
	return a.profile.Namespace
}

func (a *ContainerProfileAdapter) GetName() string {
	return a.profile.Name
}

func (a *ContainerProfileAdapter) GetContent() interface{} {
	// Work on a deep copy so signing/verification never mutates the wrapped
	// (often cached) profile. PolicyByRuleId is normalized (nil -> {}) on the
	// copy only, for a stable JSON representation — the ContainerProfile spec
	// carries a single map (unlike the AP's per-container maps).
	profile := a.profile.DeepCopy()
	if profile.Spec.PolicyByRuleId == nil {
		profile.Spec.PolicyByRuleId = make(map[string]v1beta1.RulePolicy)
	}

	apiVersion := profile.APIVersion
	if apiVersion == "" {
		apiVersion = "spdx.softwarecomposition.kubescape.io/v1beta1"
	}
	kind := profile.Kind
	if kind == "" {
		kind = "ContainerProfile"
	}
	return map[string]interface{}{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]interface{}{
			"name":      profile.Name,
			"namespace": profile.Namespace,
			"labels":    profile.Labels,
		},
		"spec": profile.Spec,
	}
}

func (a *ContainerProfileAdapter) GetUpdatedObject() interface{} {
	return a.profile
}
