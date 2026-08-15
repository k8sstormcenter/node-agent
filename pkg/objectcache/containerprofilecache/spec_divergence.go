package containerprofilecache

import (
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// reportSpecDivergence warns when a signed object's STORED spec no longer
// matches its embedded signed content: what kubectl shows is not what is
// enforced, in either direction. Observability only — never part of the
// admission decision, and a comparison failure reports nothing. One warning
// per distinct stored content (re-armed when the divergence clears or the
// stored content changes again). Path names and counts only, never values.
func (c *ContainerProfileCacheImpl) reportSpecDivergence(key string, cp *v1beta1.ContainerProfile, bundleName, ns string) {
	paths, storedHash, ok := bundle.FragmentStoredDivergence(cp)
	if !ok {
		return
	}
	if len(paths) == 0 {
		c.specDivergence.Delete(key)
		return
	}
	if prev, loaded := c.specDivergence.Load(key); loaded && prev.(string) == storedHash {
		return
	}
	c.specDivergence.Store(key, storedHash)
	logger.L().Warning("signed fragment stored spec diverges from the signed content: the stored spec is display-only and is NOT enforced; enforcement uses the signed content",
		helpers.String("fragment", cp.Name),
		helpers.String("bundle", bundleName),
		helpers.String("namespace", ns),
		helpers.String("divergingPaths", strings.Join(paths, ",")),
		helpers.Int("pathCount", len(paths)),
		helpers.String("hint", "the object was edited after signing; re-apply the signed artifact to realign what kubectl shows with what is enforced"))
	if c.signingEnforced() {
		c.emitDriftAlert(cp.Name, ns, strings.Join(paths, ","))
	}
}

// emitDriftAlert is the enforce-mode twin of the divergence warning: a
// distinct low-severity alert, deliberately NOT R1016 — R1016 keeps meaning
// "enforced content tampered", and drift is display-only by construction.
func (c *ContainerProfileCacheImpl) emitDriftAlert(profileName, namespace, paths string) {
	if c.tamperAlertExporter == nil {
		return
	}
	ruleFailure := &types.GenericRuleFailure{
		BaseRuntimeAlert: armotypes.BaseRuntimeAlert{
			AlertName:      "Signed profile drift",
			InfectedPID:    1,
			Severity:       2,
			FixSuggestions: "The stored spec of '" + profileName + "' in namespace '" + namespace + "' differs from its signed content on: " + paths + ". The stored spec is not enforced; re-apply the signed artifact.",
		},
		AlertType: armotypes.AlertTypeRule,
		RuntimeProcessDetails: armotypes.ProcessTree{
			ProcessTree: armotypes.Process{PID: 1, Comm: "node-agent"},
		},
		RuleAlert: armotypes.RuleAlert{
			RuleDescription: "Stored spec of signed profile '" + profileName + "' in namespace '" + namespace + "' diverges from the enforced signed content (paths: " + paths + ")",
		},
		RuntimeAlertK8sDetails: armotypes.RuntimeAlertK8sDetails{Namespace: namespace},
		RuleID:                 "R1017",
	}
	c.tamperAlertExporter.SendRuleAlert(ruleFailure)
}
