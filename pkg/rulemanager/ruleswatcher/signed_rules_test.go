package ruleswatcher

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
)

// fakeK8sClient serves a fixed set of Rules objects from a fake dynamic client.
type fakeK8sClient struct {
	dyn dynamic.Interface
}

func (f *fakeK8sClient) GetWorkload(string, string, string) (k8sinterface.IWorkload, error) {
	return nil, nil
}

func (f *fakeK8sClient) CalculateWorkloadParentRecursive(k8sinterface.IWorkload) (string, string, error) {
	return "", "", nil
}

func (f *fakeK8sClient) GetKubernetesClient() kubernetes.Interface { return nil }
func (f *fakeK8sClient) GetDynamicClient() dynamic.Interface       { return f.dyn }

func newFakeK8sClient(t *testing.T, objs ...*typesv1.Rules) *fakeK8sClient {
	t.Helper()
	items := make([]runtime.Object, 0, len(objs))
	for _, o := range objs {
		u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(o)
		if err != nil {
			t.Fatalf("to unstructured: %v", err)
		}
		items = append(items, &unstructured.Unstructured{Object: u})
	}
	listKinds := map[schema.GroupVersionResource]string{typesv1.RuleGvr: "RuleList"}
	return &fakeK8sClient{dyn: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, items...)}
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return k
}

func rulesObj(name, namespace, class string, ruleIDs ...string) *typesv1.Rules {
	rules := make([]typesv1.Rule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, typesv1.Rule{Enabled: true, ID: id, Name: "rule-" + id})
	}
	labels := map[string]string{}
	if class != "" {
		labels[bundle.LabelRuleClass] = class
	}
	return &typesv1.Rules{
		TypeMeta:   metav1.TypeMeta{APIVersion: "kubescape.io/v1", Kind: "Rule"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Spec:       typesv1.RulesSpec{Rules: rules},
	}
}

func sign(t *testing.T, r *typesv1.Rules, key *ecdsa.PrivateKey) *typesv1.Rules {
	t.Helper()
	if err := signature.SignObject(profiles.NewRulesAdapter(r), signature.WithPrivateKey(key)); err != nil {
		t.Fatalf("sign %s: %v", r.Name, err)
	}
	return r
}

func signerOf(t *testing.T, r *typesv1.Rules) string {
	t.Helper()
	id, err := bundle.RulesSignerID(r)
	if err != nil {
		t.Fatalf("signer id: %v", err)
	}
	return id
}

// Rule signing disabled is the pre-existing behaviour: every enabled rule from
// every Rules object in every namespace is loaded, signed or not, and carries
// cluster-wide provenance so downstream namespace scoping is a no-op.
func TestSyncAllRulesFromCluster_SigningDisabled(t *testing.T) {
	unsigned := rulesObj("baseline", "kubescape", "", "R0001", "R0002")
	rogue := rulesObj("rogue", "attacker", "", "R0003")

	creator := rulecreator.NewRuleCreator()
	w := NewRulesWatcher(newFakeK8sClient(t, unsigned, rogue), creator, nil)

	if w.ruleSigningEnabled() {
		t.Fatal("rule signing must be disabled without a trust policy")
	}
	if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	all := creator.CreateAllRules()
	if len(all) != 3 {
		t.Fatalf("got %d rules, want 3 (unchanged pre-signing behaviour)", len(all))
	}
	for _, r := range all {
		if !r.ClusterWide || r.SourceNamespace != "" {
			t.Errorf("rule %s: want cluster-wide/unscoped provenance, got clusterWide=%v ns=%q", r.ID, r.ClusterWide, r.SourceNamespace)
		}
	}
}

// A policy that only configures ContainerProfile fragment classes must not turn
// rule signing on.
func TestSetTrustPolicy_ProfileOnlyPolicyKeepsSigningDisabled(t *testing.T) {
	w := NewRulesWatcher(newFakeK8sClient(t), rulecreator.NewRuleCreator(), nil)
	w.SetTrustPolicy(&bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{bundle.ClassBase: {}}})
	if w.ruleSigningEnabled() {
		t.Fatal("a policy without ruleClasses must leave rule signing disabled")
	}
	w.SetTrustPolicy(nil)
	if w.ruleSigningEnabled() {
		t.Fatal("nil policy must leave rule signing disabled")
	}
}

// With rule signing enabled the watcher fails closed: an unsigned or
// untrusted Rules object is dropped whole, so an attacker who can create a
// Rules object in any namespace cannot override or disable a cluster rule.
func TestSyncAllRulesFromCluster_SigningEnabledFailsClosed(t *testing.T) {
	vendor, operator, attacker := testKey(t), testKey(t), testKey(t)

	baseline := sign(t, rulesObj("baseline", "kubescape", string(bundle.RuleClassCluster), "R0001", "R0002"), vendor)
	nsFragment := sign(t, rulesObj("redis-tuning", "redis", string(bundle.RuleClassNamespace), "R0001"), operator)
	// Same shape as the real attack: a Rules object in an arbitrary namespace
	// that redefines R0001, signed with a key nobody trusts.
	rogueSigned := sign(t, rulesObj("rogue", "attacker", string(bundle.RuleClassCluster), "R0001"), attacker)
	rogueUnsigned := rulesObj("rogue-unsigned", "attacker", string(bundle.RuleClassCluster), "R0002")

	creator := rulecreator.NewRuleCreator()
	w := NewRulesWatcher(newFakeK8sClient(t, baseline, nsFragment, rogueSigned, rogueUnsigned), creator, nil)
	w.SetTrustPolicy(&bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{
		bundle.RuleClassCluster:   {Signers: []string{signerOf(t, baseline)}, AllowedRuleIDs: []string{"*"}},
		bundle.RuleClassNamespace: {Signers: []string{signerOf(t, nsFragment)}, AllowedRuleIDs: []string{"R0001"}},
	}})
	if !w.ruleSigningEnabled() {
		t.Fatal("rule signing must be enabled with a ruleClasses policy")
	}

	if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	all := creator.CreateAllRules()
	// 2 cluster rules + 1 namespace-scoped R0001; both rogue objects dropped.
	if len(all) != 3 {
		t.Fatalf("got %d rules, want 3: %+v", len(all), all)
	}
	var clusterR1, nsR1 int
	for _, r := range all {
		if r.SourceNamespace == "attacker" {
			t.Fatalf("rule from untrusted fragment was admitted: %+v", r)
		}
		if r.ID != "R0001" {
			continue
		}
		if r.ClusterWide {
			clusterR1++
			if r.SourceNamespace != "kubescape" {
				t.Errorf("cluster R0001 source namespace = %q", r.SourceNamespace)
			}
		} else {
			nsR1++
			if r.SourceNamespace != "redis" {
				t.Errorf("namespace R0001 source namespace = %q, want redis", r.SourceNamespace)
			}
		}
	}
	// The composite (namespace, ID) key in SyncRules is what lets both survive.
	if clusterR1 != 1 || nsR1 != 1 {
		t.Fatalf("want one cluster and one namespace R0001, got cluster=%d ns=%d", clusterR1, nsR1)
	}
}
