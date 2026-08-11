package bundle

import (
	"crypto/ecdsa"
	"errors"
	"testing"

	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// rule is a minimal enabled Rule with the given ID.
func rule(id string, enabled bool) rulemanagertypesv1.Rule {
	return rulemanagertypesv1.Rule{
		Enabled: enabled,
		ID:      id,
		Name:    "rule-" + id,
	}
}

// rulesObject builds a class-labeled Rules object. The class label and the
// namespace are set BEFORE signing because both are inside the signed content
// (metadata.labels / metadata.namespace), so the signature binds them.
func rulesObject(name, namespace, class string, rules []rulemanagertypesv1.Rule) *rulemanagertypesv1.Rules {
	return &rulemanagertypesv1.Rules{
		TypeMeta: metav1.TypeMeta{APIVersion: "kubescape.io/v1", Kind: "Rules"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{LabelRuleClass: class},
		},
		Spec: rulemanagertypesv1.RulesSpec{Rules: rules},
	}
}

// signedRules builds a Rules object and signs it with key.
func signedRules(t *testing.T, name, namespace, class string, rules []rulemanagertypesv1.Rule, key *ecdsa.PrivateKey) *rulemanagertypesv1.Rules {
	t.Helper()
	r := rulesObject(name, namespace, class, rules)
	if err := signature.SignObject(profiles.NewRulesAdapter(r), signature.WithPrivateKey(key)); err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	return r
}

func rulesSignerIDOf(t *testing.T, r *rulemanagertypesv1.Rules) string {
	t.Helper()
	id, err := RulesSignerID(r)
	if err != nil {
		t.Fatalf("signer identity: %v", err)
	}
	return id
}

func rulePolicy(clusterSigner, nsSigner string, clusterIDs, nsIDs []string) TrustPolicy {
	return TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{
		RuleClassCluster:   {Signers: []string{clusterSigner}, AllowedRuleIDs: clusterIDs},
		RuleClassNamespace: {Signers: []string{nsSigner}, AllowedRuleIDs: nsIDs},
	}}
}

func TestRuleSigningEnabled(t *testing.T) {
	if (TrustPolicy{}).RuleSigningEnabled() {
		t.Error("empty policy must report rule signing disabled")
	}
	// A profile-only policy (the pre-existing shape) must NOT turn rule signing on.
	profileOnly := TrustPolicy{Classes: map[FragmentClass]ClassPolicy{ClassBase: {}}}
	if profileOnly.RuleSigningEnabled() {
		t.Error("policy without ruleClasses must report rule signing disabled")
	}
	withRules := TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{RuleClassCluster: {}}}
	if !withRules.RuleSigningEnabled() {
		t.Error("policy with ruleClasses must report rule signing enabled")
	}
}

func TestAdmitRulesFragment_ClusterHappyPath(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	frag := signedRules(t, "baseline", "kubescape", string(RuleClassCluster), []rulemanagertypesv1.Rule{rule("R0001", true), rule("R0002", true)}, vendor)
	nsFrag := signedRules(t, "redis-tuning", "redis", string(RuleClassNamespace), []rulemanagertypesv1.Rule{rule("R0001", true)}, operator)
	policy := rulePolicy(rulesSignerIDOf(t, frag), rulesSignerIDOf(t, nsFrag), []string{"R0001", "R0002"}, []string{"R0001"})

	got, err := AdmitRulesFragment(frag, policy)
	if err != nil {
		t.Fatalf("AdmitRulesFragment: %v", err)
	}
	if got.Class != RuleClassCluster {
		t.Errorf("class = %q, want %q", got.Class, RuleClassCluster)
	}
	if !got.ClusterWide {
		t.Error("cluster class fragment must be ClusterWide")
	}
	if got.Namespace != "kubescape" {
		t.Errorf("namespace = %q, want %q", got.Namespace, "kubescape")
	}
	if len(got.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(got.Rules))
	}
	if got.Signer != rulesSignerIDOf(t, frag) {
		t.Errorf("signer = %q", got.Signer)
	}
}

func TestAdmitRulesFragment_NamespaceHappyPath(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	clusterFrag := signedRules(t, "baseline", "kubescape", string(RuleClassCluster), []rulemanagertypesv1.Rule{rule("R0001", true)}, vendor)
	frag := signedRules(t, "redis-tuning", "redis", string(RuleClassNamespace), []rulemanagertypesv1.Rule{rule("R0001", false)}, operator)
	policy := rulePolicy(rulesSignerIDOf(t, clusterFrag), rulesSignerIDOf(t, frag), []string{"R0001"}, []string{"R0001"})

	got, err := AdmitRulesFragment(frag, policy)
	if err != nil {
		t.Fatalf("AdmitRulesFragment: %v", err)
	}
	if got.Class != RuleClassNamespace {
		t.Errorf("class = %q, want %q", got.Class, RuleClassNamespace)
	}
	if got.ClusterWide {
		t.Error("namespace class fragment must not be ClusterWide")
	}
	if got.Namespace != "redis" {
		t.Errorf("namespace = %q, want %q", got.Namespace, "redis")
	}
}

func TestAdmitRulesFragment_Unsigned(t *testing.T) {
	policy := rulePolicy("key:whatever", "key:whatever", []string{"*"}, []string{"*"})
	frag := rulesObject("unsigned", "redis", string(RuleClassNamespace), []rulemanagertypesv1.Rule{rule("R0001", true)})

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrFragmentUnsigned) {
		t.Fatalf("want ErrFragmentUnsigned, got %v", err)
	}
}

func TestAdmitRulesFragment_Tampered(t *testing.T) {
	// The canonical attack: flip a rule to disabled after the vendor signed it.
	key := genKey(t)
	frag := signedRules(t, "baseline", "kubescape", string(RuleClassCluster), []rulemanagertypesv1.Rule{rule("R0001", true)}, key)
	policy := rulePolicy(rulesSignerIDOf(t, frag), "key:none", []string{"*"}, []string{"*"})
	if _, err := AdmitRulesFragment(frag, policy); err != nil {
		t.Fatalf("precondition: fragment must admit before tampering: %v", err)
	}

	frag.Spec.Rules[0].Enabled = false

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrFragmentTampered) {
		t.Fatalf("want ErrFragmentTampered, got %v", err)
	}
}

func TestAdmitRulesFragment_TamperedNamespace(t *testing.T) {
	// Re-scoping a validly signed namespace fragment into another namespace must
	// not be possible: metadata.namespace is inside the signed content.
	key := genKey(t)
	frag := signedRules(t, "redis-tuning", "redis", string(RuleClassNamespace), []rulemanagertypesv1.Rule{rule("R0001", true)}, key)
	policy := rulePolicy("key:none", rulesSignerIDOf(t, frag), []string{"*"}, []string{"*"})

	frag.Namespace = "payments"

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrFragmentTampered) {
		t.Fatalf("want ErrFragmentTampered on re-scoped fragment, got %v", err)
	}
}

func TestAdmitRulesFragment_UntrustedSigner(t *testing.T) {
	vendor, attacker := genKey(t), genKey(t)
	trusted := signedRules(t, "baseline", "kubescape", string(RuleClassCluster), []rulemanagertypesv1.Rule{rule("R0001", true)}, vendor)
	frag := signedRules(t, "rogue", "kubescape", string(RuleClassCluster), []rulemanagertypesv1.Rule{rule("R0001", false)}, attacker)
	policy := rulePolicy(rulesSignerIDOf(t, trusted), "key:none", []string{"*"}, []string{"*"})

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrSignerNotTrusted) {
		t.Fatalf("want ErrSignerNotTrusted, got %v", err)
	}
}

func TestAdmitRulesFragment_RuleIDNotAllowed(t *testing.T) {
	key := genKey(t)
	frag := signedRules(t, "redis-tuning", "redis", string(RuleClassNamespace), []rulemanagertypesv1.Rule{rule("R0001", true), rule("R9999", true)}, key)
	policy := rulePolicy("key:none", rulesSignerIDOf(t, frag), []string{"*"}, []string{"R0001"})

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrRuleIDNotAllowed) {
		t.Fatalf("want ErrRuleIDNotAllowed, got %v", err)
	}
	if err == nil || !contains(err.Error(), "R9999") {
		t.Errorf("error must name the offending rule ID, got %v", err)
	}
}

func TestAdmitRulesFragment_ClassNotAllowed(t *testing.T) {
	key := genKey(t)
	frag := signedRules(t, "redis-tuning", "redis", string(RuleClassNamespace), []rulemanagertypesv1.Rule{rule("R0001", true)}, key)
	// Policy only knows the cluster class.
	policy := TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{
		RuleClassCluster: {Signers: []string{rulesSignerIDOf(t, frag)}, AllowedRuleIDs: []string{"*"}},
	}}

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrRuleClassNotAllowed) {
		t.Fatalf("want ErrRuleClassNotAllowed, got %v", err)
	}
}

func TestAdmitRulesFragment_NoClassLabel(t *testing.T) {
	key := genKey(t)
	frag := signedRules(t, "unclassed", "redis", "", []rulemanagertypesv1.Rule{rule("R0001", true)}, key)
	policy := rulePolicy(rulesSignerIDOf(t, frag), rulesSignerIDOf(t, frag), []string{"*"}, []string{"*"})

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrNoClass) {
		t.Fatalf("want ErrNoClass, got %v", err)
	}
}

func TestAdmitRulesFragment_WildcardRuleIDs(t *testing.T) {
	key := genKey(t)
	frag := signedRules(t, "baseline", "kubescape", string(RuleClassCluster), []rulemanagertypesv1.Rule{rule("R0001", true), rule("R4242", true), rule("anything", true)}, key)
	policy := TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{
		RuleClassCluster: {Signers: []string{rulesSignerIDOf(t, frag)}, AllowedRuleIDs: []string{"*"}},
	}}

	got, err := AdmitRulesFragment(frag, policy)
	if err != nil {
		t.Fatalf("wildcard AllowedRuleIDs must admit any ID: %v", err)
	}
	if len(got.Rules) != 3 {
		t.Errorf("got %d rules, want 3", len(got.Rules))
	}
}

func TestAdmitRulesFragment_NamespaceClassWithoutNamespace(t *testing.T) {
	key := genKey(t)
	frag := signedRules(t, "clusterscoped", "", string(RuleClassNamespace), []rulemanagertypesv1.Rule{rule("R0001", true)}, key)
	policy := TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{
		RuleClassNamespace: {Signers: []string{rulesSignerIDOf(t, frag)}, AllowedRuleIDs: []string{"*"}},
	}}

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrRuleNamespaceEmpty) {
		t.Fatalf("want ErrRuleNamespaceEmpty, got %v", err)
	}
}

func TestRuleClassPolicy_Allows(t *testing.T) {
	p := RuleClassPolicy{Signers: []string{"key:a"}, AllowedRuleIDs: []string{"R0001"}}
	if !p.allowsSigner("key:a") || p.allowsSigner("key:b") {
		t.Error("allowsSigner mismatch")
	}
	if !p.allowsRuleID("R0001") || p.allowsRuleID("R0002") {
		t.Error("allowsRuleID mismatch")
	}
	// The wildcard is only honoured in AllowedRuleIDs, never in Signers.
	w := RuleClassPolicy{Signers: []string{"*"}, AllowedRuleIDs: []string{"*"}}
	if !w.allowsRuleID("whatever") {
		t.Error("wildcard rule ID must match")
	}
	if !w.allowsSigner("*") || w.allowsSigner("key:a") {
		t.Error("signers must be matched literally, no wildcard")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
