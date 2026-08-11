package cache

import (
	"testing"

	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

func clusterRule(id, name string) rulemanagertypesv1.Rule {
	return rulemanagertypesv1.Rule{ID: id, Name: name, Enabled: true, ClusterWide: true}
}

func nsRule(id, name, ns string) rulemanagertypesv1.Rule {
	return rulemanagertypesv1.Rule{ID: id, Name: name, Enabled: true, SourceNamespace: ns}
}

func ids(rules []rulemanagertypesv1.Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.ID)
	}
	return out
}

func TestScopeRulesToNamespace_ClusterRuleAppliesEverywhere(t *testing.T) {
	in := []rulemanagertypesv1.Rule{clusterRule("R0001", "baseline")}

	for _, ns := range []string{"redis", "payments", "default"} {
		got := scopeRulesToNamespace(in, ns)
		if len(got) != 1 || got[0].Name != "baseline" {
			t.Fatalf("namespace %q: got %+v, want the cluster rule", ns, ids(got))
		}
	}
}

func TestScopeRulesToNamespace_NamespaceRuleOnlyInItsNamespace(t *testing.T) {
	in := []rulemanagertypesv1.Rule{nsRule("R0002", "redis-only", "redis")}

	if got := scopeRulesToNamespace(in, "redis"); len(got) != 1 || got[0].Name != "redis-only" {
		t.Fatalf("in own namespace: got %+v, want the namespace rule", ids(got))
	}
	if got := scopeRulesToNamespace(in, "payments"); len(got) != 0 {
		t.Fatalf("outside its namespace: got %+v, want none", ids(got))
	}
}

func TestScopeRulesToNamespace_NamespaceOverridesClusterRule(t *testing.T) {
	in := []rulemanagertypesv1.Rule{
		clusterRule("R0001", "cluster-baseline"),
		nsRule("R0001", "redis-override", "redis"),
		clusterRule("R0003", "other"),
	}

	got := scopeRulesToNamespace(in, "redis")
	if len(got) != 2 {
		t.Fatalf("in redis: got %+v, want 2 rules", ids(got))
	}
	if got[0].ID != "R0001" || got[0].Name != "redis-override" {
		t.Errorf("in redis: R0001 must be the namespace override, got %q", got[0].Name)
	}
	if got[1].ID != "R0003" {
		t.Errorf("in redis: expected R0003 second, got %q", got[1].ID)
	}

	// Elsewhere the cluster rule is untouched and the override is invisible.
	got = scopeRulesToNamespace(in, "payments")
	if len(got) != 2 {
		t.Fatalf("in payments: got %+v, want 2 rules", ids(got))
	}
	if got[0].Name != "cluster-baseline" {
		t.Errorf("in payments: R0001 must stay the cluster rule, got %q", got[0].Name)
	}
}

func TestScopeRulesToNamespace_OverrideRegardlessOfInputOrder(t *testing.T) {
	// The namespace rule must win whether it is listed before or after the
	// cluster rule (the watcher's list order is not stable).
	nsFirst := []rulemanagertypesv1.Rule{
		nsRule("R0001", "redis-override", "redis"),
		clusterRule("R0001", "cluster-baseline"),
	}
	got := scopeRulesToNamespace(nsFirst, "redis")
	if len(got) != 1 || got[0].Name != "redis-override" {
		t.Fatalf("namespace-first: got %+v", got)
	}
}

func TestScopeRulesToNamespace_NoProvenanceUnchanged(t *testing.T) {
	// Rule signing disabled: the watcher stamps ClusterWide=true and an empty
	// SourceNamespace, so scoping is an exact pass-through in every namespace —
	// including duplicate IDs contributed by two rule bindings with different
	// prefilter parameters, which must NOT be collapsed.
	in := []rulemanagertypesv1.Rule{
		clusterRule("R0001", "a"),
		clusterRule("R0002", "b"),
		clusterRule("R0001", "a-with-other-params"),
		clusterRule("R0003", "c"),
	}
	got := scopeRulesToNamespace(in, "anything")
	if len(got) != len(in) {
		t.Fatalf("got %+v, want all %d rules unchanged", ids(got), len(in))
	}
	for i := range in {
		if got[i].ID != in[i].ID || got[i].Name != in[i].Name {
			t.Fatalf("input was altered at %d: %+v vs %+v", i, got[i], in[i])
		}
	}
}

func TestScopeRulesToNamespace_Empty(t *testing.T) {
	if got := scopeRulesToNamespace(nil, "redis"); len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}
