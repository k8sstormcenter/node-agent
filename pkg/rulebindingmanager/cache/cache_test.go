package cache

import (
	"context"
	"fmt"
	"slices"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/mocks"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	typesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestRuntimeObjAddHandler(t *testing.T) {
	type rules struct {
		ruleID string
	}
	type args struct {
		c   *RBCache
		pod *corev1.Pod
		rb  []typesv1.RuntimeAlertRuleBinding
	}
	tests := []struct {
		name          string
		args          args
		expectedRules []rules
	}{
		{
			name: "Add a pod to the cache",
			args: args{
				c: NewCacheMock(""),
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "testPod",
						Namespace: "testNamespace",
						Labels: map[string]string{
							"app": "testPod",
						},
					},
				},
				rb: []typesv1.RuntimeAlertRuleBinding{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "testRB",
							Namespace: "testNamespace",
						},
						Spec: typesv1.RuntimeAlertRuleBindingSpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "testPod",
								},
							},
							Rules: []typesv1.RuntimeAlertRuleBindingRule{
								{
									RuleID: "R0001",
								},
							},
						},
					},
				},
			},
			expectedRules: []rules{
				{
					ruleID: "R0001",
				},
			},
		},
		{
			name: "Pod with MatchExpressions",
			args: args{
				c: NewCacheMock(""),
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "testPod",
						Namespace: "testNamespace",
						Labels: map[string]string{
							"app": "testPod",
						},
					},
				},
				rb: []typesv1.RuntimeAlertRuleBinding{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "testRB",
							Namespace: "testNamespace",
						},
						Spec: typesv1.RuntimeAlertRuleBindingSpec{
							PodSelector: metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"testPod"},
									},
								},
							},
							Rules: []typesv1.RuntimeAlertRuleBindingRule{
								{
									RuleID: "R0001",
								},
							},
						},
					},
				},
			},
			expectedRules: []rules{
				{
					ruleID: "R0001",
				},
			},
		},
		{
			name: "Pod with mismatch labels",
			args: args{
				c: NewCacheMock(""),
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "testPod",
						Namespace: "testNamespace",
						Labels: map[string]string{
							"app": "testPod",
						},
					},
				},
				rb: []typesv1.RuntimeAlertRuleBinding{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "testRB",
							Namespace: "testNamespace",
						},
						Spec: typesv1.RuntimeAlertRuleBindingSpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "testPod1",
								},
							},
							Rules: []typesv1.RuntimeAlertRuleBindingRule{
								{
									RuleID: "R0001",
								},
							},
						},
					},
				},
			},
			expectedRules: []rules{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := range tt.args.rb {
				tt.args.c.addRuleBinding(&tt.args.rb[i])
			}
			tt.args.c.addPod(context.Background(), tt.args.pod)
			r := tt.args.c.ListRulesForPod(tt.args.pod.GetNamespace(), tt.args.pod.GetName())
			assert.Equal(t, len(tt.expectedRules), len(r))
			for i := range r {
				assert.Equal(t, tt.expectedRules[i].ruleID, r[i].ID)

			}
		})

	}
}
func TestDeletePod(t *testing.T) {
	tests := []struct {
		setup      func(*RBCache)
		name       string
		uniqueName string
	}{
		{
			name:       "Test with existing pod",
			uniqueName: "default/pod-1",
			setup: func(c *RBCache) {
				c.allPods.Add("default/pod-1")
				c.podToRBNames.Set("default/pod-1", mapset.NewSet[string]("rb-1"))
				c.rbNameToPods.Set("rb-1", mapset.NewSet[string]("default/pod-1"))
			},
		},
		{
			name:       "Test with non-existing pod",
			uniqueName: "default/pod-2",
			setup:      func(c *RBCache) {},
		},
		{
			name:       "Test pod not found",
			uniqueName: "default/pod-2",
			setup: func(c *RBCache) {
				c.allPods.Add("default/pod-1")
				c.podToRBNames.Set("default/pod-1", mapset.NewSet[string]("rb-1"))
				c.rbNameToPods.Set("rb-1", mapset.NewSet[string]("default/pod-1"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &RBCache{
				allPods:      mapset.NewSet[string](),
				podToRBNames: maps.SafeMap[string, mapset.Set[string]]{},
				rbNameToPods: maps.SafeMap[string, mapset.Set[string]]{},
			}
			tt.setup(c)

			c.deletePod(tt.uniqueName)

			assert.False(t, c.allPods.Contains(tt.uniqueName))
			assert.False(t, c.podToRBNames.Has(tt.uniqueName))
			for _, rbName := range c.rbNameToPods.Keys() {
				assert.False(t, c.rbNameToPods.Get(rbName).Contains(tt.uniqueName))
			}
		})
	}
}

func TestDeleteHandler(t *testing.T) {
	type expected struct {
		pod  string
		rule string
	}
	tests := []struct {
		name     string
		obj      runtime.Object
		expected expected
	}{
		{
			name: "Test with Pod kind",
			obj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-1",
					Namespace: "default",
				},
			},
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
		{
			name: "Test with RuntimeRuleBindingAlert kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "RuntimeRuleAlertBinding",
					"metadata": map[string]interface{}{
						"name":      "rule-1",
						"namespace": "default",
					},
				},
			},
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &RBCache{
				allPods: mapset.NewSet[string](tt.expected.pod),
			}
			c.DeleteHandler(context.Background(), tt.obj)
			if _, ok := tt.obj.(*corev1.Pod); ok {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
			} else {
				assert.True(t, c.allPods.Contains(tt.expected.pod))
			}
		})
	}
}

func TestModifyHandler(t *testing.T) {
	type expected struct {
		pod  string
		rule string
	}
	tests := []struct {
		name     string
		obj      runtime.Object
		expected expected
		addedPod bool
		addedRB  bool
	}{
		{
			name: "Test with Pod kind",
			obj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-1",
					Namespace: "default",
				},
			},
			addedPod: true,
			addedRB:  false,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
		{
			name: "Test with RuntimeRuleBindingAlert kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "RuntimeRuleAlertBinding",
					"metadata": map[string]interface{}{
						"name":      "rule-1",
						"namespace": "default",
					},
				},
			},
			addedPod: false,
			addedRB:  true,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
		{
			name: "Test with invalid RuntimeRuleBindingAlert kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "RuntimeAlertRuleBinding",
					"metadata": map[string]interface{}{
						"name":      "rule-1",
						"namespace": "default",
					},
					"spec": "invalid",
				},
			},
			addedPod: false,
			addedRB:  false,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
		{
			name: "Test with invalid Pod kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata": map[string]interface{}{
						"name":      "pod-1",
						"namespace": "default",
					},
					"spec": map[string]interface{}{
						"containers": "invalid",
					},
				},
			},
			addedPod: false,
			addedRB:  false,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			c := NewCacheMock("")

			c.ModifyHandler(context.Background(), tt.obj)

			if tt.addedPod {
				assert.True(t, c.allPods.Contains(tt.expected.pod))
			}
			if tt.addedRB {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
			}
			if !tt.addedPod && !tt.addedRB {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
			}
		})
	}
}

func TestAddHandler(t *testing.T) {
	type expected struct {
		pod  string
		rule string
	}
	tests := []struct {
		name     string
		obj      runtime.Object
		expected expected
		addedPod bool
		addedRB  bool
	}{
		{
			name: "Test with Pod kind",
			obj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-1",
					Namespace: "default",
				},
			},
			addedPod: true,
			addedRB:  false,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
		{
			name: "Test with RuntimeRuleBindingAlert kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "RuntimeRuleAlertBinding",
					"metadata": map[string]interface{}{
						"name":      "rule-1",
						"namespace": "default",
					},
				},
			},
			addedPod: false,
			addedRB:  true,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
		{
			name: "Test with invalid RuntimeRuleBindingAlert kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "RuntimeAlertRuleBinding",
					"metadata": map[string]interface{}{
						"name":      "rule-1",
						"namespace": "default",
					},
					"spec": "invalid",
				},
			},
			addedPod: false,
			addedRB:  false,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
		{
			name: "Test with invalid Pod kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata": map[string]interface{}{
						"name":      "pod-1",
						"namespace": "default",
					},
					"spec": map[string]interface{}{
						"containers": "invalid",
					},
				},
			},
			addedPod: false,
			addedRB:  false,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			c := NewCacheMock("")

			c.AddHandler(context.Background(), tt.obj)

			if tt.addedPod {
				assert.True(t, c.allPods.Contains(tt.expected.pod))
			}
			if tt.addedRB {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
			}
			if !tt.addedPod && !tt.addedRB {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
			}
		})
	}
}
func TestDeleteRuleBinding(t *testing.T) {

	tests := []struct {
		podToRBNames         map[string][]string
		expectedPodToRBNames map[string][]string
		name                 string
		uniqueName           string
	}{
		{
			name:                 "Test with valid unique name without pods",
			uniqueName:           "test-unique-name",
			podToRBNames:         map[string][]string{},
			expectedPodToRBNames: map[string][]string{},
		},
		{
			name:       "Test with valid unique name one pod",
			uniqueName: "test-unique-name",
			podToRBNames: map[string][]string{
				"default/pod-1": {"test-unique-name"},
			},
			expectedPodToRBNames: map[string][]string{},
		},
		{
			name:       "Delete all pods with the same unique name",
			uniqueName: "test-unique-name",
			podToRBNames: map[string][]string{
				"default/pod-1": {"test-unique-name"},
				"default/pod-2": {"test-unique-name"},
				"default/pod-3": {"test-unique-name"},
			},
			expectedPodToRBNames: map[string][]string{},
		},
		{
			name:       "Delete one pod with the same unique name",
			uniqueName: "test-unique-name",
			podToRBNames: map[string][]string{
				"default/pod-1": {"test-unique-name"},
				"default/pod-2": {"test-unique-name", "test-unique-name-2", "test-unique-name-3"},
				"default/pod-3": {"test-unique-name-2", "test-unique-name-3"},
			},
			expectedPodToRBNames: map[string][]string{
				"default/pod-2": {"test-unique-name-2", "test-unique-name-3"},
				"default/pod-3": {"test-unique-name-2", "test-unique-name-3"},
			},
		},
		{
			name:       "Do not delete any",
			uniqueName: "test-unique-name",
			podToRBNames: map[string][]string{
				"default/pod-2": {"test-unique-name-2", "test-unique-name-3"},
				"default/pod-3": {"test-unique-name-2", "test-unique-name-3"},
			},
			expectedPodToRBNames: map[string][]string{
				"default/pod-2": {"test-unique-name-2", "test-unique-name-3"},
				"default/pod-3": {"test-unique-name-2", "test-unique-name-3"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCacheMock("")

			for k, v := range tt.podToRBNames {
				for _, s := range v {
					c.rbNameToRB.Set(s, typesv1.RuntimeAlertRuleBinding{})
					c.rbNameToRules.Set(s, []rulemanagertypesv1.Rule{{}})

					if !c.rbNameToPods.Has(s) {
						c.rbNameToPods.Set(s, mapset.NewSet[string]())
					}
					c.rbNameToPods.Get(s).Add(k)

					if !c.podToRBNames.Has(k) {
						c.podToRBNames.Set(k, mapset.NewSet[string]())
					}
					c.podToRBNames.Get(k).Add(s)
				}

			}

			c.deleteRuleBinding(tt.uniqueName)

			assert.False(t, c.rbNameToPods.Has(tt.uniqueName))
			assert.False(t, c.rbNameToRB.Has(tt.uniqueName))
			assert.False(t, c.rbNameToRules.Has(tt.uniqueName))
			for k, v := range tt.expectedPodToRBNames {
				slices.Sort(v)
				tmp := c.podToRBNames.Get(k).ToSlice()
				slices.Sort(tmp)
				assert.Equal(t, v, tmp)
			}
		})
	}
}

func TestAddRuleBinding(t *testing.T) {

	defer func() {
		mocks.NAMESPACE = ""
	}()

	k8sClient := k8sinterface.NewKubernetesApiMock()
	var r []runtime.Object
	mocks.NAMESPACE = "default"
	r = append(r, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: mocks.NAMESPACE, Labels: map[string]string{"app": mocks.NAMESPACE}}})
	r = append(r, mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection))
	r = append(r, mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx))

	mocks.NAMESPACE = "other"
	r = append(r, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: mocks.NAMESPACE, Labels: map[string]string{"app": mocks.NAMESPACE}}})
	r = append(r, mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection))
	r = append(r, mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx))

	mocks.NAMESPACE = "test"
	r = append(r, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: mocks.NAMESPACE, Labels: map[string]string{"app": mocks.NAMESPACE}}})
	r = append(r, mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection))
	r = append(r, mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx))

	k8sClient.KubernetesClient = k8sfake.NewClientset(r...)

	tests := []struct {
		rb                   *typesv1.RuntimeAlertRuleBinding
		name                 string
		expectedNotifiedPods []string
		invalidRB            bool
	}{
		{
			name: "Add roleBinding",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rb1",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
					},
				},
			},
			expectedNotifiedPods: []string{
				"default/collection-94c495554-z8s5k",
				"default/nginx-77b4fdf86c-hp4x5",
				"other/collection-94c495554-z8s5k",
				"other/nginx-77b4fdf86c-hp4x5",
				"test/collection-94c495554-z8s5k",
				"test/nginx-77b4fdf86c-hp4x5",
			},
		},
		{
			name: "Add roleBinding namespace 'other'",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rb1",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "app",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"other"},
							},
						},
					},
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
						{
							RuleID: "R0002",
						},
					},
				},
			},
			expectedNotifiedPods: []string{
				"other/collection-94c495554-z8s5k",
				"other/nginx-77b4fdf86c-hp4x5",
			},
		},
		{
			name: "Add namespaced roleBinding",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "rb1",
					Namespace: "other",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "app",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"other"},
							},
						},
					},
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
						{
							RuleID: "R0002",
						},
					},
				},
			},
			expectedNotifiedPods: []string{
				"other/collection-94c495554-z8s5k",
				"other/nginx-77b4fdf86c-hp4x5",
			},
		},
		{
			name: "Add namespaced roleBinding without pods",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "rb1",
					Namespace: "blabla",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "app",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"other"},
							},
						},
					},
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
						{
							RuleID: "R0002",
						},
					},
				},
			},
			expectedNotifiedPods: []string{},
		},
		{
			name: "Add roleBinding exclude namespace 'other'",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rb1",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "app",
								Operator: metav1.LabelSelectorOpNotIn,
								Values:   []string{"other"},
							},
						},
					},
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
						{
							RuleID: "R0002",
						},
					},
				},
			},
			expectedNotifiedPods: []string{
				"default/collection-94c495554-z8s5k",
				"default/nginx-77b4fdf86c-hp4x5",
				"test/collection-94c495554-z8s5k",
				"test/nginx-77b4fdf86c-hp4x5",
			},
		},
		{
			name: "Add roleBinding MatchLabels",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rb1",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test",
						},
					},
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "collection",
						},
					},
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
						{
							RuleID: "R0002",
						},
					},
				},
			},
			expectedNotifiedPods: []string{
				"test/collection-94c495554-z8s5k",
			},
		},
		{
			name: "Namespace does not exists",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rb1",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "bla",
						},
					},
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
					},
				},
			},
			expectedNotifiedPods: []string{},
		},
		{
			name: "Invalid ns selector",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rb1",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "app",
								Operator: metav1.LabelSelectorOperator("invalid"),
								Values:   []string{"other"},
							},
						},
					},
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
					},
				},
			},
			invalidRB:            true,
			expectedNotifiedPods: []string{},
		},
		{
			name: "Invalid label selector",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rb1",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					PodSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "app",
								Operator: metav1.LabelSelectorOperator("invalid"),
								Values:   []string{"other"},
							},
						},
					},
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
					},
				},
			},
			invalidRB:            true,
			expectedNotifiedPods: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCacheMock("")
			c.k8sClient = k8sClient

			c.addRuleBinding(tt.rb)

			rbName := uniqueName(tt.rb)

			if tt.invalidRB {
				assert.False(t, c.rbNameToPods.Has(rbName))
				assert.False(t, c.rbNameToRB.Has(rbName))
				assert.False(t, c.rbNameToRules.Has(rbName))
				return
			}

			assert.True(t, c.rbNameToPods.Has(rbName))
			assert.True(t, c.rbNameToRB.Has(rbName))
			assert.True(t, c.rbNameToRules.Has(rbName))

			for _, pod := range tt.expectedNotifiedPods {
				assert.True(t, c.podToRBNames.Has(pod))
				assert.True(t, c.podToRBNames.Get(pod).Contains(rbName))
			}

		})
	}
}

func TestDiff(t *testing.T) {
	tests := []struct {
		name string
		a, b []rulebindingmanager.RuleBindingNotify
		want []rulebindingmanager.RuleBindingNotify
	}{
		{
			name: "Test with non-overlapping slices",
			a: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
			},
			b: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default-2"}},
					Action: rulebindingmanager.Removed,
				},
			},
			want: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default-2"}},
					Action: rulebindingmanager.Removed,
				},
			},
		},
		{
			name: "Test with overlapping slices",
			a: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
			},
			b: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Removed,
				},
			},
			want: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
			},
		},
		{
			name: "Test with overlapping slices - 2",
			a: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
			},
			b: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Removed,
				},
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Removed,
				},
			},
			want: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Removed,
				},
			},
		},
		{
			name: "Test all overlapping slices",
			a: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
			},
			b: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Removed,
				},
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Removed,
				},
			},
			want: []rulebindingmanager.RuleBindingNotify{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diff(tt.a, tt.b)
			var gotL []string
			for _, v := range got {
				gotL = append(gotL, fmt.Sprintf("%s-%s-%d", v.Pod.Namespace, v.Pod.Name, v.Action))
			}
			var wantL []string
			for _, v := range tt.want {
				wantL = append(wantL, fmt.Sprintf("%s-%s-%d", v.Pod.Namespace, v.Pod.Name, v.Action))
			}
			slices.Sort(gotL)
			slices.Sort(wantL)

			assert.Equal(t, wantL, gotL)
		})
	}
}

// TestBundleOverrideOnByNameBinding pins the end-to-end behaviour the real
// deployment depends on: a RuntimeAlertRuleBinding that names its rules
// explicitly (ruleName, no ruleTags, no IgnoreRuleBindings) must still let a
// signed bundle overlay override the base rule of the same ID for the workloads
// bound to that bundle, and only for them — regardless of namespace.
//
// This exercises the whole chain — pod label -> podToBundle -> createRules ->
// CreateRulesByName -> ListRulesForPod -> scopeRulesToBundle. Resolving the name
// to a single rule in createRule would make this test fail with the base variant
// for the redis pod.
//
// The lookups must use distinct pods: rulesForPod is an LRU keyed by the
// namespace-qualified pod ID, so a single pod would serve one memoised result to
// every case.
func TestBundleOverrideOnByNameBinding(t *testing.T) {
	const ruleName = "unexpected_process_launched"

	rc := rulecreator.NewRuleCreator()
	// Cluster-wide baseline from a base-class fragment.
	rc.RegisterRule(rulemanagertypesv1.Rule{
		ID: "R0001", Name: ruleName, Enabled: true, Severity: 5,
		Expressions: rulemanagertypesv1.RuleExpressions{Message: "cluster baseline"},
		ClusterWide: true,
	})
	// Signed overlay for the "redis" bundle, same ID and name, retuned.
	rc.RegisterRule(rulemanagertypesv1.Rule{
		ID: "R0001", Name: ruleName, Enabled: true, Severity: 10,
		Expressions: rulemanagertypesv1.RuleExpressions{Message: "redis override"},
		Bundle:      "redis",
	})
	// An unrelated cluster rule, also bound by name, must be unaffected.
	rc.RegisterRule(rulemanagertypesv1.Rule{
		ID: "R0003", Name: "exec_from_malicious_source", Enabled: true, Severity: 7,
		ClusterWide: true,
	})

	c := NewCacheMock("")
	c.ruleCreator = rc

	rbName := "kubescape/rb-by-name"
	rb := typesv1.RuntimeAlertRuleBinding{
		Spec: typesv1.RuntimeAlertRuleBindingSpec{
			Rules: []typesv1.RuntimeAlertRuleBindingRule{
				{RuleName: ruleName},
				{RuleName: "exec_from_malicious_source"},
			},
		},
	}
	c.rbNameToRB.Set(rbName, rb)
	c.rbNameToRules.Set(rbName, c.createRules(rb.Spec.Rules))

	// Four pods, all selected by the same binding. Two opted into the "redis"
	// bundle from DIFFERENT namespaces, one opted into another bundle, one did
	// not opt in at all.
	pods := []*corev1.Pod{
		podWithBundle("redis", "redis-0", "redis"),
		podWithBundle("team-a", "cache-0", "redis"),
		podWithBundle("other", "pg-0", "postgres"),
		podWithBundle("other", "api-0", ""),
	}
	for _, p := range pods {
		c.podToRBNames.Set(uniqueName(p), mapset.NewSet[string](rbName))
		c.setPodBundle(p)
	}

	assertOverridden := func(t *testing.T, namespace, name string) {
		t.Helper()
		got := c.ListRulesForPod(namespace, name)
		require.Len(t, got, 2, "expected exactly one R0001 plus R0003, got %v", got)

		var r0001 []rulemanagertypesv1.Rule
		for _, r := range got {
			if r.ID == "R0001" {
				r0001 = append(r0001, r)
			}
		}
		require.Len(t, r0001, 1, "the override must replace the base rule, not be added next to it")
		assert.Equal(t, "redis", r0001[0].Bundle)
		assert.False(t, r0001[0].ClusterWide)
		assert.Equal(t, 10, r0001[0].Severity)
		assert.Equal(t, "redis override", r0001[0].Expressions.Message)
	}

	assertBaseline := func(t *testing.T, namespace, name string) {
		t.Helper()
		got := c.ListRulesForPod(namespace, name)
		require.Len(t, got, 2, "expected exactly one R0001 plus R0003, got %v", got)

		var r0001 []rulemanagertypesv1.Rule
		for _, r := range got {
			if r.ID == "R0001" {
				r0001 = append(r0001, r)
			}
		}
		require.Len(t, r0001, 1, "the redis overlay must not leak outside its bundle")
		assert.True(t, r0001[0].ClusterWide)
		assert.Empty(t, r0001[0].Bundle)
		assert.Equal(t, 5, r0001[0].Severity)
		assert.Equal(t, "cluster baseline", r0001[0].Expressions.Message)
	}

	t.Run("pod bound to the bundle gets the overlay", func(t *testing.T) {
		assertOverridden(t, "redis", "redis-0")
	})

	t.Run("bundle crosses namespaces", func(t *testing.T) {
		// Same bundle, entirely different namespace: the overlay still applies.
		// This is what scoping by bundle buys over scoping by namespace.
		assertOverridden(t, "team-a", "cache-0")
	})

	t.Run("pod bound to another bundle keeps the base rule", func(t *testing.T) {
		assertBaseline(t, "other", "pg-0")
	})

	t.Run("pod with no bundle label keeps the base rule", func(t *testing.T) {
		assertBaseline(t, "other", "api-0")
	})

	t.Run("pod unknown to the bundle map keeps the base rule", func(t *testing.T) {
		// Safe default: an unknown pod is treated as bound to no bundle.
		c.podToRBNames.Set("ghost/ghost-0", mapset.NewSet[string](rbName))
		assertBaseline(t, "ghost", "ghost-0")
	})

	t.Run("binding contributes both variants before scoping", func(t *testing.T) {
		// The cache must hold BOTH R0001 variants per binding; scoping picks one
		// per pod. If this drops to one, the override above is accidental.
		rules, ok := c.rbNameToRules.Load(rbName)
		require.True(t, ok)
		count := 0
		for _, r := range rules {
			if r.ID == "R0001" {
				count++
			}
		}
		assert.Equal(t, 2, count, "createRules must expand a by-name entry to every variant")
	})
}

// podWithBundle builds a pod carrying (or not carrying) the user-defined-profile
// label that opts a workload into a signed bundle.
func podWithBundle(namespace, name, bundleName string) *corev1.Pod {
	labels := map[string]string{}
	if bundleName != "" {
		labels[helpersv1.UserDefinedProfileMetadataKey] = bundleName
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels},
	}
}

// TestPodBundleTracking pins the pod -> bundle bookkeeping the scoping depends
// on: the label is read on add and on every update, and the entry disappears
// with the pod (or with the label).
func TestPodBundleTracking(t *testing.T) {
	c := NewCacheMock("")
	c.config.IgnoreRuleBindings = true // pod bundles are tracked in this mode too

	pod := podWithBundle("redis", "redis-0", "redis")
	c.AddHandler(context.Background(), pod)
	assert.Equal(t, "redis", c.bundleForPod("redis/redis-0"))

	// Re-labelled to another bundle.
	c.ModifyHandler(context.Background(), podWithBundle("redis", "redis-0", "postgres"))
	assert.Equal(t, "postgres", c.bundleForPod("redis/redis-0"))

	// Opted out: a stale entry would keep applying an overlay.
	c.ModifyHandler(context.Background(), podWithBundle("redis", "redis-0", ""))
	assert.Empty(t, c.bundleForPod("redis/redis-0"))

	// Deleted: the entry must not survive for a recycled pod ID.
	c.ModifyHandler(context.Background(), podWithBundle("redis", "redis-0", "redis"))
	require.Equal(t, "redis", c.bundleForPod("redis/redis-0"))
	c.DeleteHandler(context.Background(), podWithBundle("redis", "redis-0", "redis"))
	assert.Empty(t, c.bundleForPod("redis/redis-0"))

	// An entirely unknown pod resolves to no bundle.
	assert.Empty(t, c.bundleForPod("nowhere/nothing"))
}

// TestListRulesForPod_IgnoreRuleBindingsScopesByBundle covers the other
// ListRulesForPod branch: with IgnoreRuleBindings the rules come straight from
// the rule creator, and they must still be scoped to the pod's bundle.
func TestListRulesForPod_IgnoreRuleBindingsScopesByBundle(t *testing.T) {
	rc := rulecreator.NewRuleCreator()
	rc.RegisterRule(rulemanagertypesv1.Rule{
		ID: "R0001", Name: "r1", Enabled: true, Severity: 5,
		Expressions: rulemanagertypesv1.RuleExpressions{Message: "cluster baseline"},
		ClusterWide: true,
	})
	rc.RegisterRule(rulemanagertypesv1.Rule{
		ID: "R0001", Name: "r1", Enabled: true, Severity: 10,
		Expressions: rulemanagertypesv1.RuleExpressions{Message: "redis override"},
		Bundle:      "redis",
	})

	c := NewCacheMock("")
	c.ruleCreator = rc
	c.config.IgnoreRuleBindings = true

	c.AddHandler(context.Background(), podWithBundle("anywhere", "redis-0", "redis"))
	c.AddHandler(context.Background(), podWithBundle("anywhere", "plain-0", ""))

	inBundle := c.ListRulesForPod("anywhere", "redis-0")
	require.Len(t, inBundle, 1)
	assert.Equal(t, "redis override", inBundle[0].Expressions.Message)

	outside := c.ListRulesForPod("anywhere", "plain-0")
	require.Len(t, outside, 1)
	assert.Equal(t, "cluster baseline", outside[0].Expressions.Message)
}

func TestCreateRulePrefilter(t *testing.T) {
	tests := []struct {
		name       string
		binding    *typesv1.RuntimeAlertRuleBindingRule
		wantNil    bool
		wantIgnore []string
		wantIncl   []string
	}{
		{
			name: "parameters propagate to prefilter",
			binding: &typesv1.RuntimeAlertRuleBindingRule{
				RuleID: "R0002",
				Parameters: map[string]interface{}{
					"ignorePrefixes":  []interface{}{"/tmp", "/var/log"},
					"includePrefixes": []interface{}{"/etc"},
				},
			},
			wantIgnore: []string{"/tmp", "/var/log"},
			wantIncl:   []string{"/etc"},
		},
		{
			name:    "nil parameters produce nil prefilter",
			binding: &typesv1.RuntimeAlertRuleBindingRule{RuleID: "R0002"},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCacheMock("")
			rules := c.createRule(tt.binding)
			require.Len(t, rules, 1)
			if tt.wantNil {
				assert.Nil(t, rules[0].Prefilter)
			} else {
				require.NotNil(t, rules[0].Prefilter)
				assert.Equal(t, tt.wantIgnore, rules[0].Prefilter.IgnorePrefixes)
				assert.Equal(t, tt.wantIncl, rules[0].Prefilter.IncludePrefixes)
			}
		})
	}
}
