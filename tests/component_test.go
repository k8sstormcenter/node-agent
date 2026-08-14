//go:build component

package tests

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/tests/testutils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1client "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"
)

func tearDownTest(t *testing.T, startTime time.Time) {
	end := time.Now()

	t.Log("Waiting 30 seconds for Prometheus to scrape the data")
	time.Sleep(30 * time.Second)

	err := testutils.PlotNodeAgentPrometheusCPUUsage(t.Name(), startTime, end)
	if err != nil {
		t.Logf("plot cpu usage: %v", err)
	}

	_, err = testutils.PlotNodeAgentPrometheusMemoryUsage(t.Name(), startTime, end)
	if err != nil {
		t.Logf("plot memory usage: %v", err)
	}

	testutils.PrintAppLogs(t, "node-agent")
	testutils.PrintAppLogs(t, "malicious-app")
	testutils.PrintAppLogs(t, "endpoint-traffic")
}

func Test_01_BasicAlertTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/deployment-multiple-containers.yaml"))
	require.NoError(t, err, "Error creating workload")
	require.NoError(t, wl.WaitForReady(80))

	time.Sleep(10 * time.Second)

	// process launched from nginx container
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "nginx")

	// network activity from server container
	_, _, err = wl.ExecIntoPod([]string{"wget", "ebpf.io", "-T", "2", "-t", "1"}, "server")

	// network activity from nginx container
	_, _, err = wl.ExecIntoPod([]string{"curl", "kubernetes.io", "-m", "2"}, "nginx")

	err = wl.WaitForContainerProfileCompletion(80)
	require.NoError(t, err, "Error waiting for application profile to be completed")
	err = wl.WaitForContainerProfileCompletion(80)
	require.NoError(t, err, "Error waiting for network neighborhood to be completed")

	time.Sleep(30 * time.Second)

	profiles, _ := wl.GetContainerProfiles()
	profilesJson, _ := json.Marshal(profiles)

	t.Logf("container profiles: %v", string(profilesJson))

	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "nginx")                               // no alert expected
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "server")                              // alert expected
	_, _, err = wl.ExecIntoPod([]string{"wget", "ebpf.io", "-T", "2", "-t", "1"}, "server") // no alert expected
	_, _, err = wl.ExecIntoPod([]string{"curl", "ebpf.io", "-m", "2"}, "nginx")             // alert expected

	// Wait for the alert to be signaled
	time.Sleep(30 * time.Second)

	alerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Error getting alerts")

	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "server", []bool{true})
	testutils.AssertNotContains(t, alerts, "Unexpected process launched", "ls", "nginx", []bool{true})

	testutils.AssertContains(t, alerts, "DNS Anomalies in container", "curl", "nginx", []bool{true})
	testutils.AssertNotContains(t, alerts, "DNS Anomalies in container", "wget", "server", []bool{true})

	// Verify UID fields are populated in alerts
	testutils.AssertUIDFieldsPopulated(t, alerts, wl.Namespace)

	// check per-container network surface (one ContainerProfile per container)
	nginxCP, err := wl.GetContainerProfile("nginx")
	require.NoError(t, err, "Error getting nginx container profile")
	serverCP, err := wl.GetContainerProfile("server")
	require.NoError(t, err, "Error getting server container profile")

	testutils.AssertContainerProfileContains(t, nginxCP, []string{"kubernetes.io."}, []string{})
	testutils.AssertContainerProfileNotContains(t, serverCP, []string{"kubernetes.io."}, []string{})

	testutils.AssertContainerProfileContains(t, serverCP, []string{"ebpf.io."}, []string{})
	testutils.AssertContainerProfileNotContains(t, nginxCP, []string{"ebpf.io."}, []string{})
}

// enableR0002ForTest applies an override Rules CRD that enables R0002 ("Files
// Access Anomalies in container") — which ships disabled in the bundle
// (rulelibrary default) — for the calling test's cluster only, without
// modifying tests/chart/templates/node-agent/default-rules.yaml. The
// rules-watcher filters disabled rules before its per-ID merge, so it uses this
// enabled copy in place of the disabled bundle one. Each component-test matrix
// job runs on its own cluster, so this stays isolated. Use as:
//
//	defer enableR0002ForTest(t)()
func enableR0002ForTest(t *testing.T) func() {
	t.Helper()
	override := path.Join(utils.CurrentDir(), "resources/r0002-files-access-enabled.yaml")
	require.Equal(t, 0, testutils.RunCommand("kubectl", "apply", "--validate=false", "-f", override), "enable R0002 override")
	// allow the rules-watcher to pick up the newly enabled rule
	time.Sleep(10 * time.Second)
	return func() { testutils.RunCommand("kubectl", "delete", "--ignore-not-found", "-f", override) }
}

func Test_02_AllAlertsFromMaliciousApp(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)
	defer enableR0002ForTest(t)()

	// Create a random namespace
	ns := testutils.NewRandomNamespace()

	// Create a workload
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/malicious-job.yaml"))
	require.NoError(t, err, "Error creating workload")

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	// Wait for the application profile to be created and completed
	err = wl.WaitForContainerProfileCompletion(150)
	require.NoError(t, err, "Error waiting for application profile to be completed")

	// Wait for the alerts to be generated
	time.Sleep(2 * time.Minute)

	// Get all the alerts for the namespace
	alerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Error getting alerts")

	// Validate that all alerts are signaled
	expectedAlerts := map[string]bool{
		"Unexpected process launched":               false,
		"Files Access Anomalies in container":       false,
		"Syscalls Anomalies in container":           false,
		"Linux Capabilities Anomalies in container": false,
		"Workload uses Kubernetes API unexpectedly": false,
		"Process Executed from /dev/shm":            false,
		"Process tries to load a kernel module":     false,
		"Drifted process executed":                  false,
		"Process executed from mount":               false,
		"Unexpected service account token access":   false,
		"DNS Anomalies in container":                false,
		"Crypto Mining Related Port Communication":  false,
		"Crypto Mining Domain Communication":        false,
	}

	expectedFailOnProfile := map[string][]bool{
		"Unexpected process launched":               {true},
		"Files Access Anomalies in container":       {true},
		"Syscalls Anomalies in container":           {true},
		"Linux Capabilities Anomalies in container": {true},
		"Workload uses Kubernetes API unexpectedly": {true},
		"Process Executed from /dev/shm":            {false},
		"Process tries to load a kernel module":     {false},
		"Drifted process executed":                  {true},
		"Process executed from mount":               {true},
		"Unexpected service account token access":   {true},
		"DNS Anomalies in container":                {true},
		"Crypto Mining Related Port Communication":  {true},
		"Crypto Mining Domain Communication":        {false},
	}

	for _, alert := range alerts {
		ruleName, ruleOk := alert.Labels["rule_name"]
		failOnProfile, failOnProfileOk := alert.Labels["fail_on_profile"]
		failOnProfileBool, err := strconv.ParseBool(failOnProfile)
		require.NoError(t, err, "Error parsing fail_on_profile")
		if ruleOk && failOnProfileOk {
			if _, exists := expectedAlerts[ruleName]; exists && slices.Contains(expectedFailOnProfile[ruleName], failOnProfileBool) {
				expectedAlerts[ruleName] = true
			}
		}
	}

	for ruleName, signaled := range expectedAlerts {
		assert.Truef(t, signaled, "Expected alert '%s' was not signaled", ruleName)
	}
}

func Test_03_BasicLoadActivities(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()

	// Create a workload
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "Error creating workload")

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	// Wait for the application profile to be created and completed
	err = wl.WaitForContainerProfileCompletion(80)
	require.NoError(t, err, "Error waiting for application profile to be completed")

	// Create loader
	loader, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/locust-deployment.yaml"))
	require.NoError(t, err)
	err = loader.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	loadStart := time.Now()

	// Create a load of 5 minutes
	time.Sleep(5 * time.Minute)

	loadEnd := time.Now()

	// Get CPU usage of Node Agent pods
	podToCpuUsage, err := testutils.GetNodeAgentAverageCPUUsage(loadStart, loadEnd)
	require.NoError(t, err, "Error getting CPU usage")

	require.NotEqual(t, 0, podToCpuUsage, "No CPU usage data found")

	for pod, cpuUsage := range podToCpuUsage {
		assert.LessOrEqual(t, cpuUsage, 0.4, "CPU usage of Node Agent is too high. CPU usage is %f, Pod: %s", cpuUsage, pod)
	}
}

func Test_04_MemoryLeak(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()

	// Create 2 workloads
	wlPaths := []string{
		"resources/locust-deployment.yaml",
		"resources/nginx-deployment.yaml",
	}
	var workloads []testutils.TestWorkload
	for _, p := range wlPaths {
		wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), p))
		require.NoError(t, err, "Error creating deployment")
		workloads = append(workloads, *wl)
	}
	for _, wl := range workloads {
		err := wl.WaitForReady(80)
		require.NoError(t, err, "Error waiting for workload to be ready")
		err = wl.WaitForContainerProfileCompletion(80)
		require.NoError(t, err, "Error waiting for application profile to be completed")
	}

	// Wait for 60 seconds for the GC to run, so the memory leak can be detected
	time.Sleep(60 * time.Second)

	metrics, err := testutils.PlotNodeAgentPrometheusMemoryUsage("memleak_basic", start, time.Now())
	require.NoError(t, err, "Error plotting memory usage")

	require.NotEqual(t, 0, metrics, "No memory usage data found")

	for _, metric := range metrics {
		podName := metric.Name
		firstValue := metric.Values[0]
		lastValue := metric.Values[len(metric.Values)-1]

		// Validate that there is no memory leak, but tolerate 100Mb memory leak
		tolerateMb := 100
		assert.LessOrEqual(t, lastValue, firstValue+float64(tolerateMb*1024*1024), "Memory leak detected in node-agent pod (%s). Memory usage at the end of the test is %f and at the beginning of the test is %f", podName, lastValue, firstValue)
	}
}

func Test_05_MemoryLeak_10K_Alerts(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()

	// Create nginx workload
	nginx, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "Error creating workload")
	err = nginx.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	err = nginx.WaitForContainerProfileCompletion(80)
	require.NoError(t, err, "Error waiting for application profile to be completed")

	// wait for 300 seconds for the GC to run, so the memory leak can be detected
	t.Log("Waiting 300 seconds to have a baseline memory usage")
	time.Sleep(300 * time.Second)

	//Exec into the nginx pod and create a file in the /tmp directory in a loop
	startLoad := time.Now()
	for i := 0; i < 100; i++ {
		_, _, err := nginx.ExecIntoPod([]string{"bash", "-c", "for i in {1..100}; do touch /tmp/nginx-test-$i; done"}, "")
		require.NoError(t, err, "Error executing remote command")
		if i%5 == 0 {
			t.Logf("Created file %d times", (i+1)*100)
		}
	}

	// wait for 300 seconds for the GC to run, so the memory leak can be detected
	t.Log("Waiting 300 seconds to GC to run")
	time.Sleep(300 * time.Second)

	metrics, err := testutils.PlotNodeAgentPrometheusMemoryUsage("memleak_10k_alerts", startLoad, time.Now())
	require.NoError(t, err, "Error plotting memory usage")

	require.NotEqual(t, 0, metrics, "No memory usage data found")

	for _, metric := range metrics {
		podName := metric.Name
		firstValue := metric.Values[0]
		lastValue := metric.Values[len(metric.Values)-1]

		// Validate that there is no memory leak, but tolerate 40mb memory leak
		tolerateMb := 40
		assert.LessOrEqual(t, lastValue, firstValue+float64(tolerateMb*1024*1024), "Memory leak detected in node-agent pod (%s). Memory usage at the end of the test is %f and at the beginning of the test is %f", podName, lastValue, firstValue)
	}
}

func Test_06_KillProcessInTheMiddle(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()
	// Create nginx deployment
	nginx, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "Error creating workload")
	err = nginx.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	// Give time for the nginx application profile to be ready
	require.NoError(t, nginx.WaitForContainerProfile(80, "ready"))

	// Exec into the nginx pod and kill the process
	_, _, err = nginx.ExecIntoPod([]string{"bash", "-c", "kill -9 1"}, "")
	require.NoError(t, err, "Error executing remote command")

	// Wait for the application profile to be 'completed'
	err = nginx.WaitForContainerProfileCompletion(20)
	require.NoError(t, err, "Error waiting for application profile to be completed")
}

func Test_07_RuleBindingApplyTest(t *testing.T) {
	ruleBindingPath := func(name string) string {
		return path.Join(utils.CurrentDir(), "resources/rulebindings", name)
	}

	// valid
	exitCode := testutils.RunCommand("kubectl", "apply", "--validate=false", "-f", ruleBindingPath("all-valid.yaml"))
	assert.Equal(t, 0, exitCode, "Error applying valid rule binding")
	exitCode = testutils.RunCommand("kubectl", "delete", "-f", ruleBindingPath("all-valid.yaml"))
	require.Equal(t, 0, exitCode, "Error deleting valid rule binding")

	// duplicate fields
	file := ruleBindingPath("dup-fields-name-tag.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "--validate=false", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	file = ruleBindingPath("dup-fields-name-id.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "--validate=false", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	file = ruleBindingPath("dup-fields-id-tag.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "--validate=false", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)
}

// Test_08_ContainerProfilePatching pins how a ContainerProfile behaves under a
// JSON-patch. A ContainerProfile is per-container with a FLAT spec (unlike the
// former ApplicationProfile, which nested containers under /spec/containers/<i>/),
// so patch paths target /spec/<field> directly. The contract exercised here:
//   - `add /spec/<array>/-` appends one element (a syscall, a capability, an exec);
//   - `replace /spec/<field>` overwrites the whole field;
//   - lifecycle annotations (kubescape.io/status, kubescape.io/completion) are
//     patchable, bounded by the completed-immutability invariant (see Test_15):
//     a completed profile cannot be patched back to learning, but a forward/lateral
//     transition such as initializing→ready is allowed;
//   - the storage layer accepts a JSONPatchType patch, persists it, and the
//     patched fields read back.
func Test_08_ContainerProfilePatching(t *testing.T) {
	k8sClient := k8sinterface.NewKubernetesApi()
	storageclient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	t.Log("Creating namespace")
	ns := testutils.NewRandomNamespace()

	// One profile per container; the (former ApplicationProfile) surfaces live
	// directly on the flat Spec, so patches target /spec/<field>.
	name := "replicaset-checkoutservice-59596bf8d8-server"
	containerProfile := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			// A learned CP carries lifecycle annotations; the patch below
			// replaces them, so they must pre-exist.
			Annotations: map[string]string{
				"kubescape.io/completion": "complete",
				"kubescape.io/status":     "initializing",
			},
		},
		Spec: v1beta1.ContainerProfileSpec{
			Syscalls: []string{
				"capget", "capset", "chdir", "close", "epoll_ctl", "faccessat2",
				"fcntl", "fstat", "fstatfs", "futex", "getdents64", "getppid",
				"nanosleep", "newfstatat", "openat", "prctl", "read", "setgid",
				"setgroups", "setuid", "write",
			},
		},
		Status: v1beta1.ContainerProfileStatus{},
	}

	_, err := storageclient.ContainerProfiles(ns.Name).Create(context.TODO(), containerProfile, metav1.CreateOptions{})
	require.NoError(t, err)

	// patch the container profile
	patchOperations := []utils.PatchOperation{
		{Op: "replace", Path: "/spec/capabilities", Value: []string{"NET_ADMIN"}},
		{Op: "add", Path: "/spec/capabilities/-", Value: "SETGID"},
		{Op: "add", Path: "/spec/capabilities/-", Value: "SETPCAP"},
		{Op: "add", Path: "/spec/capabilities/-", Value: "SETUID"},
		{Op: "add", Path: "/spec/capabilities/-", Value: "SYS_ADMIN"},
		{Op: "add", Path: "/spec/syscalls/-", Value: "accept4"},
		{Op: "add", Path: "/spec/syscalls/-", Value: "arch_prctl"},
		{Op: "add", Path: "/spec/syscalls/-", Value: "bind"},
		{Op: "replace", Path: "/spec/execs", Value: []map[string]interface{}{{
			"path": "/checkoutservice",
			"args": []string{"/checkoutservice"},
		}}},
		{Op: "add", Path: "/spec/execs/-", Value: map[string]interface{}{
			"path": "/bin/grpc_health_probe",
			"args": []string{"/bin/grpc_health_probe", "-addr=:5050"},
		}},
		{Op: "replace", Path: "/metadata/annotations/kubescape.io~1status", Value: "ready"},
		{Op: "replace", Path: "/metadata/annotations/kubescape.io~1completion", Value: "complete"},
	}

	patch, err := json.Marshal(patchOperations)
	require.NoError(t, err)

	// Resilient to transient API errors: retry the patch until storage accepts it.
	require.Eventually(t, func() bool {
		_, patchErr := storageclient.ContainerProfiles(ns.Name).Patch(
			context.Background(), name, types.JSONPatchType, patch, metav1.PatchOptions{})
		return patchErr == nil
	}, 30*time.Second, 1*time.Second, "JSON-patch of the ContainerProfile must be accepted by storage")

	// Read back and prove the patch persisted on the flat spec. Poll, since the
	// write may not be immediately visible.
	var patched *v1beta1.ContainerProfile
	require.Eventually(t, func() bool {
		got, getErr := storageclient.ContainerProfiles(ns.Name).Get(
			context.Background(), name, metav1.GetOptions{})
		if getErr != nil {
			return false
		}
		patched = got
		return patched.Annotations["kubescape.io/status"] == "ready"
	}, 30*time.Second, 1*time.Second, "patched ContainerProfile must read back with the updated status")

	// replace reset /spec/capabilities to [NET_ADMIN], then four adds appended.
	assert.ElementsMatch(t, []string{"NET_ADMIN", "SETGID", "SETPCAP", "SETUID", "SYS_ADMIN"},
		patched.Spec.Capabilities, "replace + add /- on /spec/capabilities")

	// add /spec/syscalls/- appended without dropping the learned syscalls.
	assert.Subset(t, patched.Spec.Syscalls, []string{"accept4", "arch_prctl", "bind"},
		"add /spec/syscalls/- must append")
	assert.Contains(t, patched.Spec.Syscalls, "read", "existing syscalls must survive the patch")

	// replace reset /spec/execs to checkoutservice, then one add appended the probe.
	execPaths := make([]string, 0, len(patched.Spec.Execs))
	for _, e := range patched.Spec.Execs {
		execPaths = append(execPaths, e.Path)
	}
	assert.ElementsMatch(t, []string{"/checkoutservice", "/bin/grpc_health_probe"}, execPaths,
		"replace + add /- on /spec/execs")

	// lifecycle annotations updated; initializing→ready is a legal transition
	// (a completed→learning regression would instead be reverted — see Test_15).
	assert.Equal(t, "ready", patched.Annotations["kubescape.io/status"])
	assert.Equal(t, "complete", patched.Annotations["kubescape.io/completion"])
}

func Test_09_FalsePositiveTest(t *testing.T) {
	// Disabled: under the monitoring-stack load this test drives, storage's
	// single-writer serialization cannot keep up (http: Handler timeout,
	// completion writes never land), so it times out at 20m and has been
	// perpetually red. Also removed from the CI matrix. Re-enable once storage
	// write-serialization lands.
	t.Skip("Test_09_FalsePositiveTest disabled pending storage write-serialization (times out under storage single-writer contention)")
	start := time.Now()
	defer tearDownTest(t, start)

	testutils.IncreaseNodeAgentSniffingTime("10m")

	time.Sleep(5 * time.Second)

	t.Log("Creating namespace")
	ns := testutils.NewRandomNamespace()

	t.Log("Creating services")
	_, err := testutils.CreateWorkloadsInPath(ns.Name, path.Join(utils.CurrentDir(), "resources/hipster_shop/services"))
	require.NoError(t, err, "Error creating services")

	t.Log("Creating deployments")
	deployments, err := testutils.CreateWorkloadsInPath(ns.Name, path.Join(utils.CurrentDir(), "resources/hipster_shop/deployments"))
	require.NoError(t, err, "Error creating deployments")

	t.Log("Waiting for all workloads to be ready")
	for _, wl := range deployments {
		err = wl.WaitForReady(80)
		require.NoError(t, err, "Error waiting for workload to be ready")
	}
	t.Log("All workloads are ready")

	t.Log("Waiting for all application profiles to be completed")
	for _, wl := range deployments {
		err = wl.WaitForContainerProfileCompletion(80)
		require.NoError(t, err, "Error waiting for application profile to be completed")
	}

	// wait for 1 minute for the alerts to be generated
	time.Sleep(1 * time.Minute)

	require.NoError(t, err, "Error getting pods with restarts")

	alerts, err := testutils.GetAlerts(ns.Name)
	require.NoError(t, err, "Error getting alerts")

	assert.Equal(t, 0, len(alerts), "Expected no alerts to be generated, but got %d alerts", len(alerts))
}

func Test_10_MalwareDetectionTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	t.Log("Creating namespace")
	ns := testutils.NewRandomNamespace()

	t.Log("Deploy container with malware")
	exitCode := testutils.RunCommand("kubectl", "run", "-n", ns.Name, "malware-cryptominer", "--image=quay.io/petr_ruzicka/malware-cryptominer-container:2.0.2")
	require.Equalf(t, 0, exitCode, "expected no error when deploying malware container")

	// Wait for pod to be ready
	exitCode = testutils.RunCommand("kubectl", "wait", "--for=condition=Ready", "pod", "malware-cryptominer", "-n", ns.Name, "--timeout=300s")
	require.Equalf(t, 0, exitCode, "expected no error when waiting for pod to be ready")

	// wait for application profile to be completed
	time.Sleep(3 * time.Minute)

	_, _, err := testutils.ExecIntoPod("malware-cryptominer", ns.Name, []string{"ls", "-l", "/usr/share/nginx/html/xmrig"}, "")
	require.NoErrorf(t, err, "expected no error when executing command in malware container")

	_, _, err = testutils.ExecIntoPod("malware-cryptominer", ns.Name, []string{"/usr/share/nginx/html/xmrig/xmrig"}, "")

	// wait for the alerts to be generated
	time.Sleep(20 * time.Second)

	alerts, err := testutils.GetMalwareAlerts(ns.Name)
	require.NoError(t, err, "Error getting alerts")

	expectedMalwares := []string{
		"Multios.Coinminer.Miner-6781728-2.UNOFFICIAL",
	}

	malwaresDetected := map[string]bool{}

	for _, alert := range alerts {
		podName, podNameOk := alert.Labels["pod_name"]
		malwareName, malwareNameOk := alert.Labels["malware_name"]

		if podNameOk && malwareNameOk {
			if podName == "malware-cryptominer" && slices.Contains(expectedMalwares, malwareName) {
				malwaresDetected[malwareName] = true
			}
		}
	}

	assert.Equal(t, len(expectedMalwares), len(malwaresDetected), "Expected %d malwares to be detected, but got %d malwares", len(expectedMalwares), len(malwaresDetected))
}

func Test_11_EndpointTest(t *testing.T) {
	threshold := 101
	ns := testutils.NewRandomNamespace()

	endpointTraffic, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/endpoint-traffic.yaml"))
	require.NoError(t, err, "Error creating workload")
	err = endpointTraffic.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	require.NoError(t, endpointTraffic.WaitForContainerProfile(80, "ready"))

	// Merge methods
	_, _, err = endpointTraffic.ExecIntoPod([]string{"wget", "http://127.0.0.1:80"}, "")
	require.NoError(t, err)
	_, _, err = endpointTraffic.ExecIntoPod([]string{"wget", "http://127.0.0.1:80", "-O", "/dev/null", "--post-data", "test-data"}, "") // avoid index.html already exists error

	// Merge dynamic
	for i := 0; i < threshold; i++ {
		_, _, err = endpointTraffic.ExecIntoPod([]string{"wget", fmt.Sprintf("http://127.0.0.1:80/users/%d", i)}, "")
	}

	// Wait for dedup cache entries to expire (~2s TTL) so the next requests
	// with different headers are not deduplicated before reaching the profile.
	time.Sleep(3 * time.Second)

	// Merge headers
	_, _, err = endpointTraffic.ExecIntoPod([]string{"wget", "http://127.0.0.1:80/users/99", "--header", "Connection:1234r"}, "")
	_, _, err = endpointTraffic.ExecIntoPod([]string{"wget", "http://127.0.0.1:80/users/12", "--header", "Connection:ziz"}, "")

	err = endpointTraffic.WaitForContainerProfileCompletion(80)
	require.NoError(t, err, "Error waiting for application profile to be completed")

	containerProfile, err := endpointTraffic.GetContainerProfile("endpoint-traffic")
	require.NoError(t, err, "Error getting container profile")

	headers := map[string][]string{"Connection": {"close"}, "Host": {"127.0.0.1:80"}}
	rawJSON, err := json.Marshal(headers)
	require.NoError(t, err)

	endpoint2 := v1beta1.HTTPEndpoint{
		Endpoint:  ":80/",
		Methods:   []string{"GET", "POST"},
		Internal:  false,
		Direction: "inbound",
		Headers:   rawJSON,
	}

	headers = map[string][]string{"Host": {"127.0.0.1:80"}, "Connection": {"1234r", "close", "ziz"}}
	rawJSON, err = json.Marshal(headers)
	require.NoError(t, err)

	endpoint1 := v1beta1.HTTPEndpoint{
		Endpoint:  ":80/users/" + dynamicpathdetector.DynamicIdentifier,
		Methods:   []string{"GET"},
		Internal:  false,
		Direction: "inbound",
		Headers:   rawJSON,
	}

	savedEndpoints := containerProfile.Spec.Endpoints

	for i := range savedEndpoints {

		headers := savedEndpoints[i].Headers
		var headersMap map[string][]string
		err := json.Unmarshal(headers, &headersMap)
		require.NoError(t, err, "Error unmarshalling headers")

		if headersMap["Connection"] != nil {
			sort.Strings(headersMap["Connection"])
			rawJSON, err = json.Marshal(headersMap)
			require.NoError(t, err)
			savedEndpoints[i].Headers = rawJSON
		}
	}

	expectedEndpoints := []v1beta1.HTTPEndpoint{endpoint1, endpoint2}
	for _, expectedEndpoint := range expectedEndpoints {
		found := false
		for _, savedEndpoint := range savedEndpoints {
			e := savedEndpoint
			sort.Strings(e.Methods)
			sort.Strings(expectedEndpoint.Methods)
			if reflect.DeepEqual(e, expectedEndpoint) {
				found = true
				break
			}
		}
		assert.Truef(t, found, "Expected endpoint %v not found in the container profile", expectedEndpoint)
	}
}

func Test_14_RulePoliciesTest(t *testing.T) {
	ns := testutils.NewRandomNamespace()

	endpointTraffic, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/endpoint-traffic.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}
	err = endpointTraffic.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	// Wait for application profile to be ready
	assert.NoError(t, endpointTraffic.WaitForContainerProfile(80, "ready"))
	time.Sleep(10 * time.Second)

	// Add to rule policy symlink
	_, _, err = endpointTraffic.ExecIntoPod([]string{"ln", "-s", "/etc/shadow", "/tmp/a"}, "")
	assert.NoError(t, err)

	_, _, err = endpointTraffic.ExecIntoPod([]string{"rm", "/tmp/a"}, "")
	assert.NoError(t, err)

	// Not add to rule policy
	_, _, err = endpointTraffic.ExecIntoPod([]string{"ln", "/bin/sh", "/tmp/a"}, "")
	assert.NoError(t, err)

	_, _, err = endpointTraffic.ExecIntoPod([]string{"rm", "/tmp/a"}, "")
	assert.NoError(t, err)

	require.NoError(t, endpointTraffic.WaitForContainerProfileCompletion(80),
		"Error waiting for container profile to be completed")

	containerProfile, err := endpointTraffic.GetContainerProfile("endpoint-traffic")
	require.NoError(t, err, "Error getting container profile")

	symlinkPolicy := containerProfile.Spec.PolicyByRuleId["R1010"]
	assert.Equal(t, []string{"ln"}, symlinkPolicy.AllowedProcesses)

	hardlinkPolicy := containerProfile.Spec.PolicyByRuleId["R1012"]
	assert.Len(t, hardlinkPolicy.AllowedProcesses, 0)

	fmt.Println("After completed....")

	// wait for cache
	time.Sleep(40 * time.Second)

	// generate hardlink alert
	_, _, err = endpointTraffic.ExecIntoPod([]string{"ln", "/etc/shadow", "/tmp/a"}, "")
	_, _, err = endpointTraffic.ExecIntoPod([]string{"rm", "/tmp/a"}, "")
	assert.NoError(t, err)

	// not generate alert
	_, _, err = endpointTraffic.ExecIntoPod([]string{"ln", "-s", "/etc/shadow", "/tmp/a"}, "")
	_, _, err = endpointTraffic.ExecIntoPod([]string{"rm", "/tmp/a"}, "")
	assert.NoError(t, err)

	// Wait for the alert to be signaled
	time.Sleep(30 * time.Second)

	alerts, err := testutils.GetAlerts(endpointTraffic.Namespace)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}

	testutils.AssertContains(t, alerts, "Hard link created over sensitive file", "ln", "endpoint-traffic", []bool{true})
	testutils.AssertNotContains(t, alerts, "Soft link created over sensitive file", "ln", "endpoint-traffic", []bool{true})

	// Also check for learning mode
	testutils.AssertContains(t, alerts, "Soft link created over sensitive file", "ln", "endpoint-traffic", []bool{false})
	testutils.AssertNotContains(t, alerts, "Hard link created over sensitive file", "ln", "endpoint-traffic", []bool{false})

}

func Test_15_CompletedApCannotBecomeReadyAgain(t *testing.T) {
	k8sClient := k8sinterface.NewKubernetesApi()
	storageclient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	ns := testutils.NewRandomNamespace()
	defer func() {
		_ = k8sClient.KubernetesClient.CoreV1().Namespaces().Delete(context.Background(), ns.Name, v1.DeleteOptions{})
	}()

	// create a container profile with completed status
	name := "test"
	cp1, err := storageclient.ContainerProfiles(ns.Name).Create(context.TODO(), &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
	}, v1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, helpersv1.Completed, cp1.Annotations[helpersv1.StatusMetadataKey])

	// patch the container profile with learning status
	patchOperations := []utils.PatchOperation{
		{
			Op:    "replace",
			Path:  "/metadata/annotations/" + utils.EscapeJSONPointerElement(helpersv1.StatusMetadataKey),
			Value: helpersv1.Learning,
		},
	}
	patch, err := json.Marshal(patchOperations)
	require.NoError(t, err)
	cp2, err := storageclient.ContainerProfiles(ns.Name).Patch(context.Background(), name, types.JSONPatchType, patch, v1.PatchOptions{})
	assert.NoError(t, err)                                                             // patch should succeed
	assert.Equal(t, helpersv1.Completed, cp2.Annotations[helpersv1.StatusMetadataKey]) // but the status should not change
}

func Test_16_ApNotStuckOnRestart(t *testing.T) {
	const containerName = "nginx"

	ns := testutils.NewRandomNamespace()

	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "Error creating workload")

	require.NoError(t, wl.WaitForReady(80))

	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	// A container restart spawns transient per-instance ContainerProfiles named
	// "<mergedName>-<32 hex>" that briefly flip failed/ready around the restart;
	// the stable MERGED profile that node-agent actually enforces has no such
	// suffix. The completion gate below therefore keys off the merged profile
	// only — not "all matching profiles completed" (WaitForContainerProfileCompletion),
	// which would hang on a lingering transient failed/ready per-instance profile.
	isMerged := func(name string) bool {
		i := strings.LastIndex(name, "-")
		if i < 0 || len(name)-i-1 != 32 {
			return true
		}
		for _, c := range name[i+1:] {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return true
			}
		}
		return false
	}
	mergedCompleted := func() (string, bool) {
		cps, e := storageClient.ContainerProfiles(ns.Name).List(context.Background(), metav1.ListOptions{})
		if e != nil {
			return "", false
		}
		for _, c := range cps.Items {
			if c.Labels["kubescape.io/workload-container-name"] != containerName || !isMerged(c.Name) {
				continue
			}
			if c.Annotations[helpersv1.StatusMetadataKey] == helpersv1.Completed {
				return c.Name, true
			}
		}
		return "", false
	}
	logCPs := func() {
		cps, e := storageClient.ContainerProfiles(ns.Name).List(context.Background(), metav1.ListOptions{})
		if e != nil {
			t.Logf("  <could not list ContainerProfiles: %v>", e)
			return
		}
		for _, c := range cps.Items {
			t.Logf("  CP %s status=%q completion=%q merged=%v", c.Name,
				c.Annotations[helpersv1.StatusMetadataKey],
				c.Annotations[helpersv1.CompletionMetadataKey], isMerged(c.Name))
		}
	}

	// Let the container run briefly, then stop nginx (PID 1) so the kubelet
	// restarts the container — the "does the profile get stuck on restart?"
	// scenario under test.
	time.Sleep(30 * time.Second)
	_, _, _ = wl.ExecIntoPod([]string{"service", "nginx", "stop"}, "") // expected to error: this kills the container

	require.NoError(t, wl.WaitForReady(80), "workload did not become ready again after restart")

	// GATE — replaces the former fixed time.Sleep(160s)+time.Sleep(15s). Wait
	// for the merged ContainerProfile to reach 'completed' (i.e. enforcing)
	// AFTER the restart. That is the real precondition for the violation below
	// to alert; the fixed sleep raced this and dropped the alert whenever the
	// completion (or its storage write, under load) ran past the timer. Bounded
	// deadline + dump the ContainerProfiles on timeout — never the 20m panic.
	restartReadyAt := time.Now()
	var mergedName string
	completionDeadline := time.Now().Add(5 * time.Minute)
	for {
		if n, ok := mergedCompleted(); ok {
			mergedName = n
			break
		}
		if time.Now().After(completionDeadline) {
			t.Logf("timeout waiting for merged ContainerProfile to complete after restart — current ContainerProfiles:")
			logCPs()
			t.Fatalf("merged ContainerProfile for container %q did not reach %q within 5m after restart", containerName, helpersv1.Completed)
		}
		time.Sleep(5 * time.Second)
	}
	completedAt := time.Now()
	t.Logf("merged ContainerProfile %q reached %q %s after restart-ready", mergedName, helpersv1.Completed, completedAt.Sub(restartReadyAt).Round(time.Second))

	// A completed/enforcing profile now exists; run a process that is NOT in it.
	t.Logf("exec 'ls -l' now — %s after profile completion", time.Since(completedAt).Round(time.Second))
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
	require.NoError(t, err)

	// Poll for the alert (replaces the fixed time.Sleep(30s)+single GetAlerts).
	var alerts []testutils.Alert
	require.Eventually(t, func() bool {
		alerts, _ = testutils.GetAlerts(wl.Namespace)
		for _, a := range alerts {
			if a.Labels["rule_name"] == "Unexpected process launched" &&
				a.Labels["comm"] == "ls" && a.Labels["container_name"] == containerName {
				return true
			}
		}
		return false
	}, 90*time.Second, 5*time.Second, "expected 'Unexpected process launched' alert for 'ls' in container 'nginx'")

	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "nginx", []bool{true})
}

func Test_17_ApCompletedToPartialUpdateTest(t *testing.T) {
	ns := testutils.NewRandomNamespace()

	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "Error creating workload")

	time.Sleep(30 * time.Second)
	require.NoError(t, wl.WaitForReady(80))
	require.NoError(t, wl.WaitForContainerProfile(80, "ready"))

	err = testutils.RestartDaemonSet("kubescape", "node-agent")
	require.NoError(t, err, "Error restarting daemonset")

	require.NoError(t, wl.WaitForContainerProfileCompletion(160))
	require.NoError(t, wl.WaitForContainerProfileCompletion(160))

	time.Sleep(30 * time.Second)

	_, _, err = wl.ExecIntoPod([]string{"sh", "-c", "cat /run/secrets/kubernetes.io/serviceaccount/token >/dev/null"}, "")
	require.NoError(t, err)

	time.Sleep(30 * time.Second)

	alerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Error getting alerts")

	testutils.AssertContains(t, alerts, "Unexpected service account token access", "cat", "nginx", []bool{true})
}

func Test_18_ShortLivedJobTest(t *testing.T) {
	ns := testutils.NewRandomNamespace()

	// Create a short-lived job
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/echo-job.yaml"))
	require.NoError(t, err, "Error creating workload")

	// Application profile should be created and completed
	err = wl.WaitForContainerProfileCompletion(80)
	require.NoError(t, err, "Error waiting for application profile to be completed")
}

func Test_19_AlertOnPartialProfileTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()

	// Create a workload
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "Error creating workload")

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	// Restart the daemonset
	err = testutils.RestartDaemonSet("kubescape", "node-agent")
	require.NoError(t, err, "Error restarting daemonset")

	// Wait for the application profile to be completed
	err = wl.WaitForContainerProfileCompletion(160)
	require.NoError(t, err, "Error waiting for application profile to be completed")

	profile, err := wl.GetContainerProfile("nginx")
	require.NoError(t, err, "Error getting container profile")

	require.Equal(t, helpersv1.Partial, profile.Annotations[helpersv1.CompletionMetadataKey])

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	// Generate an alert by executing a command
	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
	require.NoError(t, err, "Error executing command in pod")
	// Wait for the alert to be generated
	time.Sleep(15 * time.Second)
	alerts, err := testutils.GetAlerts(ns.Name)
	require.NoError(t, err, "Error getting alerts")
	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "nginx", []bool{true})
}

// Test_20_AlertOnPartialThenLearnProcessTest exercises process-execution
// ENFORCEMENT against an AUTHORED (user-defined) ContainerProfile, deterministically.
//
// SEMANTIC NOTE (flagged for review): this is NOT the old natural-learning /
// daemonset-restart / re-learn / blacklist dance. It authors the profile
// directly and then UPDATES it in place, so what it proves is profile
// ENFORCEMENT of an authored partial -> full profile, not that learning
// eventually captures the process. The core contract is preserved: a process
// NOT in the profile alerts (R0001); the SAME process, once added to the
// profile, does not.
//
// Determinism comes from a POSITIVE reload gate. The single update that ADDS
// the subject binary (ls) also REMOVES a canary binary (id). Because id was
// allowed before and forbidden after, it begins to fire R0001 the instant
// node-agent reloads the new revision — an alert-APPEARS signal (never a race
// on proving a negative) that confirms the reload took effect before we assert
// that ls has gone silent. Subject and canary are told apart by the alert
// `comm` label (real debian binaries => comm == binary basename).
func Test_20_AlertOnPartialThenLearnProcessTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const (
		overlayName   = "partial20-overlay"
		containerName = "app"
	)

	ns := testutils.NewRandomNamespace()
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	// Authored profile: allow the pod's baseline exec (sleep) and the canary
	// (id) but NOT the subject (ls).
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: overlayName, Namespace: ns.Name},
		Spec: v1beta1.ContainerProfileSpec{
			Execs: []v1beta1.ExecCalls{
				{Path: "/usr/bin/sleep"},
				{Path: "/usr/bin/id"},
			},
			LabelSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "partial20"}},
		},
	}
	_, err := storageClient.ContainerProfiles(ns.Name).Create(context.Background(), cp, metav1.CreateOptions{})
	require.NoError(t, err, "create authored ContainerProfile")
	require.Eventually(t, func() bool {
		_, e := storageClient.ContainerProfiles(ns.Name).Get(context.Background(), overlayName, v1.GetOptions{})
		return e == nil
	}, 30*time.Second, time.Second, "authored CP must be in storage before pod deploy")

	wl, err := testutils.NewTestWorkload(ns.Name,
		path.Join(utils.CurrentDir(), "resources/partial-process-deployment.yaml"))
	require.NoError(t, err, "create workload")
	require.NoError(t, wl.WaitForReady(80), "workload ready")

	// Count R0001 alerts for a given process comm in this container.
	countR0001 := func(comm string) int {
		alerts, _ := testutils.GetAlerts(ns.Name)
		n := 0
		for _, a := range alerts {
			if a.Labels["rule_id"] == "R0001" &&
				a.Labels["container_name"] == containerName &&
				a.Labels["comm"] == comm {
				n++
			}
		}
		return n
	}
	// On any stuck wait, dump the namespace's ContainerProfiles (name + status
	// + exec count) so a stuck state is visible immediately.
	logCPs := func() {
		cps, e := storageClient.ContainerProfiles(ns.Name).List(context.Background(), metav1.ListOptions{})
		if e != nil {
			t.Logf("  <could not list ContainerProfiles: %v>", e)
			return
		}
		for _, c := range cps.Items {
			t.Logf("  CP %s status=%q execs=%d", c.Name,
				c.Annotations[helpersv1.StatusMetadataKey], len(c.Spec.Execs))
		}
	}
	// Bounded poll: fail fast (never the 20m global panic) and dump CPs on
	// timeout. `cond` polls the real condition (alert present).
	waitFor := func(cond func() bool, timeout time.Duration, desc string) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(5 * time.Second)
		}
		t.Logf("timeout waiting for %s — current ContainerProfiles:", desc)
		logCPs()
		t.Fatalf("timeout after %s waiting for %s", timeout, desc)
	}

	// Give node-agent time to project the authored profile before generating
	// events (matches Test_28; evaluating an unloaded profile is unreliable).
	time.Sleep(30 * time.Second)

	// PHASE 1 — subject NOT in the profile must alert. Doubles as the
	// profile-load gate: once the authored CP is loaded, ls (not allowed)
	// fires R0001.
	waitFor(func() bool {
		wl.ExecIntoPod([]string{"/usr/bin/ls", "-l"}, containerName)
		return countR0001("ls") > 0
	}, 3*time.Minute, "R0001 for ls (subject not in authored profile)")
	t.Logf("phase1: R0001(ls)=%d on partial profile (expected >0)", countR0001("ls"))

	// UPDATE — add the subject (ls), remove the canary (id). One atomic
	// revision so the canary flip proves the ls addition also loaded.
	cur, err := storageClient.ContainerProfiles(ns.Name).Get(context.Background(), overlayName, v1.GetOptions{})
	require.NoError(t, err, "get CP for update")
	cur.Spec.Execs = []v1beta1.ExecCalls{
		{Path: "/usr/bin/sleep"},
		{Path: "/usr/bin/ls"},
	}
	_, err = storageClient.ContainerProfiles(ns.Name).Update(context.Background(), cur, metav1.UpdateOptions{})
	require.NoError(t, err, "update CP: add ls, remove id")

	// Propagation delay before the reload gate (not an assertion gate).
	time.Sleep(20 * time.Second)

	// RELOAD GATE (positive) — the removed canary (id) must now alert, which
	// proves node-agent reloaded the new revision (which also contains ls).
	waitFor(func() bool {
		wl.ExecIntoPod([]string{"/usr/bin/id"}, containerName)
		return countR0001("id") > 0
	}, 3*time.Minute, "R0001 for id (canary removed on update => proves reload)")
	t.Logf("reload confirmed: R0001(id)=%d", countR0001("id"))

	// PHASE 2 — the SAME subject, now in the profile, must NOT produce a NEW
	// R0001. Cooldown headroom (per-container/per-rule, count 10) is untouched
	// by the id-based gate, so a failed reload here would still let ls alert
	// and be caught — this is a real enforcement check, not a vacuous pass.
	before := countR0001("ls")
	// Guard against phase-1 self-exhaustion: if the per-container/per-rule R0001
	// cooldown budget (cap 10) were already spent, ls could not alert in phase 2
	// regardless of enforcement, making the "no NEW R0001" check below vacuous.
	require.Less(t, before, 10,
		"phase 1 exhausted the R0001 ls cooldown budget (before=%d, cap=10); phase 2 would pass vacuously", before)
	_, _, err = wl.ExecIntoPod([]string{"/usr/bin/ls", "-l"}, containerName)
	require.NoError(t, err, "exec ls after profile update")
	_, _, err = wl.ExecIntoPod([]string{"/usr/bin/ls", "-l"}, containerName)
	require.NoError(t, err, "exec ls after profile update")
	time.Sleep(20 * time.Second) // settle so any alert would have surfaced
	after := countR0001("ls")
	if after != before {
		logCPs()
	}
	require.Equal(t, before, after,
		"ls is now in the authored profile: no NEW R0001 expected (before=%d after=%d)", before, after)
}

// Test_21_AlertOnPartialThenLearnNetworkTest exercises network-egress
// ENFORCEMENT against an AUTHORED (user-defined) ContainerProfile,
// deterministically.
//
// SEMANTIC NOTE (flagged for review): like Test_20 this replaces natural
// learning with an authored profile updated in place, so it proves egress
// ENFORCEMENT of an authored partial -> full profile, not that learning
// captures the destination. Core contract preserved: a destination NOT in the
// egress list alerts; the SAME destination, once added, does not.
//
// The subject and the reload canary use DISTINCT rules so they never confuse
// each other (alerts carry no destination label, only the rule + comm):
//   - Subject: raw-IP TCP egress to 1.1.1.1:80 -> R0011 (no DNS, stable IP).
//   - Reload canary: DNS lookup of fusioncore.ai -> R0005.
//
// The single update ADDS 1.1.1.1 to egress and REMOVES fusioncore.ai, so
// nslookup fusioncore.ai starts firing R0005 the instant the new revision
// loads — the positive reload gate — while the subject IP goes silent. Each
// step mirrors a proven Test_28 subtest (28c: curl 1.1.1.1 -> R0011; 28b:
// unknown domain -> R0005; 28a: listed destination -> no alert).
func Test_21_AlertOnPartialThenLearnNetworkTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const (
		overlayName   = "partial21-overlay"
		containerName = "curl"
		subjectIP     = "1.1.1.1"
		canaryDomain  = "fusioncore.ai"
		fusioncoreIP  = "162.0.217.171"
	)
	port80 := int32(80)

	ns := testutils.NewRandomNamespace()
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	// Authored profile: egress allows the canary domain (fusioncore.ai) only;
	// the subject IP (1.1.1.1) is NOT allowed. Execs/syscalls are listed only
	// to keep unrelated rules quiet — the assertions key on R0011/R0005.
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: overlayName, Namespace: ns.Name},
		Spec: v1beta1.ContainerProfileSpec{
			Execs: []v1beta1.ExecCalls{
				{Path: "/bin/sleep"},
				{Path: "/usr/bin/curl"},
				{Path: "/usr/bin/nslookup"},
				{Path: "/usr/bin/wget"},
			},
			Syscalls:      []string{"socket", "connect", "sendto", "recvfrom", "read", "write", "close", "openat", "mmap", "mprotect", "munmap", "fcntl", "ioctl", "poll", "epoll_create1", "epoll_ctl", "epoll_wait", "bind", "listen", "accept4", "getsockopt", "setsockopt", "getsockname", "getpid", "fstat", "rt_sigaction", "rt_sigprocmask", "writev", "execve"},
			LabelSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "partial21"}},
			Egress: []v1beta1.NetworkNeighbor{
				{
					Identifier: "canary-egress",
					Type:       v1beta1.CommunicationTypeEgress,
					DNS:        canaryDomain + ".",
					DNSNames:   []string{canaryDomain + "."},
					IPAddress:  fusioncoreIP,
					Ports:      []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: v1beta1.ProtocolTCP, Port: &port80}},
				},
			},
		},
	}
	_, err := storageClient.ContainerProfiles(ns.Name).Create(context.Background(), cp, metav1.CreateOptions{})
	require.NoError(t, err, "create authored ContainerProfile")
	require.Eventually(t, func() bool {
		_, e := storageClient.ContainerProfiles(ns.Name).Get(context.Background(), overlayName, v1.GetOptions{})
		return e == nil
	}, 30*time.Second, time.Second, "authored CP must be in storage before pod deploy")

	wl, err := testutils.NewTestWorkload(ns.Name,
		path.Join(utils.CurrentDir(), "resources/partial-network-deployment.yaml"))
	require.NoError(t, err, "create workload")
	require.NoError(t, wl.WaitForReady(80), "workload ready")

	countRule := func(ruleID string) int {
		alerts, _ := testutils.GetAlerts(ns.Name)
		n := 0
		for _, a := range alerts {
			if a.Labels["rule_id"] == ruleID && a.Labels["container_name"] == containerName {
				n++
			}
		}
		return n
	}
	logCPs := func() {
		cps, e := storageClient.ContainerProfiles(ns.Name).List(context.Background(), metav1.ListOptions{})
		if e != nil {
			t.Logf("  <could not list ContainerProfiles: %v>", e)
			return
		}
		for _, c := range cps.Items {
			t.Logf("  CP %s status=%q egress=%d", c.Name,
				c.Annotations[helpersv1.StatusMetadataKey], len(c.Spec.Egress))
		}
	}
	waitFor := func(cond func() bool, timeout time.Duration, desc string) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(5 * time.Second)
		}
		t.Logf("timeout waiting for %s — current ContainerProfiles:", desc)
		logCPs()
		t.Fatalf("timeout after %s waiting for %s", timeout, desc)
	}

	// Let node-agent project the authored profile before generating traffic.
	time.Sleep(30 * time.Second)

	// PHASE 1 — subject IP NOT in egress must alert (R0011). Doubles as the
	// profile-load gate.
	waitFor(func() bool {
		wl.ExecIntoPod([]string{"curl", "-sm5", "http://" + subjectIP}, containerName)
		return countRule("R0011") > 0
	}, 3*time.Minute, "R0011 for curl "+subjectIP+" (subject IP not in egress)")
	t.Logf("phase1: R0011=%d on partial profile (expected >0)", countRule("R0011"))

	// UPDATE — add the subject IP to egress, remove the canary domain.
	cur, err := storageClient.ContainerProfiles(ns.Name).Get(context.Background(), overlayName, v1.GetOptions{})
	require.NoError(t, err, "get CP for update")
	cur.Spec.Egress = []v1beta1.NetworkNeighbor{
		{
			Identifier: "subject-egress",
			Type:       v1beta1.CommunicationTypeEgress,
			IPAddress:  subjectIP,
			Ports:      []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: v1beta1.ProtocolTCP, Port: &port80}},
		},
	}
	_, err = storageClient.ContainerProfiles(ns.Name).Update(context.Background(), cur, metav1.UpdateOptions{})
	require.NoError(t, err, "update CP: add subject IP, remove canary domain")

	// Propagation delay before the reload gate (not an assertion gate).
	time.Sleep(20 * time.Second)

	// RELOAD GATE (positive) — the removed canary domain must now fire R0005,
	// proving node-agent reloaded the new revision (which also allows the
	// subject IP). R0005 (DNS) is a distinct rule from the subject's R0011, so
	// the two signals never cross-talk.
	waitFor(func() bool {
		wl.ExecIntoPod([]string{"nslookup", canaryDomain}, containerName)
		return countRule("R0005") > 0
	}, 3*time.Minute, "R0005 for nslookup "+canaryDomain+" (canary domain removed => proves reload)")
	t.Logf("reload confirmed: R0005=%d", countRule("R0005"))

	// PHASE 2 — the SAME subject IP, now in egress, must NOT produce a NEW
	// R0011.
	before := countRule("R0011")
	wl.ExecIntoPod([]string{"curl", "-sm5", "http://" + subjectIP}, containerName)
	wl.ExecIntoPod([]string{"curl", "-sm5", "http://" + subjectIP}, containerName)
	time.Sleep(20 * time.Second) // settle so any alert would have surfaced
	after := countRule("R0011")
	if after != before {
		logCPs()
	}
	require.Equal(t, before, after,
		"%s is now in the authored egress: no NEW R0011 expected (before=%d after=%d)", subjectIP, before, after)
}

func Test_22_AlertOnPartialNetworkProfileTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()

	// Create a workload
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/deployment-multiple-containers.yaml"))
	require.NoError(t, err, "Error creating workload")

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	// Restart the daemonset
	err = testutils.RestartDaemonSet("kubescape", "node-agent")
	require.NoError(t, err, "Failed to restart daemonset")

	// Wait for the network neighborhood to be completed
	err = wl.WaitForContainerProfileCompletion(160)
	require.NoError(t, err, "Error waiting for network neighborhood to be completed")

	// Wait for cache to be updated
	time.Sleep(15 * time.Second)

	// Generate an alert by making an unexpected network request
	_, _, err = wl.ExecIntoPod([]string{"curl", "google.com", "-m", "5"}, "nginx")
	require.NoError(t, err, "Error executing network command in pod")

	// Wait for the alert to be generated
	time.Sleep(15 * time.Second)
	alerts, err := testutils.GetAlerts(ns.Name)
	require.NoError(t, err, "Error getting alerts")
	testutils.AssertContains(t, alerts, "DNS Anomalies in container", "curl", "nginx", []bool{true})
}

func Test_23_RuleCooldownTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()

	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "Error creating workload")

	require.NoError(t, wl.WaitForContainerProfileCompletion(80))

	// Wait for cache
	time.Sleep(30 * time.Second)

	// Run the same process 20 times
	for i := 0; i < 20; i++ {
		_, _, err = wl.ExecIntoPod([]string{"ls", "-l"}, "")
		require.NoError(t, err)
		time.Sleep(1 * time.Second)
	}

	// Wait for alerts to be processed
	time.Sleep(30 * time.Second)

	// Get all alerts
	alerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Error getting alerts")

	// Count alerts for "Unexpected process launched" rule
	alertCount := 0
	for _, alert := range alerts {
		if ruleName, ok := alert.Labels["rule_name"]; ok && ruleName == "Unexpected process launched" {
			alertCount++
		}
	}

	// We should get exactly 10 alerts (cooldown threshold) even though we ran the process 20 times
	assert.Equal(t, 10, alertCount, "Expected exactly 10 alerts due to cooldown threshold, got %d", alertCount)

	// Verify the specific alert details
	testutils.AssertContains(t, alerts, "Unexpected process launched", "ls", "nginx", []bool{true})
}

func Test_24_ProcessTreeDepthTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()

	endpointTraffic, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/tree.yaml"))
	require.NoError(t, err, "Error creating workload")

	err = endpointTraffic.WaitForReady(80)
	require.NoError(t, err, "Error waiting for workload to be ready")

	err = endpointTraffic.WaitForContainerProfileCompletion(80)
	require.NoError(t, err, "Error waiting for application profile to be completed")

	// wait for cache
	time.Sleep(30 * time.Second)

	// Add to rule policy symlink
	buf, _, err := endpointTraffic.ExecIntoPod([]string{"/bin/sh", "-c", "python3 /root/python_spawner.py 10"}, "")
	require.NoError(t, err)

	t.Logf("Output: %s", buf)

	t.Logf("Waiting for the alert to be signaled")

	// Wait for the alert to be signaled
	time.Sleep(2 * time.Minute)

	alerts, err := testutils.GetAlerts(endpointTraffic.Namespace)
	require.NoError(t, err, "Error getting alerts")

	found := false

	for _, alert := range alerts {
		if alert.Labels["rule_name"] == "Unexpected process launched" {
			if alert.Labels["processtree_depth"] == "10" {
				found = true
				break
			}
		}
	}

	assert.Truef(t, found, "Expected to find an alert for the process tree depth")

	t.Logf("Found alerts for the process tree depth: %v", alerts)
}

// Test_27_ApplicationProfileOpens tests that the dynamic path matching in
// application profiles works correctly for both recorded (auto-learned)
// profiles and user-defined profiles.
//
// Path matching symbols:
//
//	⋯  (U+22EF DynamicIdentifier)  — matches exactly ONE path segment
//	*  (WildcardIdentifier)         — matches ZERO or more path segments
//	0  (in endpoints)               — wildcard port (any port)
//
// R0002 "Files Access Anomalies in container" fires when a file is opened
// under a monitored prefix (/etc/, /var/log/, …) and the path was NOT
// recorded in the application profile.
func Test_27_ApplicationProfileOpens(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)
	defer enableR0002ForTest(t)()

	const ruleName = "Files Access Anomalies in container"
	const profileName = "nginx-regex-profile"

	// --- result tracking for end-of-test summary ---
	type subtestResult struct {
		name        string
		profilePath string
		filePath    string
		expectAlert bool
		passed      bool
		detail      string
	}
	var results []subtestResult
	addResult := func(name, profilePath, filePath string, expectAlert, passed bool, detail string) {
		results = append(results, subtestResult{name, profilePath, filePath, expectAlert, passed, detail})
	}
	defer func() {
		t.Log("\n========== Test_27 Summary ==========")
		anyFailed := false
		for _, r := range results {
			status := "PASS"
			if !r.passed {
				status = "FAIL"
				anyFailed = true
			}
			expect := "expect alert"
			if !r.expectAlert {
				expect = "expect NO alert"
			}
			t.Logf("  [%s] %-35s profile=%-25s file=%-25s %s", status, r.name, r.profilePath, r.filePath, expect)
			if !r.passed {
				t.Logf("         -> %s", r.detail)
			}
		}
		if !anyFailed {
			t.Log("  All subtests passed.")
		}
		t.Log("======================================")
	}()

	// deployWithProfile creates a user-defined ContainerProfile with the given
	// Opens list, then deploys nginx bound to it via the
	// kubescape.io/user-defined-profile label and waits for readiness.
	deployWithProfile := func(t *testing.T, opens []v1beta1.OpenCalls) *testutils.TestWorkload {
		t.Helper()
		ns := testutils.NewRandomNamespace()

		profile := &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      profileName,
				Namespace: ns.Name,
			},
			Spec: v1beta1.ContainerProfileSpec{
				Architectures: []string{"amd64"},
				Execs: []v1beta1.ExecCalls{
					{Path: "/bin/cat", Args: []string{"/bin/cat"}},
				},
				Opens: opens,
			},
		}

		k8sClient := k8sinterface.NewKubernetesApi()
		storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)
		_, err := storageClient.ContainerProfiles(ns.Name).Create(
			context.Background(), profile, metav1.CreateOptions{})
		require.NoError(t, err, "create user-defined ContainerProfile %q in ns %s", profileName, ns.Name)

		require.Eventually(t, func() bool {
			_, cpErr := storageClient.ContainerProfiles(ns.Name).Get(
				context.Background(), profileName, v1.GetOptions{})
			return cpErr == nil
		}, 30*time.Second, 1*time.Second, "CP must be retrievable from storage before deploying the pod")

		wl, err := testutils.NewTestWorkload(ns.Name,
			path.Join(utils.CurrentDir(), "resources/nginx-user-profile-deployment.yaml"))
		require.NoError(t, err, "create workload in ns %s", ns.Name)
		require.NoError(t, wl.WaitForReady(80), "workload not ready in ns %s", ns.Name)

		// Wait for node-agent to load the user-defined profile into cache.
		time.Sleep(10 * time.Second)
		return wl
	}

	// triggerAndGetAlerts execs cat on the given path, then polls for alerts
	// up to 60s to avoid race conditions with alert propagation.
	triggerAndGetAlerts := func(t *testing.T, wl *testutils.TestWorkload, filePath string) []testutils.Alert {
		t.Helper()
		stdout, stderr, err := wl.ExecIntoPod([]string{"cat", filePath}, "nginx")
		if err != nil {
			t.Errorf("exec 'cat %s' in container nginx failed: %v (stdout=%q stderr=%q)", filePath, err, stdout, stderr)
		}
		// Poll for alerts — they may take time to propagate through
		// eBPF → node-agent → alertmanager.
		var alerts []testutils.Alert
		require.Eventually(t, func() bool {
			alerts, err = testutils.GetAlerts(wl.Namespace)
			return err == nil
		}, 60*time.Second, 5*time.Second, "alerts must be retrievable from ns %s", wl.Namespace)
		// Give extra time for all alerts to arrive after first successful fetch.
		time.Sleep(10 * time.Second)
		alerts, err = testutils.GetAlerts(wl.Namespace)
		require.NoError(t, err, "get alerts from ns %s", wl.Namespace)
		return alerts
	}

	// hasAlert checks whether an R0002 alert exists for comm=cat, container=nginx.
	hasAlert := func(alerts []testutils.Alert) bool {
		for _, a := range alerts {
			if a.Labels["rule_name"] == ruleName &&
				a.Labels["comm"] == "cat" &&
				a.Labels["container_name"] == "nginx" {
				return true
			}
		}
		return false
	}

	// ---------------------------------------------------------------
	// 1a. Recorded (auto-learned) profile must use absolute paths.
	//     There must be no "." in the Opens paths.
	// ---------------------------------------------------------------
	t.Run("recorded_profile_absolute_paths", func(t *testing.T) {
		ns := testutils.NewRandomNamespace()
		wl, err := testutils.NewTestWorkload(ns.Name,
			path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
		require.NoError(t, err)
		require.NoError(t, wl.WaitForReady(80))
		require.NoError(t, wl.WaitForContainerProfileCompletion(80))

		profiles, err := wl.GetContainerProfiles()
		require.NoError(t, err, "get container profiles")

		passed := true
		// A fully resolved open path never begins with a numeric first segment.
		// One that does is a scrambled, prefix-stripped path: a /proc/<pid> residue
		// (/17/setgroups) or a k8s atomic-writer "..<ts>" projected-volume prefix
		// that lost its root (/8011833/master.conf, /03_16_52_09.../token).
		// Regression guard for #721/#872 and the full-path resolution fix.
		scrambledPath := regexp.MustCompile(`^/[0-9]`)
		checkOpens := func(cpName, containerName string, opens []v1beta1.OpenCalls) {
			for _, open := range opens {
				if !strings.HasPrefix(open.Path, "/") {
					t.Errorf("recorded path must be absolute: got %q (%s container %s)", open.Path, cpName, containerName)
					passed = false
				}
				if open.Path == "." {
					t.Errorf("recorded path must not be relative dot: got %q (%s container %s)", open.Path, cpName, containerName)
					passed = false
				}
				if scrambledPath.MatchString(open.Path) {
					t.Errorf("scrambled (prefix-stripped) open path: got %q (%s container %s) — a resolved path never begins with a numeric segment", open.Path, cpName, containerName)
					passed = false
				}
			}
		}

		for _, profile := range profiles {
			checkOpens(profile.Name, profile.Labels["kubescape.io/workload-container-name"], profile.Spec.Opens)
		}

		// Distro-wide scan: the scrambled paths originally surfaced in real distro
		// workloads (redis/valkey mounted-etc, health-check scripts, service-account
		// tokens), so scan EVERY learned ContainerProfile across all namespaces, not
		// only this test's workload. Best-effort: a failed cluster-wide list is not fatal.
		k8sClient := k8sinterface.NewKubernetesApi()
		storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)
		if allCPs, listErr := storageClient.ContainerProfiles(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{}); listErr != nil {
			t.Logf("distro-wide scrambled-path scan skipped (cluster-wide list failed): %v", listErr)
		} else {
			for i := range allCPs.Items {
				cp := &allCPs.Items[i]
				checkOpens(cp.Namespace+"/"+cp.Name, cp.Labels["kubescape.io/workload-container-name"], cp.Spec.Opens)
			}
		}
		detail := ""
		if !passed {
			detail = "found non-absolute or '.' paths in recorded profile"
		}
		addResult("recorded_profile_absolute_paths", "(auto-learned)", "(nginx startup)", false, passed, detail)
	})

	// ---------------------------------------------------------------
	// 1b. User-defined profile wildcard tests.
	//     Each sub-test deploys nginx in its own namespace with a
	//     different Opens pattern and verifies R0002 behaviour.
	// ---------------------------------------------------------------

	// 1b-1: Exact path — profile has the exact file => no alert.
	t.Run("exact_path_match", func(t *testing.T) {
		profilePath := "/etc/nginx/nginx.conf"
		filePath := "/etc/nginx/nginx.conf"
		wl := deployWithProfile(t, []v1beta1.OpenCalls{
			{Path: profilePath, Flags: []string{"O_RDONLY"}},
			{Path: "/etc/ld.so.cache", Flags: []string{"O_RDONLY", "O_CLOEXEC"}}, // dynamic linker opens this on every exec
		})
		alerts := triggerAndGetAlerts(t, wl, filePath)
		got := hasAlert(alerts)
		if got {
			t.Errorf("expected NO R0002 alert: profile allows %q, opened %q, but alert fired", profilePath, filePath)
		}
		addResult("exact_path_match", profilePath, filePath, false, !got,
			fmt.Sprintf("got %d alerts, expected none for cat", len(alerts)))
	})

	// 1b-2: Exact path — profile has a DIFFERENT file => alert.
	t.Run("exact_path_mismatch", func(t *testing.T) {
		profilePath := "/etc/nginx/nginx.conf"
		filePath := "/etc/hostname"
		wl := deployWithProfile(t, []v1beta1.OpenCalls{
			{Path: profilePath, Flags: []string{"O_RDONLY"}},
		})
		alerts := triggerAndGetAlerts(t, wl, filePath)
		got := hasAlert(alerts)
		if !got {
			t.Errorf("expected R0002 alert: profile only allows %q, opened %q, but no alert", profilePath, filePath)
		}
		addResult("exact_path_mismatch", profilePath, filePath, true, got,
			fmt.Sprintf("got %d alerts, expected at least one for cat", len(alerts)))
	})

	// 1b-3: Ellipsis ⋯ matches single segment — /etc/⋯ covers /etc/hostname.
	t.Run("ellipsis_single_segment_match", func(t *testing.T) {
		profilePath := "/etc/" + dynamicpathdetector.DynamicIdentifier
		filePath := "/etc/hostname"
		wl := deployWithProfile(t, []v1beta1.OpenCalls{
			{Path: profilePath, Flags: []string{"O_RDONLY"}},
		})
		alerts := triggerAndGetAlerts(t, wl, filePath)
		got := hasAlert(alerts)
		if got {
			t.Errorf("expected NO R0002 alert: profile %q should match %q (single segment), but alert fired", profilePath, filePath)
		}
		addResult("ellipsis_single_segment_match", profilePath, filePath, false, !got,
			fmt.Sprintf("got %d alerts, expected none for cat", len(alerts)))
	})

	// 1b-4: Ellipsis ⋯ rejects multi-segment — /etc/⋯ does NOT cover
	//        /etc/nginx/nginx.conf (two segments past /etc/).
	t.Run("ellipsis_rejects_multi_segment", func(t *testing.T) {
		profilePath := "/etc/" + dynamicpathdetector.DynamicIdentifier
		filePath := "/etc/nginx/nginx.conf"
		wl := deployWithProfile(t, []v1beta1.OpenCalls{
			{Path: profilePath, Flags: []string{"O_RDONLY"}},
		})
		alerts := triggerAndGetAlerts(t, wl, filePath)
		got := hasAlert(alerts)
		if !got {
			t.Errorf("expected R0002 alert: profile %q should NOT match %q (two segments), but no alert", profilePath, filePath)
		}
		addResult("ellipsis_rejects_multi_segment", profilePath, filePath, true, got,
			fmt.Sprintf("got %d alerts, expected at least one for cat", len(alerts)))
	})

	// 1b-5: Wildcard * matches any depth — /etc/* covers /etc/nginx/nginx.conf.
	t.Run("wildcard_matches_deep_path", func(t *testing.T) {
		profilePath := "/etc/*"
		filePath := "/etc/nginx/nginx.conf"
		wl := deployWithProfile(t, []v1beta1.OpenCalls{
			{Path: profilePath, Flags: []string{"O_RDONLY"}},
		})
		alerts := triggerAndGetAlerts(t, wl, filePath)
		got := hasAlert(alerts)
		if got {
			t.Errorf("expected NO R0002 alert: profile %q should match %q (wildcard), but alert fired", profilePath, filePath)
		}
		addResult("wildcard_matches_deep_path", profilePath, filePath, false, !got,
			fmt.Sprintf("got %d alerts, expected none for cat", len(alerts)))
	})

	// ---------------------------------------------------------------
	// 1c. Deploy known-application-profile-wildcards.yaml (curl image)
	//     and verify that files under wildcard-covered opens paths
	//     produce no R0002 alert.
	// ---------------------------------------------------------------
	t.Run("wildcard_yaml_profile_allowed_opens", func(t *testing.T) {
		ns := testutils.NewRandomNamespace()
		wildcardProfileName := "fusioncore-profile-wildcards"

		// Create the profile matching known-application-profile-wildcards.yaml.
		profile := &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      wildcardProfileName,
				Namespace: ns.Name,
			},
			Spec: v1beta1.ContainerProfileSpec{
				Architectures: []string{"amd64"},
				ImageID:       "docker.io/curlimages/curl@sha256:08e466006f0860e54fc299378de998935333e0e130a15f6f98482e9f8dab3058",
				ImageTag:      "docker.io/curlimages/curl:8.5.0",
				Capabilities: []string{
					"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
					"CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID", "CAP_SYS_ADMIN",
				},
				Execs: []v1beta1.ExecCalls{
					{Path: "/bin/sleep", Args: []string{"/bin/sleep", "infinity"}},
					{Path: "/bin/cat", Args: []string{"/bin/cat"}},
					{Path: "/usr/bin/curl", Args: []string{"/usr/bin/curl", "-sm2", "fusioncore.ai"}},
				},
				Opens: []v1beta1.OpenCalls{
					{Path: "/etc/*", Flags: []string{"O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"}},
					{Path: "/etc/ssl/openssl.cnf", Flags: []string{"O_RDONLY", "O_LARGEFILE"}},
					{Path: "/home/*", Flags: []string{"O_RDONLY", "O_LARGEFILE"}},
					{Path: "/lib/*", Flags: []string{"O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"}},
					{Path: "/usr/lib/*", Flags: []string{"O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"}},
					{Path: "/usr/local/lib/*", Flags: []string{"O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"}},
					{Path: "/proc/*/cgroup", Flags: []string{"O_RDONLY", "O_CLOEXEC"}},
					{Path: "/proc/*/kernel/cap_last_cap", Flags: []string{"O_RDONLY", "O_CLOEXEC"}},
					{Path: "/proc/*/mountinfo", Flags: []string{"O_RDONLY", "O_CLOEXEC"}},
					{Path: "/proc/*/task/*/fd", Flags: []string{"O_RDONLY", "O_DIRECTORY", "O_CLOEXEC"}},
					{Path: "/sys/fs/cgroup/cpu.max", Flags: []string{"O_RDONLY", "O_CLOEXEC"}},
					{Path: "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", Flags: []string{"O_RDONLY"}},
					{Path: "/7/setgroups", Flags: []string{"O_RDONLY", "O_CLOEXEC"}},
					{Path: "/runc", Flags: []string{"O_RDONLY", "O_CLOEXEC"}},
				},
				Syscalls: []string{
					"arch_prctl", "bind", "brk", "capget", "capset", "chdir",
					"clone", "close", "close_range", "connect", "epoll_ctl",
					"epoll_pwait", "execve", "exit", "exit_group", "faccessat2",
					"fchown", "fcntl", "fstat", "fstatfs", "futex", "getcwd",
					"getdents64", "getegid", "geteuid", "getgid", "getpeername",
					"getppid", "getsockname", "getsockopt", "gettid", "getuid",
					"ioctl", "membarrier", "mmap", "mprotect", "munmap",
					"nanosleep", "newfstatat", "open", "openat", "openat2",
					"pipe", "poll", "prctl", "read", "recvfrom", "recvmsg",
					"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sendto",
					"set_tid_address", "setgid", "setgroups", "setsockopt",
					"setuid", "sigaltstack", "socket", "statx", "tkill",
					"unknown", "write", "writev",
				},
			},
		}

		k8sClient := k8sinterface.NewKubernetesApi()
		storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)
		_, err := storageClient.ContainerProfiles(ns.Name).Create(
			context.Background(), profile, metav1.CreateOptions{})
		require.NoError(t, err, "create wildcard ContainerProfile %q in ns %s", wildcardProfileName, ns.Name)

		require.Eventually(t, func() bool {
			_, cpErr := storageClient.ContainerProfiles(ns.Name).Get(
				context.Background(), wildcardProfileName, v1.GetOptions{})
			return cpErr == nil
		}, 30*time.Second, 1*time.Second, "CP must be retrievable before deploying the pod")

		wl, err := testutils.NewTestWorkload(ns.Name,
			path.Join(utils.CurrentDir(), "resources/curl-user-profile-wildcards-deployment.yaml"))
		require.NoError(t, err, "create curl workload in ns %s", ns.Name)
		require.NoError(t, wl.WaitForReady(80), "curl workload not ready in ns %s", ns.Name)

		// Wait for node-agent to load the user-defined profile into cache.
		time.Sleep(10 * time.Second)

		// Cat files that are covered by the wildcard opens.
		allowedFiles := []string{
			"/etc/hosts",           // covered by /etc/*
			"/etc/resolv.conf",     // covered by /etc/*
			"/etc/ssl/openssl.cnf", // exact match
		}
		for _, f := range allowedFiles {
			stdout, stderr, err := wl.ExecIntoPod([]string{"cat", f}, "curl")
			if err != nil {
				t.Logf("exec 'cat %s' failed: %v (stdout=%q stderr=%q)", f, err, stdout, stderr)
			}
		}

		// Poll for alerts to propagate.
		time.Sleep(15 * time.Second)
		alerts, err := testutils.GetAlerts(wl.Namespace)
		require.NoError(t, err, "get alerts from ns %s", wl.Namespace)

		var r0002Fired bool
		for _, a := range alerts {
			if a.Labels["rule_name"] == ruleName &&
				a.Labels["comm"] == "cat" &&
				a.Labels["container_name"] == "curl" {
				r0002Fired = true
				break
			}
		}
		if r0002Fired {
			t.Errorf("expected NO R0002 for files covered by wildcard opens, but alert fired")
		}
		addResult("wildcard_yaml_profile_allowed_opens",
			"/etc/*, /etc/ssl/openssl.cnf", "/etc/hosts, /etc/resolv.conf, /etc/ssl/openssl.cnf",
			false, !r0002Fired,
			fmt.Sprintf("got R0002=%v, expected none for wildcard-covered files", r0002Fired))
	})
}

func Test_33_AnalyzeOpensWildcardAnchoring(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)
	// R0002 file-access monitoring is opt-in (monitored prefixes incl. /etc/);
	// without this the rule never evaluates opens and every "expect alert"
	// anchoring case silently passes as a no-alert. Test_27 enables it the same
	// way; Test_33 was missing it (it had never run in CI to expose the gap).
	defer enableR0002ForTest(t)()

	const ruleName = "Files Access Anomalies in container"
	const profileName = "nginx-regex-profile"

	type subtestResult struct {
		name        string
		profilePath string
		filePath    string
		expectAlert bool
		passed      bool
		detail      string
	}
	var results []subtestResult
	addResult := func(name, profilePath, filePath string, expectAlert, passed bool, detail string) {
		results = append(results, subtestResult{name, profilePath, filePath, expectAlert, passed, detail})
	}
	defer func() {
		t.Log("\n========== Test_33 Summary ==========")
		anyFailed := false
		for _, r := range results {
			status := "PASS"
			if !r.passed {
				status = "FAIL"
				anyFailed = true
			}
			expect := "expect alert"
			if !r.expectAlert {
				expect = "expect NO alert"
			}
			t.Logf("  [%s] %-50s profile=%-25s file=%-30s %s", status, r.name, r.profilePath, r.filePath, expect)
			if !r.passed {
				t.Logf("         -> %s", r.detail)
			}
		}
		if !anyFailed {
			t.Log("  All subtests passed.")
		}
		t.Log("======================================")
	}()

	// deployWithProfile creates a user-defined AP with a single Opens
	// entry (plus a couple of always-needed paths nginx hits at startup),
	// then deploys nginx with the user-defined-profile label pointing at
	// it and waits for the pod + cache load.
	deployWithProfile := func(t *testing.T, profilePath string) *testutils.TestWorkload {
		t.Helper()
		ns := testutils.NewRandomNamespace()

		profile := &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      profileName,
				Namespace: ns.Name,
			},
			Spec: v1beta1.ContainerProfileSpec{
				Architectures: []string{"amd64"},
				Execs: []v1beta1.ExecCalls{
					{Path: "/bin/cat", Args: []string{"/bin/cat"}},
				},
				Opens: []v1beta1.OpenCalls{
					{Path: profilePath, Flags: []string{"O_RDONLY"}},
					// Dynamic linker fires this on every exec — keep it whitelisted.
					{Path: "/etc/ld.so.cache", Flags: []string{"O_RDONLY", "O_CLOEXEC"}},
				},
			},
		}

		k8sClient := k8sinterface.NewKubernetesApi()
		storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)
		_, err := storageClient.ContainerProfiles(ns.Name).Create(
			context.Background(), profile, metav1.CreateOptions{})
		require.NoError(t, err, "create user-defined ContainerProfile %q in ns %s", profileName, ns.Name)

		require.Eventually(t, func() bool {
			_, cpErr := storageClient.ContainerProfiles(ns.Name).Get(
				context.Background(), profileName, v1.GetOptions{})
			return cpErr == nil
		}, 30*time.Second, 1*time.Second, "CP must be retrievable from storage before deploying the pod")

		wl, err := testutils.NewTestWorkload(ns.Name,
			path.Join(utils.CurrentDir(), "resources/nginx-user-profile-deployment.yaml"))
		require.NoError(t, err, "create workload in ns %s", ns.Name)
		// 11 subtests deploy a fresh pod sequentially, so each later subtest
		// races against an increasingly loaded kind cluster — the upstream
		// CP cache reconciler, alertmanager, and prometheus all chew CPU at
		// boot. 80s timed out intermittently; 180s gives headroom without
		// pushing the total test runtime into a different regime.
		require.NoError(t, wl.WaitForReady(180), "workload not ready in ns %s", ns.Name)

		// Wait for node-agent to load the user-defined profile into cache.
		time.Sleep(10 * time.Second)
		return wl
	}

	// catAndAlerts execs `cat <path>` (ignoring cat's own exit error —
	// catting a directory or a non-readable file still triggers the
	// open() syscall the eBPF tracer captures), then polls for alerts.
	catAndAlerts := func(t *testing.T, wl *testutils.TestWorkload, filePath string) []testutils.Alert {
		t.Helper()
		stdout, stderr, _ := wl.ExecIntoPod([]string{"cat", filePath}, "nginx")
		t.Logf("cat %q → stdout=%q stderr=%q", filePath, stdout, stderr)

		var alerts []testutils.Alert
		require.Eventually(t, func() bool {
			a, err := testutils.GetAlerts(wl.Namespace)
			if err != nil {
				return false
			}
			alerts = a
			return true
		}, 60*time.Second, 5*time.Second, "alerts must be retrievable from ns %s", wl.Namespace)
		// Settle so any late R0002 alert lands before we count.
		time.Sleep(10 * time.Second)
		alerts, err := testutils.GetAlerts(wl.Namespace)
		require.NoError(t, err, "get alerts from ns %s", wl.Namespace)
		return alerts
	}

	// hasR0002 returns true if any R0002 alert fired for `cat` in the
	// nginx container.
	hasR0002 := func(alerts []testutils.Alert) bool {
		for _, a := range alerts {
			if a.Labels["rule_name"] == ruleName &&
				a.Labels["comm"] == "cat" &&
				a.Labels["container_name"] == "nginx" {
				return true
			}
		}
		return false
	}

	tests := []struct {
		name        string
		profilePath string
		filePath    string
		expectAlert bool
		why         string // contract pinned by this case
	}{
		// ─── Trailing-`*` anchoring (the security fix) ──────────────
		//
		// IMPORTANT: R0002's CEL ruleExpression has a strict prefix
		// filter (event.path.startsWith('/etc/'), startsWith('/var/log/'),
		// etc. — all with trailing slash). Bare `/etc` and `/var/log`
		// don't match those prefixes, so the rule never evaluates on
		// them and the matcher's anchoring contract stays invisible at
		// runtime. Probe one level deeper instead — `/etc/ssl` IS under
		// the `/etc/` monitored prefix, so R0002 CAN see whether a
		// `/etc/ssl/*` profile entry matches the bare `/etc/ssl` parent.
		{
			name:        "trailing_star_matches_immediate_child",
			profilePath: "/etc/*",
			filePath:    "/etc/hosts",
			expectAlert: false,
			why:         "/etc/* matches a one-segment child under /etc",
		},
		{
			name:        "trailing_star_matches_deep_child",
			profilePath: "/etc/*",
			filePath:    "/etc/ssl/openssl.cnf",
			expectAlert: false,
			why:         "/etc/* matches a multi-segment path under /etc (mid-path zero-or-more)",
		},
		{
			name:        "trailing_star_does_not_match_bare_parent_under_monitored_prefix",
			profilePath: "/etc/ssl/*",
			filePath:    "/etc/ssl",
			expectAlert: true,
			why:         "/etc/ssl/* must NOT match the bare /etc/ssl directory itself — pins the security fix at a path R0002's prefix filter can observe",
		},
		{
			name:        "deep_prefix_trailing_star_does_not_match_parent",
			profilePath: "/etc/ssl/certs/*",
			filePath:    "/etc/ssl/certs",
			expectAlert: true,
			why:         "Same anchoring rule, deeper: /etc/ssl/certs/* does NOT match /etc/ssl/certs",
		},

		// ─── DynamicIdentifier (⋯) exactly-one ──────────────────────
		{
			name:        "ellipsis_requires_one_segment_not_zero",
			profilePath: "/etc/passwd/" + dynamicpathdetector.DynamicIdentifier,
			filePath:    "/etc/passwd",
			expectAlert: true,
			why:         "⋯ consumes EXACTLY ONE segment; /etc/passwd/⋯ requires one more, /etc/passwd alone has zero past — must fire R0002",
		},

		// ─── Mixed ⋯/* combinations ─────────────────────────────────
		{
			name:        "ellipsis_then_trailing_star_matches_two_segment_tail",
			profilePath: "/proc/" + dynamicpathdetector.DynamicIdentifier + "/*",
			filePath:    "/proc/1/status",
			expectAlert: false,
			why:         "/proc/⋯/* matches /proc/1/status (⋯ consumes 1, * consumes ≥1)",
		},
		{
			name:        "ellipsis_then_trailing_star_matches_three_segment_tail",
			profilePath: "/proc/" + dynamicpathdetector.DynamicIdentifier + "/*",
			filePath:    "/proc/1/task/1",
			expectAlert: false,
			why:         "/proc/⋯/* matches deeper paths (⋯ consumes 1, * consumes ≥1 covering rest)",
		},

		// ─── Multiple trailing wildcards ────────────────────────────
		{
			name:        "double_trailing_matches_one_child",
			profilePath: "/etc/*/*",
			filePath:    "/etc/ssl",
			expectAlert: false,
			why:         "/etc/*/* matches /etc/ssh (mid-* consumes zero, trailing-* consumes one)",
		},
		{
			name:        "double_trailing_matches_deep_child",
			profilePath: "/etc/*/*",
			filePath:    "/etc/ssl/openssl.cnf",
			expectAlert: false,
			why:         "/etc/*/* matches /etc/ssl/openssl.cnf (mid-* consumes one, trailing-* consumes one)",
		},
		{
			name:        "double_trailing_does_not_match_parent_under_monitored_prefix",
			profilePath: "/etc/ssl/*/*",
			filePath:    "/etc/ssl",
			expectAlert: true,
			why:         "/etc/ssl/*/* requires at least one segment past /etc/ssl; bare /etc/ssl must NOT match (probed under /etc/ so R0002 sees it)",
		},

		// ─── splitPath trailing-slash normalisation ─────────────────
		{
			name:        "trailing_slash_in_profile_normalises_to_literal",
			profilePath: "/etc/passwd/",
			filePath:    "/etc/passwd",
			expectAlert: false,
			why:         "Profile `/etc/passwd/` is normalised to `/etc/passwd`; matches the literal at runtime",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("contract: %s", tc.why)
			wl := deployWithProfile(t, tc.profilePath)
			alerts := catAndAlerts(t, wl, tc.filePath)
			got := hasR0002(alerts)

			detail := fmt.Sprintf("got %d alerts total; R0002 fired = %v", len(alerts), got)
			passed := got == tc.expectAlert
			if !passed {
				if tc.expectAlert {
					t.Errorf("expected R0002 alert: profile %q must NOT match %q (%s); but no alert fired",
						tc.profilePath, tc.filePath, tc.why)
				} else {
					t.Errorf("expected NO R0002 alert: profile %q should match %q (%s); but alert fired",
						tc.profilePath, tc.filePath, tc.why)
				}
			}
			addResult(tc.name, tc.profilePath, tc.filePath, tc.expectAlert, passed, detail)
		})
	}
}

func Test_32_UnexpectedProcessArguments(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const overlayName = "curl-32-overlay"

	setup := func(t *testing.T) (*testutils.TestWorkload, int) {
		t.Helper()
		ns := testutils.NewRandomNamespace()
		k8sClient := k8sinterface.NewKubernetesApi()
		storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

		cp := &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      overlayName,
				Namespace: ns.Name,
			},
			Spec: v1beta1.ContainerProfileSpec{
				Execs: []v1beta1.ExecCalls{
					// storage's CompareExecArgs is a strict positional compare, so
					// Args[0] must equal runtime argv[0] (the absolute path invoked).
					// pod startup: sleep <anything>
					{Path: "/bin/sleep", Args: []string{"/bin/sleep", dynamicpathdetector.ExecArgsWildcard}},
					// sh -c <anything trailing>
					{Path: "/bin/sh", Args: []string{"/bin/sh", "-c", dynamicpathdetector.ExecArgsWildcard}},
					// echo hello <anything trailing>
					{Path: "/bin/echo", Args: []string{"/bin/echo", "hello", dynamicpathdetector.ExecArgsWildcard}},
					// curl -s <one URL>
					{Path: "/usr/bin/curl", Args: []string{"/usr/bin/curl", "-s", dynamicpathdetector.DynamicIdentifier}},
					// curl -s <one URL> file:///etc/hosts file:///etc/hostname
					// — a ⋯ in a NON-trailing position: it matches exactly
					// one arg, and the LITERAL args after it must still
					// anchor. (file:// URLs are used as the post-⋯ literals
					// so curl reads local files and exits 0.)
					{Path: "/usr/bin/curl", Args: []string{"/usr/bin/curl", "-s", dynamicpathdetector.DynamicIdentifier, "file:///etc/hosts", "file:///etc/hostname"}},
					// Busybox-symlink mirrors: the curl image's /bin/{sleep,sh,echo}
					// resolve to /bin/busybox (exepath), which the rule keys on. These
					// entries are required or R0001 fires before R0040 is reached.
					{Path: "/bin/busybox", Args: []string{"/bin/sleep", dynamicpathdetector.ExecArgsWildcard}},
					{Path: "/bin/busybox", Args: []string{"/bin/sh", "-c", dynamicpathdetector.ExecArgsWildcard}},
					{Path: "/bin/busybox", Args: []string{"/bin/echo", "hello", dynamicpathdetector.ExecArgsWildcard}},
					// Literal "*" is DATA, not a wildcard: matches only `echo star *`,
					// never `echo star <other>` (busybox + symlink forms).
					{Path: "/bin/echo", Args: []string{"/bin/echo", "star", "*"}},
					{Path: "/bin/busybox", Args: []string{"/bin/echo", "star", "*"}},
				},
				Syscalls: []string{"socket", "connect", "sendto", "recvfrom", "read", "write", "close", "openat", "mmap", "mprotect", "munmap", "fcntl", "ioctl", "poll", "epoll_create1", "epoll_ctl", "epoll_wait", "bind", "listen", "accept4", "getsockopt", "setsockopt", "getsockname", "getpid", "fstat", "rt_sigaction", "rt_sigprocmask", "writev", "execve"},
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "curl-32"},
				},
			},
		}
		_, err := storageClient.ContainerProfiles(ns.Name).Create(
			context.Background(), cp, metav1.CreateOptions{})
		require.NoError(t, err, "create user-defined ContainerProfile")

		require.Eventually(t, func() bool {
			_, cpErr := storageClient.ContainerProfiles(ns.Name).Get(context.Background(), overlayName, v1.GetOptions{})
			return cpErr == nil
		}, 30*time.Second, 1*time.Second, "user-defined CP must be in storage before pod deploy")

		wl, err := testutils.NewTestWorkload(ns.Name,
			path.Join(utils.CurrentDir(), "resources/curl-exec-arg-wildcards-deployment.yaml"))
		require.NoError(t, err)
		require.NoError(t, wl.WaitForReady(80))

		// Profile-load gate: wait until the user-defined CP is projected before
		// asserting. The canary is a deterministic argv mismatch ([echo, <probe>])
		// that must fire R0040 once the profile loads; we retry until it does and
		// return the post-gate R0040 count so subtests assert on the delta.
		countR0040 := func(alerts []testutils.Alert) int {
			n := 0
			for _, a := range alerts {
				if a.Labels["rule_id"] == "R0040" {
					n++
				}
			}
			return n
		}
		require.Eventually(t, func() bool {
			if _, _, err := wl.ExecIntoPod([]string{"echo", "__profile_probe__"}, "curl"); err != nil {
				return false
			}
			alerts, _ := testutils.GetAlerts(ns.Name)
			return countR0040(alerts) > 0
		}, 180*time.Second, 10*time.Second,
			"user overlay must project (canary R0040 must fire) before subtests run")
		// settle so all in-flight canary alerts are counted into the baseline
		time.Sleep(10 * time.Second)
		alerts, _ := testutils.GetAlerts(ns.Name)
		return wl, countR0040(alerts)
	}

	countByRule := func(alerts []testutils.Alert, ruleID string) int {
		n := 0
		for _, a := range alerts {
			if a.Labels["rule_id"] == ruleID {
				n++
			}
		}
		return n
	}

	waitAlerts := func(t *testing.T, ns string) []testutils.Alert {
		t.Helper()
		var alerts []testutils.Alert
		var err error
		require.Eventually(t, func() bool {
			alerts, err = testutils.GetAlerts(ns)
			return err == nil
		}, 60*time.Second, 5*time.Second, "must be able to fetch alerts")
		// settle time for any in-flight alerts
		time.Sleep(10 * time.Second)
		alerts, _ = testutils.GetAlerts(ns)
		return alerts
	}

	logAlerts := func(t *testing.T, alerts []testutils.Alert) {
		t.Helper()
		for i, a := range alerts {
			t.Logf("  [%d] %s(%s) comm=%s container=%s",
				i, a.Labels["rule_name"], a.Labels["rule_id"],
				a.Labels["comm"], a.Labels["container_name"])
		}
	}

	// R0001 silence is a precondition for every subtest below: it means
	// parse.get_exec_path resolved to the profile's Path key, so R0040
	// gets to evaluate its argv comparison cleanly. A non-zero R0001 for
	// the test binary's comm means the recording / capture / resolution
	// chain dropped event.exepath — that's a separate bug (track it in
	// the recording side, not in R0040), and asserting it here fails the
	// subtest on the right axis instead of polluting the R0040 signal.
	assertR0001Silent := func(t *testing.T, alerts []testutils.Alert, comm string) {
		t.Helper()
		n := 0
		for _, a := range alerts {
			if a.Labels["rule_id"] == "R0001" && a.Labels["comm"] == comm {
				n++
			}
		}
		require.Zero(t, n,
			"R0001 precondition: path resolution failed for comm=%q. "+
				"parse.get_exec_path either didn't receive event.exepath or "+
				"profile Path doesn't match its return value. Fix capture-side "+
				"exepath before reading R0040 results from this subtest.", comm)
	}

	// -----------------------------------------------------------------
	// 32a. sh -c <anything>  — argv [sh, -c, "echo hi"] matches
	//      profile [sh, -c, ⋯⋯]. R0040 must NOT fire.
	// -----------------------------------------------------------------
	t.Run("sh_dash_c_matches_wildcard_trailing", func(t *testing.T) {
		wl, base := setup(t)
		// Warm the cache: retry the exec until it runs cleanly so the user
		// overlay is loaded, then settle and assert R0040 stays silent
		// (mirrors Test_28 no-alert idiom). A matching argv must not alert.
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"sh", "-c", "echo hi"}, "curl")
			return err == nil
		}, 60*time.Second, 5*time.Second, "exec must run")
		time.Sleep(20 * time.Second)
		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "sh")
		assert.Equal(t, base, countByRule(alerts, "R0040"),
			"sh -c <cmd> matches profile [sh, -c, ⋯⋯]: R0040 must stay silent")
	})

	// -----------------------------------------------------------------
	// 32b. sh -x -c <cmd>  — argv [sh, -x, -c, "echo hi"] does NOT match
	//      profile [sh, -c, ⋯⋯] (literal anchor `-c` at position 1 mismatches
	//      `-x`). Path /bin/sh (or /bin/busybox) IS in profile so R0001
	//      stays silent. R0040 must fire.
	//
	//      Earlier shape `sh -x "echo hi"` exited 2 (busybox sh tried to
	//      open "echo hi" as a script file) — kubectl exec returned an
	//      error and require.NoError tripped before R0040 could be read.
	//      Adding -c keeps sh's invocation valid while preserving the
	//      argv-shape mismatch that exercises R0040.
	// -----------------------------------------------------------------
	t.Run("sh_dash_x_mismatches_R0040", func(t *testing.T) {
		wl, base := setup(t)
		// Retry the trigger until node-agent has loaded the user overlay
		// into the ContainerProfileCache and R0040 fires. The overlay loads
		// asynchronously, so a single exec can race the load and the
		// profile-dependent rule is suppressed (mirrors Test_28). The
		// command is idempotent, so re-exec is side-effect-free.
		var alerts []testutils.Alert
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"sh", "-x", "-c", "echo hi"}, "curl")
			if err != nil {
				return false
			}
			alerts = waitAlerts(t, wl.Namespace)
			return countByRule(alerts, "R0040") > base
		}, 120*time.Second, 10*time.Second, "sh -x mismatches profile [sh, -c, ⋯⋯]: R0040 must fire")
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "sh")
		require.Greater(t, countByRule(alerts, "R0040"), base,
			"sh -x mismatches profile [sh, -c, ⋯⋯]: R0040 must fire")
	})

	// -----------------------------------------------------------------
	// 32c. echo hello <anything> — argv [echo, hello, world, from, test]
	//      matches profile [echo, hello, ⋯⋯]. R0040 must NOT fire.
	// -----------------------------------------------------------------
	t.Run("echo_hello_matches_wildcard_trailing", func(t *testing.T) {
		wl, base := setup(t)
		// Warm the cache: retry the exec until it runs cleanly so the user
		// overlay is loaded, then settle and assert R0040 stays silent
		// (mirrors Test_28 no-alert idiom). A matching argv must not alert.
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"echo", "hello", "world", "from", "test"}, "curl")
			return err == nil
		}, 60*time.Second, 5*time.Second, "exec must run")
		time.Sleep(20 * time.Second)
		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "echo")
		assert.Equal(t, base, countByRule(alerts, "R0040"),
			"echo hello <words> matches profile [echo, hello, ⋯⋯]: R0040 must stay silent")
	})

	// -----------------------------------------------------------------
	// 32d. echo goodbye <anything> — argv [echo, goodbye, world] does
	//      NOT match profile [echo, hello, ⋯⋯] (literal anchor `hello`
	//      mismatch). R0040 must fire.
	// -----------------------------------------------------------------
	t.Run("echo_goodbye_mismatches_R0040", func(t *testing.T) {
		wl, base := setup(t)
		// Retry the trigger until node-agent has loaded the user overlay
		// into the ContainerProfileCache and R0040 fires. The overlay loads
		// asynchronously, so a single exec can race the load and the
		// profile-dependent rule is suppressed (mirrors Test_28). The
		// command is idempotent, so re-exec is side-effect-free.
		var alerts []testutils.Alert
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"echo", "goodbye", "world"}, "curl")
			if err != nil {
				return false
			}
			alerts = waitAlerts(t, wl.Namespace)
			return countByRule(alerts, "R0040") > base
		}, 120*time.Second, 10*time.Second, "echo goodbye <words> mismatches profile [echo, hello, ⋯⋯] (literal anchor): R0040 must fire")
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "echo")
		require.Greater(t, countByRule(alerts, "R0040"), base,
			"echo goodbye <words> mismatches profile [echo, hello, ⋯⋯] (literal anchor): R0040 must fire")
	})

	// -----------------------------------------------------------------
	// 32e. curl -s <one URL> — the NON-symlinked binary (curl is a real
	//      binary in curlimages/curl, not a busybox applet) with an
	//      ELLIPSIS profile: [curl, -s, ⋯]. ⋯ matches EXACTLY ONE arg, so
	//      `curl -s <single url>` matches → R0040 silent.
	//
	//      A file:// URL is used so curl reads a local file and exits 0
	//      regardless of cluster egress — the test pins argv matching, not
	//      network reachability.
	// -----------------------------------------------------------------
	t.Run("curl_dash_s_one_url_matches_ellipsis", func(t *testing.T) {
		wl, base := setup(t)
		// Warm the cache: retry the exec until it runs cleanly so the user
		// overlay is loaded, then settle and assert R0040 stays silent
		// (mirrors Test_28 no-alert idiom). A matching argv must not alert.
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"curl", "-s", "file:///etc/hostname"}, "curl")
			return err == nil
		}, 60*time.Second, 5*time.Second, "exec must run")
		time.Sleep(20 * time.Second)
		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "curl")
		assert.Equal(t, base, countByRule(alerts, "R0040"),
			"curl -s <one url> matches profile [curl, -s, dyn]: R0040 must stay silent")
	})

	// -----------------------------------------------------------------
	// 32f. curl -s <two URLs> — argv [curl, -s, url1, url2] does NOT match
	//      profile [curl, -s, ⋯] because ⋯ consumes EXACTLY ONE arg, not
	//      two. R0040 must fire. Pins the ⋯ (DynamicIdentifier) arity on
	//      the non-symlinked path. Both file:// URLs are readable so curl
	//      still exits 0.
	// -----------------------------------------------------------------
	t.Run("curl_dash_s_two_urls_mismatches_R0040", func(t *testing.T) {
		wl, base := setup(t)
		// Retry the trigger until node-agent has loaded the user overlay
		// into the ContainerProfileCache and R0040 fires. The overlay loads
		// asynchronously, so a single exec can race the load and the
		// profile-dependent rule is suppressed (mirrors Test_28). The
		// command is idempotent, so re-exec is side-effect-free.
		var alerts []testutils.Alert
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"curl", "-s", "file:///etc/hostname", "file:///etc/hosts"}, "curl")
			if err != nil {
				return false
			}
			alerts = waitAlerts(t, wl.Namespace)
			return countByRule(alerts, "R0040") > base
		}, 120*time.Second, 10*time.Second, "curl -s <two urls> exceeds the single-arg dyn token in profile [curl, -s, dyn]: R0040 must fire")
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "curl")
		require.Greater(t, countByRule(alerts, "R0040"), base,
			"curl -s <two urls> exceeds the single-arg dyn token in profile [curl, -s, dyn]: R0040 must fire")
	})

	// -----------------------------------------------------------------
	// 32g. echo star <other> — argv [echo, star, boom] does NOT match
	//      profile [echo, star, *] because the profile's "*" is a LITERAL
	//      character, not a wildcard. The path IS in profile (R0001 silent)
	//      but the argv mismatches at position 2 → R0040 must fire. This is
	//      the core symbol-contract guard: a recorded literal "*" must NOT
	//      broaden to an arbitrary arg (the over-broadening that blocked the
	//      merge). Mirrors storage's TestAP_LiteralStarVsDynamic.
	// -----------------------------------------------------------------
	t.Run("echo_literal_star_does_not_broaden_R0040", func(t *testing.T) {
		wl, base := setup(t)
		var alerts []testutils.Alert
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"echo", "star", "boom"}, "curl")
			if err != nil {
				return false
			}
			alerts = waitAlerts(t, wl.Namespace)
			return countByRule(alerts, "R0040") > base
		}, 120*time.Second, 10*time.Second, "echo star boom mismatches profile [echo, star, *] (literal star, no broaden): R0040 must fire")
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "echo")
		require.Greater(t, countByRule(alerts, "R0040"), base,
			"echo star boom mismatches profile [echo, star, *] (literal star, no broaden): R0040 must fire")
	})

	// -----------------------------------------------------------------
	// 32h. echo star "*" — argv [echo, star, *] (a genuine literal "*"
	//      argument, passed unexpanded via exec, no shell) DOES match
	//      profile [echo, star, *] exactly. R0040 must stay silent. Pins the
	//      other half of the literal-"*" contract: data matches its own
	//      value verbatim.
	// -----------------------------------------------------------------
	t.Run("echo_literal_star_matches_itself", func(t *testing.T) {
		wl, base := setup(t)
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"echo", "star", "*"}, "curl")
			return err == nil
		}, 60*time.Second, 5*time.Second, "exec must run")
		time.Sleep(20 * time.Second)
		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "echo")
		assert.Equal(t, base, countByRule(alerts, "R0040"),
			"echo star * matches profile [echo, star, *] (literal): R0040 must stay silent")
	})

	// -----------------------------------------------------------------
	// 32i. curl -s <one URL> file:///etc/hosts file:///etc/hostname —
	//      argv [curl, -s, <url>, file:///etc/hosts, file:///etc/hostname]
	//      matches profile [curl, -s, ⋯, file:///etc/hosts,
	//      file:///etc/hostname]. The ⋯ sits MID-VECTOR: it consumes exactly
	//      the one <url> arg, and the two LITERAL args after it anchor. All
	//      three URLs are readable file:// paths so curl exits 0. R0040 must
	//      stay silent.
	// -----------------------------------------------------------------
	t.Run("curl_dash_s_mid_ellipsis_then_literals_matches", func(t *testing.T) {
		wl, base := setup(t)
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"curl", "-s", "file:///etc/group", "file:///etc/hosts", "file:///etc/hostname"}, "curl")
			return err == nil
		}, 60*time.Second, 5*time.Second, "exec must run")
		time.Sleep(20 * time.Second)
		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "curl")
		assert.Equal(t, base, countByRule(alerts, "R0040"),
			"curl -s <url> file:///etc/hosts file:///etc/hostname matches profile [curl, -s, ⋯, <lit>, <lit>]: R0040 must stay silent")
	})

	// -----------------------------------------------------------------
	// 32j. curl -s <one URL> file:///etc/hosts file:///etc/group — the LAST
	//      literal mismatches the profile's anchor (profile ends
	//      file:///etc/hostname, runtime ends file:///etc/group). The ⋯ and
	//      the first literal still match, so this pins that literals AFTER a
	//      mid-vector ⋯ are enforced — a mismatch there fires R0040. All URLs
	//      are readable so curl exits 0; only the argv shape differs.
	// -----------------------------------------------------------------
	t.Run("curl_dash_s_mid_ellipsis_trailing_literal_mismatch_R0040", func(t *testing.T) {
		wl, base := setup(t)
		var alerts []testutils.Alert
		require.Eventually(t, func() bool {
			_, _, err := wl.ExecIntoPod([]string{"curl", "-s", "file:///etc/group", "file:///etc/hosts", "file:///etc/group"}, "curl")
			if err != nil {
				return false
			}
			alerts = waitAlerts(t, wl.Namespace)
			return countByRule(alerts, "R0040") > base
		}, 120*time.Second, 10*time.Second, "curl trailing literal mismatches profile [curl, -s, ⋯, <lit>, file:///etc/hostname]: R0040 must fire")
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)
		assertR0001Silent(t, alerts, "curl")
		require.Greater(t, countByRule(alerts, "R0040"), base,
			"curl trailing literal mismatches profile [curl, -s, ⋯, <lit>, file:///etc/hostname]: R0040 must fire")
	})
}

// applyUserDefinedContainerProfile reads a ContainerProfile example yaml (the
// copy-pasteable authoring example), stamps it into ns, and creates it. A
// user-managed CP carries only name + spec — the pod's user-defined-profile
// label is what binds it; no lifecycle annotations are needed.
func applyUserDefinedContainerProfile(t *testing.T, ns, resourcePath string) *v1beta1.ContainerProfile {
	t.Helper()
	b, err := os.ReadFile(path.Join(utils.CurrentDir(), resourcePath))
	require.NoError(t, err, "read %s", resourcePath)
	var cp v1beta1.ContainerProfile
	require.NoError(t, yaml.Unmarshal(b, &cp), "unmarshal %s", resourcePath)
	cp.Namespace = ns
	cp.ResourceVersion = ""
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)
	_, err = storageClient.ContainerProfiles(ns).Create(context.Background(), &cp, metav1.CreateOptions{})
	require.NoError(t, err, "create ContainerProfile from %s", resourcePath)
	require.Eventually(t, func() bool {
		_, e := storageClient.ContainerProfiles(ns).Get(context.Background(), cp.Name, v1.GetOptions{})
		return e == nil
	}, 30*time.Second, time.Second, "CP from %s must be in storage before pod deploy", resourcePath)
	return &cp
}

func Test_28_UserDefinedNetworkNeighborhood(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// setup deploys a pod bound to an authored ContainerProfile whose egress
	// allows only fusioncore.ai (162.0.217.171) on TCP/80.
	setup := func(t *testing.T) *testutils.TestWorkload {
		t.Helper()
		ns := testutils.NewRandomNamespace()

		const overlayName = "curl-28-overlay"

		// The user authors ONE ContainerProfile (merging the former AP + NN
		// surfaces); the pod's kubescape.io/user-defined-profile label names it.
		_ = applyUserDefinedContainerProfile(t, ns.Name, "resources/containerprofile-user-defined-network.yaml")

		wl, err := testutils.NewTestWorkload(ns.Name,
			path.Join(utils.CurrentDir(), "resources/nginx-user-defined-deployment.yaml"))
		require.NoError(t, err)
		require.NoError(t, wl.WaitForReady(80))
		// Give node-agent time to load the profile before generating traffic;
		// evaluating against an unloaded profile fires R0005/R0011 spuriously.
		time.Sleep(30 * time.Second)
		return wl
	}

	countByRule := func(alerts []testutils.Alert, ruleID string) int {
		n := 0
		for _, a := range alerts {
			if a.Labels["rule_id"] == ruleID {
				n++
			}
		}
		return n
	}

	waitAlerts := func(t *testing.T, ns string) []testutils.Alert {
		t.Helper()
		var alerts []testutils.Alert
		var err error
		require.Eventually(t, func() bool {
			alerts, err = testutils.GetAlerts(ns)
			return err == nil
		}, 60*time.Second, 5*time.Second, "must be able to fetch alerts")
		// Extra settle time for remaining alerts.
		time.Sleep(10 * time.Second)
		alerts, _ = testutils.GetAlerts(ns)
		return alerts
	}

	logAlerts := func(t *testing.T, alerts []testutils.Alert) {
		t.Helper()
		for i, a := range alerts {
			t.Logf("  [%d] %s(%s) comm=%s container=%s",
				i, a.Labels["rule_name"], a.Labels["rule_id"],
				a.Labels["comm"], a.Labels["container_name"])
		}
	}

	// ---------------------------------------------------------------
	// 28a. Allowed traffic — fusioncore.ai is in the NN.
	//      No R0005 (DNS) and no R0011 (egress) expected.
	// ---------------------------------------------------------------
	t.Run("allowed_fusioncore_no_alert", func(t *testing.T) {
		wl := setup(t)

		// DNS lookup via nslookup (domain in NN).
		stdout, stderr, err := wl.ExecIntoPod([]string{"nslookup", "fusioncore.ai"}, "curl")
		t.Logf("nslookup fusioncore.ai → err=%v stdout=%q stderr=%q", err, stdout, stderr)

		// HTTP via curl (domain + IP in NN).
		stdout, stderr, err = wl.ExecIntoPod([]string{"curl", "-sm5", "http://fusioncore.ai"}, "curl")
		t.Logf("curl fusioncore.ai → err=%v stdout=%q stderr=%q", err, stdout, stderr)

		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)

		assert.Equal(t, 0, countByRule(alerts, "R0005"),
			"fusioncore.ai is in NN — should NOT fire R0005")
		assert.Equal(t, 0, countByRule(alerts, "R0011"),
			"fusioncore.ai IP is in NN — should NOT fire R0011")
	})

	// ---------------------------------------------------------------
	// 28b. Unknown domains — domains NOT in the NN → R0005.
	//      Uses both nslookup (pure DNS) and curl (DNS + TCP).
	// ---------------------------------------------------------------
	t.Run("unknown_domain_R0005", func(t *testing.T) {
		wl := setup(t)

		// nslookup generates a DNS query without any TCP connection.
		wl.ExecIntoPod([]string{"nslookup", "google.com"}, "curl")
		// curl resolves + connects.
		wl.ExecIntoPod([]string{"curl", "-sm5", "http://ebpf.io"}, "curl")
		wl.ExecIntoPod([]string{"curl", "-sm5", "http://cloudflare.com"}, "curl")

		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)

		require.Greater(t, countByRule(alerts, "R0005"), 0,
			"unknown domains must fire R0005")
	})

	// ---------------------------------------------------------------
	// 28c. Unknown IPs — raw IP egress NOT in the NN → R0011.
	// ---------------------------------------------------------------
	t.Run("unknown_ip_R0011", func(t *testing.T) {
		wl := setup(t)

		wl.ExecIntoPod([]string{"curl", "-sm5", "http://8.8.8.8"}, "curl")
		wl.ExecIntoPod([]string{"curl", "-sm5", "http://1.1.1.1"}, "curl")

		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)

		require.Greater(t, countByRule(alerts, "R0011"), 0,
			"IPs not in NN must fire R0011")
	})

	// ---------------------------------------------------------------
	// 28d. MITM — DNS spoofing simulation.
	//      fusioncore.ai is an allowed domain but the IP is spoofed.
	//
	//      Step 1: nslookup fusioncore.ai (legitimate DNS, no alert).
	//      Step 2: curl --resolve fusioncore.ai:80:8.8.4.4
	//              Simulates a DNS MITM returning a different IP.
	//              The domain is allowed but the connection goes to
	//              8.8.4.4 (not 162.0.217.171) → R0011.
	// ---------------------------------------------------------------
	t.Run("mitm_spoofed_ip_R0011", func(t *testing.T) {
		wl := setup(t)

		// Step 1: Legitimate DNS lookup — no alert expected.
		wl.ExecIntoPod([]string{"nslookup", "fusioncore.ai"}, "curl")

		// Step 2: MITM — domain resolves to spoofed IP 8.8.4.4.
		// curl --resolve skips DNS and connects directly to the
		// spoofed IP, simulating what happens after DNS poisoning.
		stdout, stderr, err := wl.ExecIntoPod(
			[]string{"curl", "-sm5", "--resolve", "fusioncore.ai:80:8.8.4.4", "http://fusioncore.ai"}, "curl")
		t.Logf("curl MITM → err=%v stdout=%q stderr=%q", err, stdout, stderr)

		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)

		require.Greater(t, countByRule(alerts, "R0011"), 0,
			"MITM: fusioncore.ai allowed but spoofed IP 8.8.4.4 must fire R0011")
	})

	// ---------------------------------------------------------------
	// 28e. MITM — real CoreDNS poisoning via template plugin.
	//      Poisons CoreDNS so fusioncore.ai resolves to 8.8.4.4
	//      instead of the legitimate 162.0.217.171.
	//
	//      nslookup triggers the poisoned DNS response.
	//      R0005 does NOT fire: fusioncore.ai is in the NN egress
	//      list and BusyBox nslookup does NOT do PTR reverse-lookups.
	//      R0011 does NOT fire: no TCP egress (DNS is UDP to cluster
	//      DNS which is a private IP filtered by is_private_ip).
	//
	//      This documents a detection gap: pure DNS MITM (without
	//      subsequent TCP to the spoofed IP) is invisible to both
	//      R0005 and R0011 when the domain is already whitelisted.
	//
	//      NOTE: this subtest MUST run last — it modifies the
	//      cluster-wide CoreDNS configmap.
	// ---------------------------------------------------------------
	t.Run("mitm_coredns_poisoning", func(t *testing.T) {
		wl := setup(t)
		ctx := context.Background()
		k8sClient := k8sinterface.NewKubernetesApi()

		// ── Back up original CoreDNS Corefile ──
		cm, err := k8sClient.KubernetesClient.CoreV1().
			ConfigMaps("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
		require.NoError(t, err, "get coredns configmap")
		originalCorefile := cm.Data["Corefile"]

		restartAndWaitCoreDNS := func() {
			deploy, err := k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
			require.NoError(t, err, "get coredns deployment")
			if deploy.Spec.Template.ObjectMeta.Annotations == nil {
				deploy.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
			}
			deploy.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
			_, err = k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Update(ctx, deploy, metav1.UpdateOptions{})
			require.NoError(t, err, "restart coredns")

			require.Eventually(t, func() bool {
				d, err := k8sClient.KubernetesClient.AppsV1().
					Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
				if err != nil || d.Spec.Replicas == nil {
					return false
				}
				return d.Status.ReadyReplicas == *d.Spec.Replicas &&
					d.Status.UpdatedReplicas == *d.Spec.Replicas
			}, 60*time.Second, 2*time.Second, "coredns must become ready")
		}

		// ── Restore CoreDNS on cleanup (best-effort) ──
		t.Cleanup(func() {
			t.Log("cleanup: restoring CoreDNS Corefile")
			cm, err := k8sClient.KubernetesClient.CoreV1().
				ConfigMaps("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
			if err != nil {
				t.Logf("cleanup: get coredns cm: %v", err)
				return
			}
			cm.Data["Corefile"] = originalCorefile
			if _, err := k8sClient.KubernetesClient.CoreV1().
				ConfigMaps("kube-system").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
				t.Logf("cleanup: update coredns cm: %v", err)
				return
			}
			deploy, err := k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
			if err != nil {
				t.Logf("cleanup: get coredns deploy: %v", err)
				return
			}
			if deploy.Spec.Template.ObjectMeta.Annotations == nil {
				deploy.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
			}
			deploy.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
			if _, err := k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Update(ctx, deploy, metav1.UpdateOptions{}); err != nil {
				t.Logf("cleanup: restart coredns: %v", err)
			}
		})

		// ── Poison CoreDNS: fusioncore.ai → 8.8.4.4 ──
		poisoned := strings.Replace(originalCorefile,
			"forward .",
			"template IN A fusioncore.ai {\n        answer \"fusioncore.ai. 60 IN A 8.8.4.4\"\n        fallthrough\n    }\n    forward .",
			1)
		require.NotEqual(t, originalCorefile, poisoned, "template injection must modify Corefile")

		cm.Data["Corefile"] = poisoned
		_, err = k8sClient.KubernetesClient.CoreV1().
			ConfigMaps("kube-system").Update(ctx, cm, metav1.UpdateOptions{})
		require.NoError(t, err, "apply poisoned Corefile")
		restartAndWaitCoreDNS()

		// Verify poisoned DNS returns the spoofed IP.
		require.Eventually(t, func() bool {
			stdout, _, _ := wl.ExecIntoPod([]string{"nslookup", "fusioncore.ai"}, "curl")
			return strings.Contains(stdout, "8.8.4.4")
		}, 30*time.Second, 3*time.Second, "poisoned CoreDNS must return 8.8.4.4 for fusioncore.ai")

		// ── Trigger alerts ──
		// nslookup does DNS only (no TCP egress).
		// BusyBox nslookup does NOT do PTR reverse-lookups on result IPs.
		stdout, stderr, err := wl.ExecIntoPod([]string{"nslookup", "fusioncore.ai"}, "curl")
		t.Logf("nslookup (poisoned) → err=%v stdout=%q stderr=%q", err, stdout, stderr)

		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)

		// R0005 does NOT fire: fusioncore.ai is already in the NN
		// egress list, and BusyBox nslookup does NOT perform PTR
		// reverse-lookups on result IPs, so no unknown domain is queried.
		assert.Equal(t, 0, countByRule(alerts, "R0005"),
			"DNS MITM: domain is in NN and no PTR lookup — R0005 should not fire")

		// R0011 does NOT fire: nslookup generates only DNS (UDP)
		// traffic to the cluster DNS service, which is a private IP
		// excluded by is_private_ip().
		assert.Equal(t, 0, countByRule(alerts, "R0011"),
			"DNS MITM: nslookup has no TCP egress — R0011 should not fire")
	})

	// ---------------------------------------------------------------
	// 28f. MITM — CoreDNS poisoning with TCP egress.
	//      Same CoreDNS poisoning as 28e, but now fusioncore.ai
	//      resolves to 128.130.194.56 (a routable IP that accepts
	//      TCP on port 80).  curl generates a real TCP connection
	//      to the spoofed IP.
	//
	//      Expected:
	//        R0005 = 0 — domain is in NN, no PTR reverse-lookup.
	//        R0011 fires — TCP egress to 128.130.194.56 which is
	//                       NOT in the NN (NN only has 162.0.217.171).
	//
	//      NOTE: runs after 28e; modifies cluster-wide CoreDNS.
	// ---------------------------------------------------------------
	t.Run("mitm_coredns_poisoning_tcp", func(t *testing.T) {
		wl := setup(t)
		ctx := context.Background()
		k8sClient := k8sinterface.NewKubernetesApi()

		// ── Back up original CoreDNS Corefile ──
		cm, err := k8sClient.KubernetesClient.CoreV1().
			ConfigMaps("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
		require.NoError(t, err, "get coredns configmap")
		originalCorefile := cm.Data["Corefile"]

		restartAndWaitCoreDNS := func() {
			deploy, err := k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
			require.NoError(t, err, "get coredns deployment")
			if deploy.Spec.Template.ObjectMeta.Annotations == nil {
				deploy.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
			}
			deploy.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
			_, err = k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Update(ctx, deploy, metav1.UpdateOptions{})
			require.NoError(t, err, "restart coredns")

			require.Eventually(t, func() bool {
				d, err := k8sClient.KubernetesClient.AppsV1().
					Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
				if err != nil || d.Spec.Replicas == nil {
					return false
				}
				return d.Status.ReadyReplicas == *d.Spec.Replicas &&
					d.Status.UpdatedReplicas == *d.Spec.Replicas
			}, 60*time.Second, 2*time.Second, "coredns must become ready")
		}

		// ── Restore CoreDNS on cleanup (best-effort) ──
		t.Cleanup(func() {
			t.Log("cleanup: restoring CoreDNS Corefile")
			cm, err := k8sClient.KubernetesClient.CoreV1().
				ConfigMaps("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
			if err != nil {
				t.Logf("cleanup: get coredns cm: %v", err)
				return
			}
			cm.Data["Corefile"] = originalCorefile
			if _, err := k8sClient.KubernetesClient.CoreV1().
				ConfigMaps("kube-system").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
				t.Logf("cleanup: update coredns cm: %v", err)
				return
			}
			deploy, err := k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
			if err != nil {
				t.Logf("cleanup: get coredns deploy: %v", err)
				return
			}
			if deploy.Spec.Template.ObjectMeta.Annotations == nil {
				deploy.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
			}
			deploy.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
			if _, err := k8sClient.KubernetesClient.AppsV1().
				Deployments("kube-system").Update(ctx, deploy, metav1.UpdateOptions{}); err != nil {
				t.Logf("cleanup: restart coredns: %v", err)
			}
		})

		// ── Poison CoreDNS: fusioncore.ai → 128.130.194.56 ──
		poisoned := strings.Replace(originalCorefile,
			"forward .",
			"template IN A fusioncore.ai {\n        answer \"fusioncore.ai. 60 IN A 128.130.194.56\"\n        fallthrough\n    }\n    forward .",
			1)
		require.NotEqual(t, originalCorefile, poisoned, "template injection must modify Corefile")

		cm.Data["Corefile"] = poisoned
		_, err = k8sClient.KubernetesClient.CoreV1().
			ConfigMaps("kube-system").Update(ctx, cm, metav1.UpdateOptions{})
		require.NoError(t, err, "apply poisoned Corefile")
		restartAndWaitCoreDNS()

		// Verify poisoned DNS returns the spoofed IP.
		require.Eventually(t, func() bool {
			stdout, _, _ := wl.ExecIntoPod([]string{"nslookup", "fusioncore.ai"}, "curl")
			return strings.Contains(stdout, "128.130.194.56")
		}, 30*time.Second, 3*time.Second, "poisoned CoreDNS must return 128.130.194.56 for fusioncore.ai")

		// ── Trigger alerts ──
		// curl resolves fusioncore.ai → 128.130.194.56 (poisoned)
		// then opens a TCP connection to 128.130.194.56:80.
		stdout, stderr, err := wl.ExecIntoPod(
			[]string{"curl", "-sm5", "http://fusioncore.ai"}, "curl")
		t.Logf("curl (poisoned DNS) → err=%v stdout=%q stderr=%q", err, stdout, stderr)

		alerts := waitAlerts(t, wl.Namespace)
		t.Logf("=== %d alerts ===", len(alerts))
		logAlerts(t, alerts)

		// R0005 does NOT fire: fusioncore.ai is already in the NN
		// egress list, and curl (like BusyBox nslookup) does NOT
		// perform PTR reverse-lookups on resolved IPs.
		assert.Equal(t, 0, countByRule(alerts, "R0005"),
			"DNS MITM: domain is in NN and no PTR lookup — R0005 should not fire")

		// R0011 fires: TCP egress to 128.130.194.56 which is NOT
		// in the NN (NN only allows 162.0.217.171).
		require.Greater(t, countByRule(alerts, "R0011"), 0,
			"DNS MITM: TCP to spoofed IP 128.130.194.56 must fire R0011")
	})
}

// Test_34_NetworkNeighborsCIDRCollapse is an end-to-end test for storage
// PR kubescape/storage#348 (CIDR-based collapsing of NetworkNeighbor entries).
//
// It exercises the REAL learn→collapse path, not an injected profile: apply the
// CollapseConfiguration, wait for it to go live, deploy a workload that egresses
// to many IPs in 52.216.0.0/24, wait for node-agent to LEARN the profile to
// completion, then assert the learnt egress collapsed into a covering CIDR with
// no host /32 left behind.
//
// Why not inject a NetworkNeighborhood directly: storage rejects/empties a
// directly-created `completion: complete` profile ("object is completed"), and
// the deflate only runs at node-agent's write time — so only a genuinely learnt
// profile exercises the collapse. Validated on a real k3s: 60 IPs -> one CIDR.
//
// The collapsed CIDR lands in the plural `ipAddresses` field, which exists only
// on PR#348 storage, so the result is read via the DYNAMIC client (never
// referenced at compile time). Compiles on plain upstream; passes only on PR#348.
// cpCollapseGVR / ccCollapseGVR name the CIDR-collapse resources. The collapsed
// value lands in the plural ipAddresses field, which exists only on PR#348
// storage, so learnt ContainerProfiles are read via the dynamic client (never
// referenced at compile time). This file compiles on plain upstream and passes
// only on PR#348 storage carrying the collapse dedup fix.
var (
	cpCollapseGVR = schema.GroupVersionResource{Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Resource: "containerprofiles"}
	ccCollapseGVR = schema.GroupVersionResource{Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Resource: "collapseconfigurations"}
)

// applyCollapseFloor create-or-updates the cluster-scoped CollapseConfiguration
// singleton to threshold 5 (< the compiled-in default 50, so a modest fan-out
// trips collapse) and the given CIDR floor. Deflate collapses at write time
// using whatever config is live then, via a TTL-cached (~10s) provider — so
// callers must wait after this before deploying a learner.
func applyCollapseFloor(t *testing.T, dyn dynamic.Interface, floorBits int64) {
	ctx := context.Background()
	cc := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1",
		"kind":       "CollapseConfiguration",
		"metadata":   map[string]interface{}{"name": "default"},
		"spec":       map[string]interface{}{"networkIPGroupThreshold": int64(5), "networkCIDRFloorBits": floorBits},
	}}
	_, err := dyn.Resource(ccCollapseGVR).Create(ctx, cc, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		cur, gerr := dyn.Resource(ccCollapseGVR).Get(ctx, "default", metav1.GetOptions{})
		require.NoError(t, gerr, "get CollapseConfiguration")
		require.NoError(t, unstructured.SetNestedField(cur.Object, floorBits, "spec", "networkCIDRFloorBits"))
		require.NoError(t, unstructured.SetNestedField(cur.Object, int64(5), "spec", "networkIPGroupThreshold"))
		_, uerr := dyn.Resource(ccCollapseGVR).Update(ctx, cur, metav1.UpdateOptions{})
		require.NoError(t, uerr, "update CollapseConfiguration floor")
		return
	}
	require.NoError(t, err, "apply CollapseConfiguration")
}

// deployCIDRLearner deploys an egress fan-out workload and waits for its pod to
// be ready; the caller later waits for the learnt ContainerProfile to finalise.
func deployCIDRLearner(t *testing.T, resource string) *testutils.TestWorkload {
	ns := testutils.NewRandomNamespace()
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), resource))
	require.NoError(t, err, "deploy %s", resource)
	require.NoError(t, wl.WaitForReady(80), "%s not ready", resource)
	return wl
}

// collectLearntCollapse waits for the workload's ContainerProfiles to finalise
// (completion: complete), reads each via the dynamic client, and returns the
// sorted, de-duplicated set of learnt egress CIDRs (plural ipAddresses values
// carrying a "/") and any bare host ipAddress left behind. The unified
// ContainerProfile carries egress on its flat spec (one profile per container),
// so entries are read from spec.egress directly rather than spec.containers[].
func collectLearntCollapse(t *testing.T, dyn dynamic.Interface, wl *testutils.TestWorkload) (cidrs, bare []string) {
	require.NoError(t, wl.WaitForContainerProfileCompletion(120), "container profile did not complete learning")
	profiles, err := wl.GetContainerProfiles()
	require.NoError(t, err, "get learnt container profiles")

	seen := map[string]struct{}{}
	for _, cp := range profiles {
		got, err := dyn.Resource(cpCollapseGVR).Namespace(cp.Namespace).Get(context.Background(), cp.Name, metav1.GetOptions{})
		require.NoError(t, err, "dynamic get container profile %s/%s", cp.Namespace, cp.Name)

		eg, _, _ := unstructured.NestedSlice(got.Object, "spec", "egress")
		for _, e := range eg {
			em, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			if ips, ok, _ := unstructured.NestedStringSlice(em, "ipAddresses"); ok {
				for _, ip := range ips {
					if strings.Contains(ip, "/") {
						if _, s := seen[ip]; !s {
							seen[ip] = struct{}{}
							cidrs = append(cidrs, ip)
						}
					}
				}
			}
			if s, _, _ := unstructured.NestedString(em, "ipAddress"); s != "" {
				bare = append(bare, s)
			}
		}
	}
	sort.Strings(cidrs)
	sort.Strings(bare)
	return cidrs, bare
}

// withPrefixes returns the members of cidrs whose network address starts with
// one of the given dotted/colon prefixes (e.g. "52.216." or "2606:4700:0:1:").
func withPrefixes(cidrs []string, prefixes ...string) []string {
	var out []string
	for _, c := range cidrs {
		for _, p := range prefixes {
			if strings.HasPrefix(c, p) {
				out = append(out, c)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// Test_34_NetworkNeighborsCIDRCollapse exercises the REAL learn→collapse path for
// storage PR kubescape/storage#348 (CIDR collapsing) plus the netipx exact-cover
// fix stacked on it. It never injects a profile: storage rejects/empties a
// directly-created `completion: complete` NN and deflate only runs at
// node-agent's write time, so only a genuinely learnt profile exercises collapse.
//
// Workloads egress to REAL cloud-provider address space (AWS S3, Cloudflare,
// Azure, GCP). Assertions pin two properties: a fully-observed block collapses to
// exactly that block (never over-approximating past what the workload reached),
// and scattered traffic is bucketed to the floor so output is bounded by the
// number of distinct floor networks — not one entry per host, the regression
// caught in the kubescape/storage#349 review against the real too-large profile.
// The collapsed value lands in the plural ipAddresses field (PR#348), read via
// the dynamic client.
//
//	floor /16, full S3 /28 (52.216.1.0/28)      -> exactly 52.216.1.0/28
//	floor /16, ~30 hosts spread across a /16     -> one covering 52.216.0.0/16 (bounded, no /32s)
//	floor /16, 8 hosts each in a distinct /16    -> one /16 bucket apiece (bounded, no /32s)
//	floor /16, full Cloudflare IPv6 /124        -> exactly 2606:4700:0:1::/124 (dual-stack only)
//	floor /28, full S3 /27 (52.216.2.0/27)      -> splits into 52.216.2.0/28 + 52.216.2.16/28
func Test_34_NetworkNeighborsCIDRCollapse(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	k8sClient := k8sinterface.NewKubernetesApi()
	dyn := dynamic.NewForConfigOrDie(k8sClient.K8SConfig)
	t.Cleanup(func() {
		_ = dyn.Resource(ccCollapseGVR).Delete(context.Background(), "default", metav1.DeleteOptions{})
	})

	// -------- Phase 1: /16 floor — exactness on real cloud ranges --------
	applyCollapseFloor(t, dyn, 16)
	time.Sleep(20 * time.Second) // let the TTL-cached provider pick up the floor

	s3 := deployCIDRLearner(t, "resources/networkneighbors-s3-28.yaml")
	scattered := deployCIDRLearner(t, "resources/networkneighbors-scattered.yaml")
	spread := deployCIDRLearner(t, "resources/networkneighbors-cidr-spread.yaml")
	v6 := deployCIDRLearner(t, "resources/networkneighbors-v6-124.yaml")

	// A fully-observed S3 /28 exact-covers to exactly that /28.
	s3CIDRs, s3Bare := collectLearntCollapse(t, dyn, s3)
	assert.Equal(t, []string{"52.216.1.0/28"}, withPrefixes(s3CIDRs, "52.216.1."),
		"a fully-observed S3 /28 must collapse to exactly 52.216.1.0/28")
	assert.Empty(t, withPrefixes(s3Bare, "52.216.1."), "no bare host /32 may remain")

	// ~30 hosts spread across dozens of /24s within a single /16 — the shape of the
	// real too-large profile from the storage#349 review. Under a /16 floor they
	// share no common prefix as long as the floor collapses to one covering
	// 52.216.0.0/16, NOT one entry per host. This is the case that exploded to
	// thousands of /32s before the bucketing fix.
	spreadCIDRs, spreadBare := collectLearntCollapse(t, dyn, spread)
	assert.Equal(t, []string{"52.216.0.0/16"}, withPrefixes(spreadCIDRs, "52.216."),
		"hosts spread across a /16 must collapse to a single bounded /16, not per-host entries")
	assert.Empty(t, withPrefixes(spreadBare, "52.216."), "no bare host /32 may remain after bucketing")

	// Scattered IPs across four providers, each in a distinct /16, share no common
	// prefix as long as the floor, so each is bucketed into its floor-length (/16)
	// network — one bounded block apiece, never left as unbounded per-host /32s.
	scatteredWant := []string{
		"104.16.0.0/16", "13.107.0.0/16", "172.64.0.0/16", "20.150.0.0/16",
		"34.120.0.0/16", "35.190.0.0/16", "52.216.0.0/16", "52.217.0.0/16",
	}
	scatteredCIDRs, scatteredBare := collectLearntCollapse(t, dyn, scattered)
	got := withPrefixes(scatteredCIDRs, "52.216.", "52.217.", "104.16.", "172.64.", "20.150.", "13.107.", "34.120.", "35.190.")
	assert.Equal(t, scatteredWant, got, "scattered cloud IPs, each in a distinct /16, bucket to one /16 apiece")
	assert.Empty(t, withPrefixes(scatteredBare, "52.216.", "52.217.", "104.16.", "172.64.", "20.150.", "13.107.", "34.120.", "35.190."),
		"no bare host /32 may remain after bucketing")

	// IPv6 exact cover — only on a dual-stack cluster; skip the assertion if the
	// pod never egressed over v6 (single-stack), rather than fail.
	v6CIDRs, _ := collectLearntCollapse(t, dyn, v6)
	if v6got := withPrefixes(v6CIDRs, "2606:4700:0:1:"); len(v6got) == 0 {
		t.Log("no IPv6 egress learnt (single-stack cluster) — skipping the v6 assertion")
	} else {
		assert.Equal(t, []string{"2606:4700:0:1::/124"}, v6got,
			"a fully-observed Cloudflare v6 /124 must collapse to exactly that /124")
	}

	// -------- Phase 2: /28 floor — a fully-observed /27 splits into two /28s ----
	applyCollapseFloor(t, dyn, 28)
	time.Sleep(20 * time.Second)

	split := deployCIDRLearner(t, "resources/networkneighbors-s3-27.yaml")
	splitCIDRs, splitBare := collectLearntCollapse(t, dyn, split)
	assert.Equal(t, []string{"52.216.2.0/28", "52.216.2.16/28"}, withPrefixes(splitCIDRs, "52.216.2."),
		"a fully-observed /27 must split into two /28s under a /28 floor")
	assert.Empty(t, withPrefixes(splitBare, "52.216.2."))

	t.Logf("collapse validated on real cloud ranges: S3=%v spread=%v scattered=%v split=%v",
		withPrefixes(s3CIDRs, "52.216.1."), withPrefixes(spreadCIDRs, "52.216."), got, withPrefixes(splitCIDRs, "52.216.2."))
}

// Test_35_ExecTTYFieldTest validates, against real eBPF on a real cluster, that
// a CEL rule can actually use the exec TTY fields (event.hasTty, event.tty,
// event.ttyMajor/ttyMinor). Everything before this test was exercised only
// against synthetic datasources, so this is the first end-to-end proof.
//
// Why four rules instead of one: an unresolvable CEL field does not raise an
// error, it fails to compile and silently disables the whole expression
// (pkg/rulemanager/cel returns (false, nil) on compile failure). "No alert" is
// therefore ambiguous between "the field was false" and "the rule never ran".
// R9902 is a control on the same trigger with no TTY predicate, and R9903/R9904
// are a mutually exclusive pair on has(event.ttyMajor). See
// resources/exec-tty-rules.yaml.
//
// Why three containers: containers in a pod have separate mount namespaces and
// therefore separate /dev/pts instances, so each trigger gets a pristine pts
// index. That matters because pts indices are not reclaimed instantly -- with a
// shared devpts a "single" exec can land on index >= 1 and make the phase-1
// expectation below flap.
func Test_35_ExecTTYFieldTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	rulesPath := path.Join(utils.CurrentDir(), "resources/exec-tty-rules.yaml")
	bindingPath := path.Join(utils.CurrentDir(), "resources/exec-tty-rulebinding.yaml")
	require.Equal(t, 0, testutils.RunCommand("kubectl", "apply", "--validate=false", "-f", rulesPath), "apply TTY test rules")
	defer testutils.RunCommand("kubectl", "delete", "--ignore-not-found", "-f", rulesPath)
	require.Equal(t, 0, testutils.RunCommand("kubectl", "apply", "--validate=false", "-f", bindingPath), "apply TTY test rule binding")
	defer testutils.RunCommand("kubectl", "delete", "--ignore-not-found", "-f", bindingPath)
	// let the rules watcher and rule-binding watcher pick the new rules up
	time.Sleep(20 * time.Second)

	ns := testutils.NewRandomNamespace()
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/exec-tty-deployment.yaml"))
	require.NoError(t, err, "Error creating workload")
	require.NoError(t, wl.WaitForReady(80))
	time.Sleep(15 * time.Second)

	probe := []string{"/bin/uname"}

	// Trigger A -- genuinely no controlling terminal.
	_, _, err = wl.ExecIntoPodNoTTY(probe, "c-none")
	require.NoError(t, err, "no-tty probe")

	// Trigger B -- one TTY exec into a pristine devpts, so /dev/pts/0.
	_, _, err = wl.ExecIntoPod(probe, "c-pts0")
	require.NoError(t, err, "single-tty probe")

	// Trigger C -- hold a pty open, then probe while it is held so the probe
	// gets a nonzero pts index.
	go func() {
		// Writes its own tty path so the test can wait for real readiness, then
		// keeps the pty allocated.
		_, _, _ = wl.ExecIntoPod([]string{"sh", "-c", "tty > /tmp/holder-tty; sleep 120"}, "c-conc")
	}()
	defer func() {
		_, _, _ = wl.ExecIntoPodNoTTY([]string{"pkill", "-f", "sleep 120"}, "c-conc")
	}()

	// Waiting for the holder to *report* its pty is the point: merely launching
	// it and sleeping is racy. Observed on kind -- a probe fired before the
	// holder's pty existed landed on pts/0 and read as "no terminal", which
	// looks exactly like the feature being broken.
	var holderTTY string
	require.Eventually(t, func() bool {
		out, _, err := wl.ExecIntoPodNoTTY([]string{"cat", "/tmp/holder-tty"}, "c-conc")
		if err != nil {
			return false
		}
		holderTTY = strings.TrimSpace(strings.ReplaceAll(out, "\r", ""))
		return strings.HasPrefix(holderTTY, "/dev/pts/")
	}, 90*time.Second, 3*time.Second, "holder must allocate its pty before the concurrent probe runs")
	t.Logf("holder holds %s", holderTTY)

	// Confirm the environment really does hand out a nonzero index here. If this
	// fails the assertions below would be testing nothing.
	out, _, err := wl.ExecIntoPod([]string{"tty"}, "c-conc")
	require.NoError(t, err, "tty check in c-conc")
	probeTTY := strings.TrimSpace(strings.ReplaceAll(out, "\r", ""))
	t.Logf("concurrent probe sees %s", probeTTY)
	require.True(t, strings.HasPrefix(probeTTY, "/dev/pts/"), "concurrent exec must get a terminal, got %q", probeTTY)
	require.NotEqual(t, "/dev/pts/0", probeTTY,
		"concurrent exec landed on pts/0; phase 1 cannot distinguish that from no terminal, so trigger C would prove nothing")

	_, _, err = wl.ExecIntoPod(probe, "c-conc")
	require.NoError(t, err, "concurrent-tty probe")

	count := func(alerts []testutils.Alert, ruleID, container string) int {
		n := 0
		for _, a := range alerts {
			if a.Labels["rule_id"] == ruleID && a.Labels["container_name"] == container {
				n++
			}
		}
		return n
	}
	total := func(alerts []testutils.Alert, ruleID string) int {
		n := 0
		for _, a := range alerts {
			if a.Labels["rule_id"] == ruleID {
				n++
			}
		}
		return n
	}

	// Wait on the *control* rule reaching all three containers. R9901 and R9902
	// evaluate the same exec event, so once R9902 has arrived for a container the
	// verdict on R9901 for that same event is already decided -- which is what
	// makes the negative assertions below sound rather than merely un-elapsed.
	var alerts []testutils.Alert
	require.Eventually(t, func() bool {
		alerts, err = testutils.GetAlerts(ns.Name)
		if err != nil {
			return false
		}
		return count(alerts, "R9902", "c-none") > 0 &&
			count(alerts, "R9902", "c-pts0") > 0 &&
			count(alerts, "R9902", "c-conc") > 0
	}, 180*time.Second, 5*time.Second,
		"control rule R9902 must fire for all three probe execs -- if it does not, the trigger or the rule pipeline is broken, not the TTY field")

	t.Logf("alert counts: R9901 none=%d pts0=%d conc=%d | R9902 total=%d | R9903=%d R9904=%d",
		count(alerts, "R9901", "c-none"), count(alerts, "R9901", "c-pts0"), count(alerts, "R9901", "c-conc"),
		total(alerts, "R9902"), total(alerts, "R9903"), total(alerts, "R9904"))

	// The feature: hasTty discriminates.
	assert.Greater(t, count(alerts, "R9901", "c-conc"), 0,
		"R9901 must fire for the exec that held a nonzero pts index -- this is the actual TTY-field proof")
	assert.Equal(t, 0, count(alerts, "R9901", "c-none"),
		"R9901 must not fire for an exec with no controlling terminal")
	// Deliberate: phase 1 reads the ambiguous per-driver index, where 0 means
	// both /dev/pts/0 and "no terminal". A single exec into a fresh container is
	// pts/0 and so is invisible to hasTty. This is a known, documented
	// limitation, not a bug -- do not "fix" this expectation. It flips when
	// phase 2 lands (gadget emits tty_major/tty_minor).
	assert.Equal(t, 0, count(alerts, "R9901", "c-pts0"),
		"phase 1: an exec on pts/0 is indistinguishable from no terminal, so R9901 must stay silent here")

	// has() presence testing is honest, and ttyMajor is registered rather than
	// silently unresolvable. Exactly one of these two must fire.
	assert.Equal(t, 0, total(alerts, "R9903"),
		"R9903 must not fire: the pinned gadget does not emit tty_major, so has(event.ttyMajor) is false")
	assert.Greater(t, total(alerts, "R9904"), 0,
		"R9904 must fire: !has(event.ttyMajor) proves ttyMajor is a registered field that is honestly absent, not a compile failure")
}

// Test_36_MultiContainerPerContainerBinding shows per-container binding: a
// multi-container pod shares ONE kubescape.io/user-defined-profile label, but
// each container resolves its own authored CP as "<label>-<containerName>"
// (mc35-app / mc35-sidecar). The two CPs carry inverse exec allow-lists, so a
// forbidden binary in either container must fire R0001 and the allowed one must
// not — proving the containers do not share a profile.
func Test_36_MultiContainerPerContainerBinding(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()

	// app allows /usr/bin/id (not whoami); sidecar allows /usr/bin/whoami (not id).
	_ = applyUserDefinedContainerProfile(t, ns.Name, "resources/mc35-cp-app.yaml")
	_ = applyUserDefinedContainerProfile(t, ns.Name, "resources/mc35-cp-sidecar.yaml")

	wl, err := testutils.NewTestWorkload(ns.Name,
		path.Join(utils.CurrentDir(), "resources/mc35-multi-container-userdefined-deployment.yaml"))
	require.NoError(t, err)
	require.NoError(t, wl.WaitForReady(80))
	// Cache-load latency on the ContainerProfileCache is bursty; 30s covers the
	// observed worst case on a loaded runner (matches Test_28).
	time.Sleep(30 * time.Second)

	// Exercise each container with BOTH binaries. Expected R0001 (unexpected
	// process) per the inverse allow-lists:
	//   app     : whoami -> R0001 (not allowed) ; id -> allowed (no alert)
	//   sidecar : id     -> R0001 (not allowed) ; whoami -> allowed (no alert)
	wl.ExecIntoPod([]string{"/usr/bin/whoami"}, "app")
	wl.ExecIntoPod([]string{"/usr/bin/id"}, "app")
	wl.ExecIntoPod([]string{"/usr/bin/id"}, "sidecar")
	wl.ExecIntoPod([]string{"/usr/bin/whoami"}, "sidecar")

	var alerts []testutils.Alert
	require.Eventually(t, func() bool {
		var e error
		alerts, e = testutils.GetAlerts(wl.Namespace)
		return e == nil
	}, 60*time.Second, 5*time.Second, "must be able to fetch alerts")
	// Extra settle time for remaining alerts.
	time.Sleep(10 * time.Second)
	alerts, _ = testutils.GetAlerts(wl.Namespace)

	for i, a := range alerts {
		t.Logf("  [%d] %s(%s) comm=%s container=%s", i,
			a.Labels["rule_name"], a.Labels["rule_id"], a.Labels["comm"], a.Labels["container_name"])
	}

	countR0001 := func(container, comm string) int {
		n := 0
		for _, a := range alerts {
			if a.Labels["rule_id"] == "R0001" &&
				a.Labels["container_name"] == container &&
				a.Labels["comm"] == comm {
				n++
			}
		}
		return n
	}

	// The forbidden process in each container MUST alert.
	assert.Greater(t, countR0001("app", "whoami"), 0,
		"whoami is NOT in mc35-app (only sidecar's CP allows it) — must fire R0001 in app")
	assert.Greater(t, countR0001("sidecar", "id"), 0,
		"id is NOT in mc35-sidecar (only app's CP allows it) — must fire R0001 in sidecar")

	// The allowed process in each container MUST NOT alert — the
	// no-cross-inheritance assertion. If both containers shared one CP, one of
	// these would be non-zero.
	assert.Equal(t, 0, countR0001("app", "id"),
		"id IS in mc35-app — must NOT fire R0001 in app (non-zero => sidecar's CP leaked in)")
	assert.Equal(t, 0, countR0001("sidecar", "whoami"),
		"whoami IS in mc35-sidecar — must NOT fire R0001 in sidecar (non-zero => app's CP leaked in)")
}

// Test_29_SignedContainerProfile ports the legacy Test_29_SignedApplicationProfile
// to the migrated ContainerProfile world: a cryptographically signed, user-authored
// ContainerProfile is pushed to storage, its signature survives the storage
// round-trip, node-agent loads + enforces it, and an unlisted exec fires R0001.
//
// Signing uses the sign-after-roundtrip pattern: storage's PreSave deflates the
// spec (dedup/sort/collapse), which changes the content hash. Signing the
// storage-normalised form (not the local one) makes the signed hash match what
// node-agent recomputes on load, so an untampered profile verifies cleanly.
func Test_29_SignedContainerProfile(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const overlayName = "signed-cp"
	const containerName = "curl"

	ns := testutils.NewRandomNamespace()
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: overlayName, Namespace: ns.Name},
		Spec: v1beta1.ContainerProfileSpec{
			Architectures: []string{"amd64"},
			Execs:         []v1beta1.ExecCalls{{Path: "/bin/sleep"}, {Path: "/usr/bin/curl"}},
			Syscalls:      []string{"close", "connect", "openat", "read", "socket", "write"},
			LabelSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "curl-signed"}},
		},
	}

	// sign-after-roundtrip: push unsigned, read the storage-normalised form, sign
	// THAT, then update with the signature.
	_, err := storageClient.ContainerProfiles(ns.Name).Create(context.Background(), cp, metav1.CreateOptions{})
	require.NoError(t, err, "create unsigned CP")
	var stored *v1beta1.ContainerProfile
	require.Eventually(t, func() bool {
		s, e := storageClient.ContainerProfiles(ns.Name).Get(context.Background(), overlayName, v1.GetOptions{})
		if e != nil {
			return false
		}
		stored = s
		return true
	}, 30*time.Second, time.Second, "CP retrievable after unsigned create")

	require.NoError(t, signature.SignObjectDisableKeyless(profiles.NewContainerProfileAdapter(stored)), "sign storage-normalised CP")
	_, err = storageClient.ContainerProfiles(ns.Name).Update(context.Background(), stored, metav1.UpdateOptions{})
	require.NoError(t, err, "update CP with signature")

	// signature survives the round-trip and still verifies.
	require.Eventually(t, func() bool {
		s, e := storageClient.ContainerProfiles(ns.Name).Get(context.Background(), overlayName, v1.GetOptions{})
		if e != nil {
			return false
		}
		a := profiles.NewContainerProfileAdapter(s)
		return signature.IsSigned(a) && signature.VerifyObjectAllowUntrusted(a) == nil
	}, 30*time.Second, time.Second, "stored signed CP must verify after round-trip")
	t.Log("signature round-trip verification passed")

	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/curl-signed-cp-deployment.yaml"))
	require.NoError(t, err, "create workload")
	require.NoError(t, wl.WaitForReady(80), "workload ready")
	time.Sleep(30 * time.Second) // let node-agent load + verify the signed profile

	countR0001 := func() int {
		alerts, _ := testutils.GetAlerts(ns.Name)
		n := 0
		for _, a := range alerts {
			if a.Labels["rule_id"] == "R0001" && a.Labels["container_name"] == containerName {
				n++
			}
		}
		return n
	}
	// nslookup is not in the signed profile → R0001. Re-exec each poll so the
	// event is generated after the profile is cached.
	require.Eventually(t, func() bool {
		wl.ExecIntoPod([]string{"nslookup", "ebpf.io"}, containerName)
		return countR0001() > 0
	}, 3*time.Minute, 10*time.Second, "nslookup not in signed CP must fire R0001")
	require.Greater(t, countR0001(), 0, "unlisted exec on a signed CP must fire R0001")
}

// Test_31_TamperDetectionAlert ports the legacy tamper CT to ContainerProfile:
// a signed user-authored CP is loaded, then its spec is modified in storage
// WITHOUT re-signing. node-agent recomputes the content hash on reload, finds it
// no longer matches the signature, and emits R1016 "Signed profile tampered".
func Test_31_TamperDetectionAlert(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const overlayName = "signed-cp"

	ns := testutils.NewRandomNamespace()
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: overlayName, Namespace: ns.Name},
		Spec: v1beta1.ContainerProfileSpec{
			Architectures: []string{"amd64"},
			Execs:         []v1beta1.ExecCalls{{Path: "/bin/sleep"}, {Path: "/usr/bin/curl"}},
			Syscalls:      []string{"close", "connect", "openat", "read", "socket", "write"},
			LabelSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "curl-signed"}},
		},
	}
	_, err := storageClient.ContainerProfiles(ns.Name).Create(context.Background(), cp, metav1.CreateOptions{})
	require.NoError(t, err, "create unsigned CP")
	var stored *v1beta1.ContainerProfile
	require.Eventually(t, func() bool {
		s, e := storageClient.ContainerProfiles(ns.Name).Get(context.Background(), overlayName, v1.GetOptions{})
		if e != nil {
			return false
		}
		stored = s
		return true
	}, 30*time.Second, time.Second, "CP retrievable after unsigned create")
	require.NoError(t, signature.SignObjectDisableKeyless(profiles.NewContainerProfileAdapter(stored)), "sign storage-normalised CP")
	_, err = storageClient.ContainerProfiles(ns.Name).Update(context.Background(), stored, metav1.UpdateOptions{})
	require.NoError(t, err, "update CP with signature")

	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/curl-signed-cp-deployment.yaml"))
	require.NoError(t, err, "create workload")
	require.NoError(t, wl.WaitForReady(80), "workload ready")
	time.Sleep(30 * time.Second) // let node-agent load + verify the clean signed profile

	// Tamper: append an exec to the stored spec WITHOUT re-signing. The signature
	// (over the pre-tamper content) no longer matches → R1016 on reload.
	patch := []byte(`[{"op":"add","path":"/spec/execs/-","value":{"path":"/bin/tampered"}}]`)
	_, err = storageClient.ContainerProfiles(ns.Name).Patch(context.Background(), overlayName, types.JSONPatchType, patch, v1.PatchOptions{})
	require.NoError(t, err, "tamper the signed CP spec")

	require.Eventually(t, func() bool {
		alerts, _ := testutils.GetAlerts(ns.Name)
		for _, a := range alerts {
			if a.Labels["rule_id"] == "R1016" {
				return true
			}
		}
		return false
	}, 3*time.Minute, 10*time.Second, "tampered signed CP must fire R1016")
	t.Log("R1016 tamper alert fired on the tampered signed ContainerProfile")
}

// ─────────────────────────── signed-fixture helpers ───────────────────────────
//
// The signature CTs verify PRE-SIGNED artifacts committed under
// tests/resources/signed (see its README): trust policies signed with the
// offline root key, ContainerProfile fragments and Rules fragments signed with
// the published component-test keys. Nothing is signed at test time, so CI
// exercises exactly the bytes a vendor would ship.
//
// Everything is signed with --embed-content: the canonical signed content
// travels in the signature.kubescape.io/content annotation, so a fixture keeps
// verifying after the apiserver/storage normalises its spec. metadata.namespace
// is deliberately NOT part of the signed content — a vendor cannot know where a
// customer installs — so the tests set the namespace at ingest time and still
// use random namespaces.

const (
	signedFixturesDir = "resources/signed"

	ksNamespace          = "kubescape"
	nodeAgentDaemonSet   = "node-agent"
	bundlePolicyCM       = "node-agent-bundle-policy"
	bundlePolicyCMKey    = "trust-policy.json"
	signatureContentAnno = "signature.kubescape.io/content"

	// Root-signed trust policies. The chart ships the profiles-only one, so
	// signed RULES stay off by default and the UNSIGNED Rules objects other CTs
	// apply (resources/r0002-files-access-enabled.yaml, resources/exec-tty-rules.yaml,
	// the chart's own kubescape-rules) keep being accepted. The rule CTs swap in
	// the full one, which adds ruleClasses.
	fixtureTrustPolicyProfilesOnly = "trust-policy.profiles-only.signed.json"
	fixtureTrustPolicyFull         = "trust-policy.signed.json"
	fixtureTrustPolicyBadSigner    = "trust-policy.badsigner.signed.json"

	// bundle37 ContainerProfile fragments (bundle label bundle37).
	fixtureFragBase      = "fragments/bundle37-base-signed.yaml"
	fixtureFragAdmission = "fragments/bundle37-admission-signed.yaml"
	fixtureFragOverlay   = "fragments/bundle37-overlay-signed.yaml"

	// Rules fragments.
	fixtureRulesBase      = "rules/cluster-baseline-signed.yaml"
	fixtureRulesOverlay   = "rules/namespace-override-signed.yaml"
	fixtureRulesUntrusted = "rules/untrusted-signer-signed.yaml"

	// Severities the two R0001 variants carry, and the marker only the overlay
	// variant's rendered message contains.
	baseR0001Severity      = "1"
	overlayR0001Severity   = "9"
	overlayR0001Marker     = "BUNDLE OVERLAY R0001"
	untrustedR0001Marker   = "ROGUE R0001"
	untrustedR0001Severity = "7"
)

// signedFixture reads a committed pre-signed fixture.
func signedFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(signedFixturePath(rel))
	require.NoError(t, err, "read signed fixture %s", rel)
	return b
}

// signedFixturePath is the on-disk path of a committed pre-signed fixture.
func signedFixturePath(rel string) string {
	return path.Join(utils.CurrentDir(), signedFixturesDir, rel)
}

// applySignedFragment ingests a pre-signed ContainerProfile fragment into ns AS
// SIGNED — the cluster never sees an unsigned form. Delete-then-create keeps it
// idempotent across re-runs.
func applySignedFragment(t *testing.T, storageClient *spdxv1beta1client.SpdxV1beta1Client, ns, rel string) *v1beta1.ContainerProfile {
	t.Helper()
	var cp v1beta1.ContainerProfile
	require.NoError(t, yaml.Unmarshal(signedFixture(t, rel), &cp), "parse signed fragment %s", rel)
	require.NotEmpty(t, cp.Annotations[signatureContentAnno], "fixture %s must carry embedded signed content", rel)
	cp.Namespace = ns

	_ = storageClient.ContainerProfiles(ns).Delete(context.Background(), cp.Name, metav1.DeleteOptions{})
	var created *v1beta1.ContainerProfile
	require.Eventually(t, func() bool {
		c, err := storageClient.ContainerProfiles(ns).Create(context.Background(), cp.DeepCopy(), metav1.CreateOptions{})
		if err != nil {
			t.Logf("create signed fragment %s: %v", cp.Name, err)
			return false
		}
		created = c
		return true
	}, 60*time.Second, 2*time.Second, "create signed fragment %s", cp.Name)

	// The signature must survive the storage round-trip: the stored carrier's
	// spec may be normalised, but the embedded signed content is what verifies.
	require.Eventually(t, func() bool {
		s, e := storageClient.ContainerProfiles(ns).Get(context.Background(), cp.Name, v1.GetOptions{})
		if e != nil {
			return false
		}
		a := profiles.NewContainerProfileAdapter(s)
		return signature.IsSigned(a) && signature.VerifyObjectAllowUntrusted(a) == nil
	}, 60*time.Second, 2*time.Second, "fragment %s must verify after the storage round-trip", cp.Name)
	return created
}

// applyBundle37Fragments ingests the three pre-signed bundle37 fragments.
func applyBundle37Fragments(t *testing.T, storageClient *spdxv1beta1client.SpdxV1beta1Client, ns string) {
	t.Helper()
	for _, rel := range []string{fixtureFragBase, fixtureFragAdmission, fixtureFragOverlay} {
		applySignedFragment(t, storageClient, ns, rel)
	}
}

// applySignedRules ingests a pre-signed Rules fragment into ns and returns its
// deleter. The fixtures carry no metadata.namespace (it is not signed), so the
// install namespace — which is what an overlay fragment scopes to — is chosen
// here.
func applySignedRules(t *testing.T, ns, rel string) func() {
	t.Helper()
	file := signedFixturePath(rel)
	testutils.RunCommand("kubectl", "delete", "-n", ns, "--ignore-not-found", "-f", file)
	require.Equal(t, 0, testutils.RunCommand("kubectl", "create", "-n", ns, "--validate=false", "-f", file),
		"ingest signed rules fixture %s into %s", rel, ns)
	return func() { testutils.RunCommand("kubectl", "delete", "-n", ns, "--ignore-not-found", "-f", file) }
}

// requireChartTrustPolicyIsFixture pins the chart-shipped policy to the
// committed fixture, so a drifted chart fails here (with a clear message)
// instead of surfacing as an unexplained enforcement failure later.
func requireChartTrustPolicyIsFixture(t *testing.T) {
	t.Helper()
	k8sClient := k8sinterface.NewKubernetesApi()
	cm, err := k8sClient.KubernetesClient.CoreV1().ConfigMaps(ksNamespace).Get(context.TODO(), bundlePolicyCM, metav1.GetOptions{})
	require.NoError(t, err, "get %s ConfigMap", bundlePolicyCM)
	require.Equal(t,
		strings.TrimSpace(string(signedFixture(t, fixtureTrustPolicyProfilesOnly))),
		strings.TrimSpace(cm.Data[bundlePolicyCMKey]),
		"the chart's trust policy must be tests/resources/signed/%s verbatim", fixtureTrustPolicyProfilesOnly)
}

// nodeAgentLogs returns the current node-agent pod logs.
func nodeAgentLogs(t *testing.T) string {
	t.Helper()
	logs, err := testutils.GetAppLogs("node-agent")
	require.NoError(t, err, "read node-agent logs")
	return logs
}

// requireNodeAgentLog waits for a line to appear in the node-agent log.
func requireNodeAgentLog(t *testing.T, substr, msg string) {
	t.Helper()
	require.Eventually(t, func() bool {
		return strings.Contains(nodeAgentLogs(t), substr)
	}, 2*time.Minute, 5*time.Second, "%s (expected %q in the node-agent log)", msg, substr)
}

// enableSignedRuleFragments turns signed RULE fragments on for the calling test
// and returns the restore func. It ingests the signed base-class ruleset (once
// rule signing is on, the chart's UNSIGNED kubescape-rules object is rejected,
// so every detection the test needs must come from a signed fragment), applies
// the extra fixtures the caller names, swaps in the ruleClasses-bearing trust
// policy, and restarts node-agent. Use as:
//
//	defer enableSignedRuleFragments(t, map[string]string{fixtureRulesOverlay: ns.Name})()
func enableSignedRuleFragments(t *testing.T, extras map[string]string) func() {
	t.Helper()
	cleanups := []func(){applySignedRules(t, ksNamespace, fixtureRulesBase)}
	for rel, ns := range extras {
		cleanups = append(cleanups, applySignedRules(t, ns, rel))
	}
	setBundleTrustPolicy(t, signedFixturePath(fixtureTrustPolicyFull))

	requireNodeAgentLog(t, "signed bundle overlays enabled", "the root-signed trust policy must verify")
	requireNodeAgentLog(t, "signed rule fragments enabled", "a policy carrying ruleClasses must enable signed rules")
	// The chart's unsigned baseline is now inadmissible; the signed one replaced
	// it. Proving the agent actually admitted a fragment keeps the later
	// severity assertions from passing on an accidental empty ruleset.
	requireNodeAgentLog(t, "RulesWatcher - signed rule fragments", "the watcher must report its signed-fragment tally")

	return func() {
		for _, c := range cleanups {
			c()
		}
		setBundleTrustPolicy(t, signedFixturePath(fixtureTrustPolicyProfilesOnly))
	}
}

// r0001AlertsFor returns the R0001 alerts raised in ns for the given comm.
func r0001AlertsFor(ns, comm string) []testutils.Alert {
	alerts, _ := testutils.GetAlerts(ns)
	var out []testutils.Alert
	for _, a := range alerts {
		if a.Labels["rule_id"] == "R0001" && a.Labels["comm"] == comm {
			out = append(out, a)
		}
	}
	return out
}

// alertSeverities collects the distinct severity labels of a set of alerts.
func alertSeverities(alerts []testutils.Alert) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range alerts {
		if s := a.Labels["severity"]; !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// alertsMentioning reports whether any alert's rendered message contains marker.
func alertsMentioning(alerts []testutils.Alert, marker string) bool {
	for _, a := range alerts {
		for _, v := range a.Annotations {
			if strings.Contains(v, marker) {
				return true
			}
		}
	}
	return false
}

// Test_37_SignedBundleOverlay is the end-to-end CT for multi-file signed
// ContainerProfile overlays ("bundles"): several independently signed partial
// CPs — authored by DIFFERENT parties — are verified per-leaf against the
// cluster trust policy, assembled into one composite profile, and enforced.
//
// The fragments are PRE-SIGNED fixtures under tests/resources/signed/fragments,
// ingested as signed (the cluster never sees an unsigned form). Their signatures
// cover embedded content, so they survive storage's spec normalisation and are
// independent of the install namespace. Phases:
//
//  0. Fragments round-trip storage with their signatures intact.
//  1. Assembly + enforcement: an exec allowed only by the overlay fragment
//     (union proof) does NOT alert; an exec in no fragment fires R0001.
//  2. Tamper: one fragment's embedded signed content is corrupted in storage →
//     the reconciler re-assembly rejects the bundle and fires R1016.
//  3. Recovery: the pristine fixture is re-applied → the composite returns and
//     is enforced again (fresh unlisted exec alerts; the overlay-allowed exec
//     stays quiet).
func Test_37_SignedBundleOverlay(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const (
		bundleName    = "bundle37"
		containerName = "curl"
	)

	ns := testutils.NewRandomNamespace()
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	// The chart must be shipping the committed root-signed policy; the fragment
	// signer fingerprints below are the ones that policy trusts.
	requireChartTrustPolicyIsFixture(t)

	// Fragment 1 — vendor default (class base, VENDOR key): the workload's
	// baseline execs. Does NOT allow id/ls/uname.
	// Fragment 2 — client admission (class admission, OPERATOR key): the
	// later-allowlisted ingress identity as a standalone signed fragment.
	// Exercises the admission class in-cluster; enforcement of it is
	// network-rule dependent, so the assembly itself is the assertion (an
	// inadmissible fragment would fail the WHOLE bundle closed and phase 1 could
	// not pass).
	// Fragment 3 — end-user overlay (class overlay, OPERATOR key): additionally
	// allows /usr/bin/id. The union proof hinges on this fragment: id is in NO
	// other fragment.
	//
	// Phase 0 (signatures survive the storage round-trip) is asserted inside
	// applySignedFragment.
	applyBundle37Fragments(t, storageClient, ns.Name)

	// Deploy the workload referencing the bundle.
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/bundle37-deployment.yaml"))
	require.NoError(t, err, "create workload")
	require.NoError(t, wl.WaitForReady(80), "workload ready")
	time.Sleep(30 * time.Second) // let node-agent assemble + project the composite

	countR0001 := func(comm string) int {
		alerts, _ := testutils.GetAlerts(ns.Name)
		n := 0
		for _, a := range alerts {
			if a.Labels["rule_id"] == "R0001" && a.Labels["container_name"] == containerName && a.Labels["comm"] == comm {
				n++
			}
		}
		return n
	}
	hasR1016 := func() bool {
		alerts, _ := testutils.GetAlerts(ns.Name)
		for _, a := range alerts {
			if a.Labels["rule_id"] == "R1016" {
				return true
			}
		}
		return false
	}

	// ── Phase 1: assembly + enforcement ──
	// Gate on the composite being loaded AND enforced: ls is in no fragment, so
	// once the composite is live it must fire R0001.
	// Exec via PATH-resolved names: the curl image is alpine/busybox, where ls
	// lives at /bin/ls (an absolute /usr/bin/ls exec fails and produces NO exec
	// event at all — starving the R0001 gate). id resolves to /usr/bin/id, the
	// exact path the overlay fragment allows.
	stdout, stderr, execErr := wl.ExecIntoPod([]string{"ls", "-l"}, containerName)
	t.Logf("probe ls → err=%v stdout=%.60q stderr=%.60q", execErr, stdout, stderr)
	require.Eventually(t, func() bool {
		wl.ExecIntoPod([]string{"ls", "-l"}, containerName)
		return countR0001("ls") > 0
	}, 3*time.Minute, 10*time.Second, "ls (in no fragment) must fire R0001 once the composite is enforced")
	require.Eventually(t, func() bool {
		before := countR0001("id")
		wl.ExecIntoPod([]string{"id"}, containerName)
		time.Sleep(8 * time.Second)
		return countR0001("id") == before
	}, 3*time.Minute, 12*time.Second, "id must become allowed once the overlay fragment is enforced")
	curlBefore := countR0001("curl")
	wl.ExecIntoPod([]string{"curl", "--version"}, containerName)
	time.Sleep(12 * time.Second)
	require.Equal(t, curlBefore, countR0001("curl"), "curl is allowed via the base fragment")
	require.False(t, hasR1016(), "no tamper yet — R1016 must not have fired in phase 1")
	t.Logf("phase1 OK: composite enforced (R0001 ls=%d id=0 curl=0)", countR0001("ls"))

	// ── Phase 2: tamper a fragment in storage ──
	// The fixture's signature covers EMBEDDED content, so editing the stored
	// spec is a no-op for verification (the embedded bytes stay authoritative,
	// which is the whole point of shippable artifacts). The tamper that matters
	// is corrupting that embedded blob: the object still CLAIMS to be signed,
	// so a blob that no longer decodes is a tamper signal, not an operational
	// hiccup, and must fail the bundle closed with R1016.
	patch := []byte(`[{"op":"replace","path":"/metadata/annotations/signature.kubescape.io~1content","value":"dGFtcGVyZWQ="}]`)
	_, err = storageClient.ContainerProfiles(ns.Name).Patch(context.Background(), bundleName+"-overlay", types.JSONPatchType, patch, v1.PatchOptions{})
	require.NoError(t, err, "tamper the overlay fragment's embedded signed content")
	require.Eventually(t, hasR1016, 3*time.Minute, 5*time.Second,
		"tampered bundle fragment must fire R1016 on reconciler re-assembly")
	t.Log("phase2 OK: R1016 fired on the tampered fragment")

	// ── Phase 3: recovery — restore the pristine signed fixture ──
	idBefore := countR0001("id")
	var tampered *v1beta1.ContainerProfile
	require.Eventually(t, func() bool {
		s, e := storageClient.ContainerProfiles(ns.Name).Get(context.Background(), bundleName+"-overlay", v1.GetOptions{})
		if e != nil {
			return false
		}
		tampered = s
		return true
	}, 30*time.Second, time.Second, "fetch tampered fragment for recovery")
	var pristine v1beta1.ContainerProfile
	require.NoError(t, yaml.Unmarshal(signedFixture(t, fixtureFragOverlay), &pristine), "parse pristine overlay fixture")
	tampered.Annotations[signatureContentAnno] = pristine.Annotations[signatureContentAnno]
	_, err = storageClient.ContainerProfiles(ns.Name).Update(context.Background(), tampered, metav1.UpdateOptions{})
	require.NoError(t, err, "restore the pristine signed fragment")
	// The composite must come back and be enforced: a FRESH unlisted exec
	// (uname, no cooldown collision with ls) alerts again, while id stays quiet
	// — distinguishing a recovered composite from a dropped/empty profile.
	require.Eventually(t, func() bool {
		wl.ExecIntoPod([]string{"uname", "-a"}, containerName)
		wl.ExecIntoPod([]string{"id"}, containerName)
		return countR0001("uname") > 0
	}, 3*time.Minute, 10*time.Second, "after recovery the composite must be enforced again (uname fires R0001)")
	require.Equal(t, idBefore, countR0001("id"), "id must stay allowed after recovery — composite (not an empty profile) is enforced")
	t.Logf("phase3 OK: bundle recovered from the pristine fixture (uname=%d, id stable at %d)", countR0001("uname"), idBefore)
}

// setBundleTrustPolicy replaces the mounted trust-policy artifact with the
// contents of policyPath and restarts node-agent so it re-reads it. The agent
// only ever VERIFIES this artifact (root public key compiled into the image), so
// swapping it is how a test switches rule signing on and off.
func setBundleTrustPolicy(t *testing.T, policyPath string) {
	t.Helper()
	body, err := os.ReadFile(policyPath)
	require.NoError(t, err, "read trust policy %s", policyPath)

	k8sClient := k8sinterface.NewKubernetesApi()
	cm, err := k8sClient.KubernetesClient.CoreV1().ConfigMaps("kubescape").
		Get(context.Background(), "node-agent-bundle-policy", metav1.GetOptions{})
	require.NoError(t, err, "get bundle policy ConfigMap")
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data["trust-policy.json"] = string(body)
	_, err = k8sClient.KubernetesClient.CoreV1().ConfigMaps("kubescape").
		Update(context.Background(), cm, metav1.UpdateOptions{})
	require.NoError(t, err, "update bundle policy ConfigMap")

	require.NoError(t, testutils.RestartDaemonSet("kubescape", "node-agent"), "restart node-agent")
	// The agent must come up, load the policy and do its initial rules sync
	// before any fragment applied below can be admitted.
	time.Sleep(45 * time.Second)
}

// Test_38_SignedRulesBundleOverlay is the end-to-end CT for signed RULE
// overlays and the scope they are confined to.
//
// Every artifact it installs is a PRE-SIGNED fixture from tests/resources/signed
// — no signing key exists anywhere on the cluster — so this also exercises the
// verify-only deployment model.
//
// Scoping is by BUNDLE, not by namespace. A rules overlay carries the same
// signature.kubescape.io/bundle label as the ContainerProfile fragments it ships
// with, and a workload opts into both halves with the pod label
// kubescape.io/user-defined-profile. Bundle membership and fragment class live
// in metadata.labels, which IS signed, so an installer can neither re-target an
// overlay at another bundle nor promote it to cluster-wide.
//
// metadata.namespace is deliberately NOT signed: a vendor cannot know which
// namespace a customer installs into. Two consequences are asserted here:
//
//  1. Vendor freedom — the fixture ships with no namespace at all and is
//     installed into a RANDOM (non-default) namespace, yet is admitted and
//     enforced there. This is the property the unsigned namespace exists for.
//  2. Confinement is by bundle — in that SAME namespace, a workload that opted
//     into bundle37 gets the overlay's R0001 while a workload that did not keeps
//     the cluster-wide base R0001. Same namespace, same exec, same rule ID: the
//     only variable is bundle membership, so a passing run cannot be explained
//     by namespace scoping.
//
// The two R0001 variants are told apart by severity and by the marker only the
// overlay's rendered message contains.
func Test_38_SignedRulesBundleOverlay(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	// A random namespace is the point: the vendor never knew this name, and the
	// signed artifacts carry no namespace of their own.
	ns := testutils.NewRandomNamespace()

	// The ContainerProfile half of bundle37, so the opted-in workload has a
	// profile at all.
	applyBundle37Fragments(t, storageClient, ns.Name)

	// The rules half: the base ruleset cluster-wide, the overlay installed into
	// this namespace. Once rule signing is on, the chart's UNSIGNED
	// kubescape-rules object is rejected, so the base fragment is the only
	// source of the cluster-wide R0001.
	defer enableSignedRuleFragments(t, map[string]string{fixtureRulesOverlay: ns.Name})()

	// Two workloads, ONE namespace. bundle37 opts into the bundle via
	// kubescape.io/user-defined-profile; nginx does not.
	inBundle, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/bundle37-deployment.yaml"))
	require.NoError(t, err, "create the bundle37 workload")
	outOfBundle, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "create the non-bundle workload")

	require.NoError(t, inBundle.WaitForReady(80), "bundle37 workload ready")
	require.NoError(t, outOfBundle.WaitForContainerProfileCompletion(160), "non-bundle profile completion")
	time.Sleep(30 * time.Second) // bundle assembly + profile cache

	// The same unlisted exec in both workloads. ls is in no bundle37 fragment
	// and not in the learned nginx profile, so it must fire R0001 for both.
	require.Eventually(t, func() bool {
		inBundle.ExecIntoPod([]string{"ls", "-l"}, "curl")
		outOfBundle.ExecIntoPod([]string{"ls", "-l"}, "nginx")
		return len(r0001AlertsFor(ns.Name, "ls")) > 0
	}, 3*time.Minute, 10*time.Second, "the unlisted exec must fire R0001")

	alertsFor := func(container string) []testutils.Alert {
		var out []testutils.Alert
		for _, a := range r0001AlertsFor(ns.Name, "ls") {
			if a.Labels["container_name"] == container {
				out = append(out, a)
			}
		}
		return out
	}

	// Property 1 + 2: the opted-in workload gets the OVERLAY variant, in a
	// namespace the vendor never knew about.
	require.Eventually(t, func() bool { return len(alertsFor("curl")) > 0 }, 2*time.Minute, 10*time.Second,
		"the bundle37 workload must raise R0001")
	overlayAlerts := alertsFor("curl")
	t.Logf("ns %s bundle37 workload: %d R0001 alerts, severities %v", ns.Name, len(overlayAlerts), alertSeverities(overlayAlerts))
	require.Equal(t, []string{overlayR0001Severity}, alertSeverities(overlayAlerts),
		"the overlay R0001 must REPLACE the base one for a bundle member, not coexist with it")
	require.True(t, alertsMentioning(overlayAlerts, overlayR0001Marker),
		"the bundle member's alert must carry the overlay's rendered message")

	// Property 2: same namespace, no bundle opt-in → untouched base rule. This
	// is what rules out namespace-wide application of the overlay.
	require.Eventually(t, func() bool { return len(alertsFor("nginx")) > 0 }, 2*time.Minute, 10*time.Second,
		"the non-bundle workload must raise R0001")
	baseAlerts := alertsFor("nginx")
	t.Logf("ns %s non-bundle workload: %d R0001 alerts, severities %v", ns.Name, len(baseAlerts), alertSeverities(baseAlerts))
	require.Equal(t, []string{baseR0001Severity}, alertSeverities(baseAlerts),
		"a workload that did not opt into bundle37 must keep the cluster-wide base R0001")
	require.False(t, alertsMentioning(baseAlerts, overlayR0001Marker),
		"the overlay applied to a workload outside its bundle — scoping is by bundle, not by namespace")

	t.Logf("overlay enforced for bundle37 members and only them, in non-default namespace %s", ns.Name)
}

// Test_39_SignedRulesUntrustedSignerRejected proves the rule-fragment admission
// gate: a Rules fragment signed by a key NO trust policy names is refused, and
// the rule it tried to redefine keeps behaving exactly as the trusted baseline
// says.
//
// The rogue fragment is a base-class R0001 with a different severity and
// message, signed with keys/ct-untrusted.pem. It is ingested BEFORE node-agent
// restarts, so it is present at the rules watcher's initial sync — the refusal
// has to happen on the first pass, not only on a later watch event.
func Test_39_SignedRulesUntrustedSignerRejected(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const containerName = "nginx"

	ns := testutils.NewRandomNamespace()
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "create workload")
	require.NoError(t, wl.WaitForReady(80), "workload ready")

	defer enableSignedRuleFragments(t, map[string]string{fixtureRulesUntrusted: ksNamespace})()

	// (1) The agent says it refused it, and says why.
	requireNodeAgentLog(t, "rules fragment rejected", "an untrusted-signer rules fragment must be rejected")
	logs := nodeAgentLogs(t)
	require.Contains(t, logs, "ct-rogue-rules", "the rejection must name the rogue fragment")
	require.Contains(t, logs, "signer not permitted for this fragment class",
		"the rejection reason must be the untrusted signer, not an incidental parse failure")

	// (2) The rogue rule did not take effect: R0001 still behaves as the trusted
	// base fragment defines it. A log line alone would not prove that.
	require.NoError(t, wl.WaitForContainerProfileCompletion(160), "profile completion")
	time.Sleep(15 * time.Second)
	require.Eventually(t, func() bool {
		wl.ExecIntoPod([]string{"ls", "-l"}, containerName)
		return len(r0001AlertsFor(ns.Name, "ls")) > 0
	}, 3*time.Minute, 10*time.Second, "R0001 from the trusted base fragment must still fire")

	alerts := r0001AlertsFor(ns.Name, "ls")
	t.Logf("ns %s: %d R0001 alerts, severities %v", ns.Name, len(alerts), alertSeverities(alerts))
	require.Equal(t, []string{baseR0001Severity}, alertSeverities(alerts),
		"R0001 must keep the trusted base severity — the rogue retune must not have been admitted")
	require.NotContains(t, alertSeverities(alerts), untrustedR0001Severity, "the rogue severity must never appear")
	require.False(t, alertsMentioning(alerts, untrustedR0001Marker), "the rogue message must never appear")
}

// Test_40_TrustPolicyFailClosed proves the root pin on the trust policy.
//
// The mounted policy is swapped for one that is correctly formed and correctly
// signed — but by a key that is NOT the root key compiled into the image. The
// agent must refuse it and leave signed-bundle overlays DISABLED, so a bundle
// whose fragments are all valid is NOT assembled. A cluster-admin who can edit
// the ConfigMap therefore cannot turn on bundle enforcement of their own
// choosing.
//
// Phase 2 restores the shipped policy and shows the very same fragments then DO
// assemble and enforce — without that positive control, phase 1's "nothing
// happened" would also pass if the bundle path were simply broken.
func Test_40_TrustPolicyFailClosed(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const (
		bundleName    = "bundle37"
		containerName = "curl"
	)

	ns := testutils.NewRandomNamespace()
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	requireChartTrustPolicyIsFixture(t)

	// Leave the cluster as found even if an assertion aborts the test.
	restored := false
	defer func() {
		if restored {
			return
		}
		setBundleTrustPolicy(t, signedFixturePath(fixtureTrustPolicyProfilesOnly))
	}()

	applyBundle37Fragments(t, storageClient, ns.Name)
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/bundle37-deployment.yaml"))
	require.NoError(t, err, "create workload")
	require.NoError(t, wl.WaitForReady(80), "workload ready")

	countR0001 := func(comm string) int {
		n := 0
		for _, a := range r0001AlertsFor(ns.Name, comm) {
			if a.Labels["container_name"] == containerName {
				n++
			}
		}
		return n
	}

	// ── Phase 1: a policy signed by a NON-root key must fail closed ──
	setBundleTrustPolicy(t, signedFixturePath(fixtureTrustPolicyBadSigner))
	requireNodeAgentLog(t, "signed bundle overlays disabled: trust policy signature invalid",
		"a policy not signed by the embedded root key must be refused")
	// Give the reconciler several ticks with the workload running, so "no
	// assembly" is an observation and not just impatience.
	time.Sleep(90 * time.Second)
	logs := nodeAgentLogs(t)
	require.NotContains(t, logs, "signed bundle overlays enabled",
		"bundles must stay disabled under a wrongly-signed trust policy")
	require.NotContains(t, logs, "assembled signed bundle overlay",
		"no bundle may be assembled while the trust policy is refused, even though every fragment is valid")
	t.Log("phase1 OK: wrongly-signed trust policy refused, no bundle assembled")

	// ── Phase 2: positive control — restore the shipped policy ──
	setBundleTrustPolicy(t, signedFixturePath(fixtureTrustPolicyProfilesOnly))
	restored = true
	requireNodeAgentLog(t, "signed bundle overlays enabled", "the shipped root-signed policy must verify")
	requireNodeAgentLog(t, "assembled signed bundle overlay",
		"the SAME fragments must assemble once the trust policy is accepted")

	require.Eventually(t, func() bool {
		wl.ExecIntoPod([]string{"ls", "-l"}, containerName)
		return countR0001("ls") > 0
	}, 3*time.Minute, 10*time.Second, "with the trust policy accepted the composite must be enforced (ls fires R0001)")
	require.Eventually(t, func() bool {
		before := countR0001("id")
		wl.ExecIntoPod([]string{"id"}, containerName)
		time.Sleep(8 * time.Second)
		return countR0001("id") == before
	}, 3*time.Minute, 12*time.Second, "id must become allowed once the overlay fragment is enforced")
	t.Logf("phase2 OK: %s assembled and enforced after restoring the shipped policy", bundleName)
}

func Test_41_SignedBundleNamespaceFreedom(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const containerName = "curl"

	ns := testutils.NewRandomNamespace()
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	requireChartTrustPolicyIsFixture(t)

	for _, rel := range []string{fixtureFragBase, fixtureFragAdmission, fixtureFragOverlay} {
		var cp v1beta1.ContainerProfile
		require.NoError(t, yaml.Unmarshal(signedFixture(t, rel), &cp), "parse fixture %s", rel)
		require.Empty(t, cp.Namespace, "fixture %s must carry no namespace — namespace is not part of the signed content", rel)
	}

	applyBundle37Fragments(t, storageClient, ns.Name)

	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/bundle37-deployment.yaml"))
	require.NoError(t, err, "create workload")
	require.NoError(t, wl.WaitForReady(80), "workload ready")
	time.Sleep(30 * time.Second)

	requireNodeAgentLog(t, "assembled signed bundle overlay",
		"the same fixture bytes (no baked namespace) must assemble in a namespace the vendor never named")

	countR0001 := func(comm string) int {
		n := 0
		for _, a := range r0001AlertsFor(ns.Name, comm) {
			if a.Labels["container_name"] == containerName {
				n++
			}
		}
		return n
	}

	require.Eventually(t, func() bool {
		wl.ExecIntoPod([]string{"ls", "-l"}, containerName)
		return countR0001("ls") > 0
	}, 3*time.Minute, 10*time.Second, "unlisted exec must fire R0001 once the composite is enforced in the random namespace")
	require.Eventually(t, func() bool {
		before := countR0001("id")
		wl.ExecIntoPod([]string{"id"}, containerName)
		time.Sleep(8 * time.Second)
		return countR0001("id") == before
	}, 3*time.Minute, 12*time.Second, "id must become allowed once the overlay is enforced in the random namespace")
	t.Logf("namespace freedom: the unmodified fixture bytes assembled and enforced in non-default namespace %s (R0001 ls=%d id=0)", ns.Name, countR0001("ls"))
}

func Test_42_SignatureStrippedFragmentRejected(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const (
		bundleName    = "bundle37"
		overlayName   = "bundle37-overlay"
		containerName = "curl"
	)

	ns := testutils.NewRandomNamespace()
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)

	requireChartTrustPolicyIsFixture(t)
	applyBundle37Fragments(t, storageClient, ns.Name)

	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/bundle37-deployment.yaml"))
	require.NoError(t, err, "create workload")
	require.NoError(t, wl.WaitForReady(80), "workload ready")
	time.Sleep(30 * time.Second)

	requireNodeAgentLog(t, "assembled signed bundle overlay",
		"positive control: the fully signed bundle must assemble before the signature is stripped")

	hasR1016 := func() bool {
		alerts, _ := testutils.GetAlerts(ns.Name)
		for _, a := range alerts {
			if a.Labels["rule_id"] == "R1016" {
				return true
			}
		}
		return false
	}
	require.False(t, hasR1016(), "no tamper yet — R1016 must not have fired before stripping")

	patch := []byte(`[{"op":"remove","path":"/metadata/annotations/signature.kubescape.io~1signature"}]`)
	_, err = storageClient.ContainerProfiles(ns.Name).Patch(context.Background(), overlayName, types.JSONPatchType, patch, v1.PatchOptions{})
	require.NoError(t, err, "strip the signature annotation off the overlay fragment")

	require.Eventually(t, func() bool {
		s, e := storageClient.ContainerProfiles(ns.Name).Get(context.Background(), overlayName, v1.GetOptions{})
		if e != nil {
			return false
		}
		return !signature.IsSigned(profiles.NewContainerProfileAdapter(s))
	}, 30*time.Second, 2*time.Second, "the stored overlay fragment must now be unsigned")

	// The overlay was a verified member, so stripping its signature makes a KNOWN
	// member stop verifying: node-agent refuses the change and keeps the last
	// verified composite rather than dropping the workload's profile.
	requireNodeAgentLog(t, "signed bundle overlay refused: a verified member no longer verifies",
		"a stripped signature on a known member must be refused, keeping the last verified composite")
	logs := nodeAgentLogs(t)
	require.Contains(t, logs, "fragment is not signed",
		"the rejection reason must be the missing signature, not an incidental parse error")
	require.Contains(t, logs, overlayName, "the rejection must name the stripped member")

	time.Sleep(60 * time.Second)
	require.False(t, hasR1016(),
		"a signature-stripped (unsigned) fragment is an admissibility rejection, not a tamper — R1016 must NOT fire")
	t.Logf("signature-stripped member refused: kept last verified composite with an unsigned-fragment reason and no R1016 in namespace %s", ns.Name)
}

// Test_44_TrustAnchorModificationRequiresElevatedRBAC checks in the claim the
// demo makes about the trust anchor: replacing the node-agent-bundle-policy
// ConfigMap (which carries the root-signed trust policy and its signer public
// fingerprints) is not something an ordinary on-cluster identity may do.
//
// The PRIMARY control on the anchor is cryptographic, not RBAC: Test_40 already
// proves a policy not signed by the root key is refused no matter who writes the
// ConfigMap. This test pins the defense-in-depth RBAC layer — that a compromised
// workload's ServiceAccount cannot modify the anchor at all, while a
// cluster-admin subject can (so the deny is RBAC, not a missing resource).
//
// It uses SubjectAccessReview, so it evaluates the live cluster's RBAC without
// minting tokens or mutating anything.
func Test_44_TrustAnchorModificationRequiresElevatedRBAC(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	k8sClient := k8sinterface.NewKubernetesApi()
	sar := k8sClient.KubernetesClient.AuthorizationV1().SubjectAccessReviews()

	can := func(t *testing.T, user string, groups []string, verb string) bool {
		t.Helper()
		review := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   user,
				Groups: groups,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: ksNamespace,
					Verb:      verb,
					Group:     "",
					Resource:  "configmaps",
					Name:      bundlePolicyCM,
				},
			},
		}
		resp, err := sar.Create(context.Background(), review, metav1.CreateOptions{})
		require.NoError(t, err, "SubjectAccessReview for %s/%s", user, verb)
		return resp.Status.Allowed
	}

	// An ordinary workload identity — the default ServiceAccount of the default
	// namespace, which is what a compromised pod without extra RBAC runs as.
	const workloadSA = "system:serviceaccount:default:default"

	for _, verb := range []string{"update", "patch", "delete", "create"} {
		require.False(t, can(t, workloadSA, nil, verb),
			"an unprivileged workload ServiceAccount must NOT be able to %s the trust-anchor ConfigMap %s/%s",
			verb, ksNamespace, bundlePolicyCM)
	}
	t.Logf("unprivileged ServiceAccount %s is denied update/patch/delete/create on %s/%s", workloadSA, ksNamespace, bundlePolicyCM)

	// Positive control: a cluster-admin subject (system:masters is bound to the
	// cluster-admin ClusterRole by default) CAN modify it — so the denials above
	// are the RBAC boundary, not an unmodifiable or absent resource.
	require.True(t, can(t, "kubernetes-admin", []string{"system:masters"}, "update"),
		"a cluster-admin subject must be able to modify the trust-anchor ConfigMap (positive control)")
	t.Log("cluster-admin (system:masters) is allowed to modify the trust anchor: modification requires elevated RBAC, and the anchor is additionally signature-protected (Test_40)")
}

// Test_45_RuleSigningZeroAdmittedDetectionOutage pins the install-time contract
// of rule signing (issue #72) end to end: a policy carrying ruleClasses while
// only the chart's UNSIGNED baseline exists is a REAL detection outage — no
// alerts fire and the agent screams the backstop on every sync — and ingesting
// the signed baseline recovers detection through the watch event alone, with no
// agent restart.
func Test_45_RuleSigningZeroAdmittedDetectionOutage(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	const containerName = "nginx"
	ns := testutils.NewRandomNamespace()
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "create workload")
	require.NoError(t, wl.WaitForReady(80), "workload ready")
	require.NoError(t, wl.WaitForContainerProfileCompletion(160), "profile completion")

	// Rule signing ON with the signed baseline deliberately NOT ingested: the
	// chart's unsigned kubescape-rules object is the only Rules object and is
	// inadmissible, so zero fragments admit.
	setBundleTrustPolicy(t, signedFixturePath(fixtureTrustPolicyFull))
	defer setBundleTrustPolicy(t, signedFixturePath(fixtureTrustPolicyProfilesOnly))

	requireNodeAgentLog(t, "signed rule fragments enabled", "a policy carrying ruleClasses must enable signed rules")
	requireNodeAgentLog(t, "detection is effectively OFF", "zero admitted fragments must raise the detection-outage backstop")

	// The outage is real, not just a log line: an exec R0001 would catch stays
	// silent while nothing is admitted.
	baseline := len(r0001AlertsFor(ns.Name, "ls"))
	for i := 0; i < 6; i++ {
		wl.ExecIntoPod([]string{"ls", "-l"}, containerName)
		time.Sleep(10 * time.Second)
	}
	require.Equal(t, baseline, len(r0001AlertsFor(ns.Name, "ls")),
		"R0001 fired while zero rule fragments were admitted — detection was supposed to be OFF")

	// Recovery: ingest the signed baseline. The rules watcher resyncs on the
	// watch event; detection must come back WITHOUT restarting the agent.
	cleanupBase := applySignedRules(t, ksNamespace, fixtureRulesBase)
	defer cleanupBase()
	require.Eventually(t, func() bool {
		wl.ExecIntoPod([]string{"ls", "-l"}, containerName)
		return len(r0001AlertsFor(ns.Name, "ls")) > baseline
	}, 3*time.Minute, 10*time.Second,
		"R0001 must fire once the signed baseline is admitted — recovery from the outage needs no restart")
	t.Logf("outage while zero admitted, recovery on signed-baseline ingest without restart (ns %s)", ns.Name)
}

// updateBundleTrustPolicy writes the trust-policy ConfigMap WITHOUT restarting
// node-agent: the reload path under test must pick it up on its own.
func updateBundleTrustPolicy(t *testing.T, body []byte) {
	t.Helper()
	k8sClient := k8sinterface.NewKubernetesApi()
	cm, err := k8sClient.KubernetesClient.CoreV1().ConfigMaps("kubescape").
		Get(context.Background(), "node-agent-bundle-policy", metav1.GetOptions{})
	require.NoError(t, err, "get bundle policy ConfigMap")
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data["trust-policy.json"] = string(body)
	_, err = k8sClient.KubernetesClient.CoreV1().ConfigMaps("kubescape").
		Update(context.Background(), cm, metav1.UpdateOptions{})
	require.NoError(t, err, "update bundle policy ConfigMap")
}

// requireNodeAgentLogWithin is requireNodeAgentLog with a caller-chosen window
// (ConfigMap mount propagation ~1min + the 30s reload poll need more than the
// default 2min in the worst case).
func requireNodeAgentLogWithin(t *testing.T, substr, msg string, within time.Duration) {
	t.Helper()
	require.Eventually(t, func() bool {
		return strings.Contains(nodeAgentLogs(t), substr)
	}, within, 5*time.Second, "%s (expected %q in the node-agent log)", msg, substr)
}

func nodeAgentRestartCounts(t *testing.T) map[string]int32 {
	t.Helper()
	k8sClient := k8sinterface.NewKubernetesApi()
	pods, err := k8sClient.KubernetesClient.CoreV1().Pods("kubescape").
		List(context.Background(), metav1.ListOptions{LabelSelector: "app=node-agent"})
	require.NoError(t, err)
	out := map[string]int32{}
	for _, p := range pods.Items {
		for _, cs := range p.Status.ContainerStatuses {
			if cs.Name == "node-agent" {
				out[p.Name] = cs.RestartCount
			}
		}
	}
	return out
}

// Test_46_TrustPolicyReloadLifecycle pins the no-restart reload path end to
// end: an invalid boot policy leaves signing off but recoverable; a valid
// policy mounted later enables signing without a restart; scoping up to
// ruleClasses re-evaluates Rules admission via resync (no watch event); a
// refused reload names both digests so the enforced policy is identifiable
// from the log alone.
func Test_46_TrustPolicyReloadLifecycle(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	profilesOnly, err := os.ReadFile(signedFixturePath(fixtureTrustPolicyProfilesOnly))
	require.NoError(t, err)
	full, err := os.ReadFile(signedFixturePath(fixtureTrustPolicyFull))
	require.NoError(t, err)
	badSigner, err := os.ReadFile(signedFixturePath(fixtureTrustPolicyBadSigner))
	require.NoError(t, err)
	defer setBundleTrustPolicy(t, signedFixturePath(fixtureTrustPolicyProfilesOnly))

	// Boot on garbage: signing disabled, said loudly, agent running.
	updateBundleTrustPolicy(t, []byte("{this is not a signed policy}"))
	require.NoError(t, testutils.RestartDaemonSet("kubescape", "node-agent"), "restart onto the garbage policy")
	time.Sleep(30 * time.Second)
	requireNodeAgentLogWithin(t, "trust policy invalid at startup", "an invalid boot policy must scream, not crash", 3*time.Minute)

	baseline := nodeAgentRestartCounts(t)

	// Recovery without restart: a valid (profiles-only) policy mounted later.
	updateBundleTrustPolicy(t, profilesOnly)
	requireNodeAgentLogWithin(t, "signed bundle overlays enabled", "signing must enable from the reloader alone", 4*time.Minute)
	requireNodeAgentLogWithin(t, "rule signing DISABLED", "a policy without ruleClasses must say rule signing is off", 1*time.Minute)

	// Scope up: ruleClasses arrive; the resync must drop the chart's unsigned
	// rules within one reload interval, with no Rules watch event.
	updateBundleTrustPolicy(t, full)
	requireNodeAgentLogWithin(t, "trust policy reloaded without restart", "the full policy must apply via reload", 4*time.Minute)
	requireNodeAgentLogWithin(t, "signed rule fragments enabled", "ruleClasses must enable rule signing on reload", 1*time.Minute)
	requireNodeAgentLogWithin(t, "detection is effectively OFF", "the resync must re-evaluate the unsigned baseline without a watch event", 2*time.Minute)

	// Signing the baseline recovers detection (watch event path).
	cleanupBase := applySignedRules(t, ksNamespace, fixtureRulesBase)
	defer cleanupBase()
	requireNodeAgentLogWithin(t, `"admitted":1`, "the signed baseline must admit", 2*time.Minute)

	// Refused reload: both digests in the log; sha256sum of the mounted
	// artifact matches the in-force digest.
	updateBundleTrustPolicy(t, badSigner)
	requireNodeAgentLogWithin(t, "trust policy reload REFUSED", "a wrongly-signed policy must be refused", 4*time.Minute)
	logs := nodeAgentLogs(t)
	fullDigest := fmt.Sprintf("%x", sha256.Sum256(full))
	badDigest := fmt.Sprintf("%x", sha256.Sum256(badSigner))
	require.Contains(t, logs, fullDigest, "the refusal must name the in-force policy by its artifact sha256")
	require.Contains(t, logs, badDigest, "the refusal must name the refused artifact by its sha256")

	for pod, count := range nodeAgentRestartCounts(t) {
		require.Equal(t, baseline[pod], count, "pod %s restarted — every phase after boot must be restart-free", pod)
	}
}

// Test_47_StoredSpecDivergenceInert pins #70 in-cluster: editing the stored
// spec of an embedded-content signed fragment changes nothing that is enforced
// — no R1016, no new bundle root — and the agent says the stored spec is
// display-only.
func Test_47_StoredSpecDivergenceInert(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := spdxv1beta1client.NewForConfigOrDie(k8sClient.K8SConfig)
	ns := testutils.NewRandomNamespace()

	applyBundle37Fragments(t, storageClient, ns.Name)
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/bundle37-deployment.yaml"))
	require.NoError(t, err, "create the bundle37 workload")
	require.NoError(t, wl.WaitForReady(80), "workload ready")
	time.Sleep(45 * time.Second) // bundle assembly

	r1016Before := strings.Count(nodeAgentLogs(t), `"RuleID":"R1016"`)

	patch := []byte(`[{"op":"add","path":"/spec/execs/-","value":{"path":"/bin/backdoor-ct47"}}]`)
	_, err = storageClient.ContainerProfiles(ns.Name).Patch(context.Background(), "bundle37-base", types.JSONPatchType, patch, v1.PatchOptions{})
	require.NoError(t, err, "edit the stored spec of the embedded-content fragment")

	requireNodeAgentLogWithin(t, "stored spec diverges", "the display-only divergence must be reported", 3*time.Minute)
	logs := nodeAgentLogs(t)
	require.NotContains(t, logs, "/bin/backdoor-ct47", "spec values must never reach the log")
	require.Equal(t, r1016Before, strings.Count(logs, `"RuleID":"R1016"`),
		"a stored-spec edit is not a tamper of enforced content — R1016 must not fire")

	// The injected exec is NOT enforced: running it must alert as unexpected.
	require.Eventually(t, func() bool {
		wl.ExecIntoPod([]string{"ls", "-l"}, "curl")
		return len(r0001AlertsFor(ns.Name, "ls")) > 0
	}, 3*time.Minute, 10*time.Second, "an exec outside the SIGNED content must still raise R0001 — the composite must be unchanged")
}
