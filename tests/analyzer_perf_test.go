//go:build component

package tests

// Test_32_AnalyzerPerfBaseline — measures allocation volume attributable
// to storage's dynamicpathdetector under realistic node-agent load.
//
// The analyzer is storage-side code that runs inside the Aggregated API
// Server pod; allocations in its hot path (processSegments, AnalyzePath)
// scale with the volume of file-open events node-agent forwards. This
// test drives real load through node-agent → storage and measures the
// analyzer's allocation contribution via storage's pprof endpoint
// (exposed on :6060 inside the pod).
//
// The test does NOT assert on an absolute threshold — it emits a signed
// delta between a "quiet" baseline and a "loaded" window, which can then
// be compared across different storage builds (e.g. old analyzer vs new
// analyzer). A follow-up PR can gate on a relative target once the
// baseline is stable across runs.

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/tests/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// storageAllocStats are the columns we care about from a pprof/allocs
// text dump: total in-use objects + a pair of per-function counts for
// the analyzer's hot path.
type storageAllocStats struct {
	TotalObjects    int64
	ProcessSegments int64
	AnalyzePath     int64
	RawText         string
}

// scrapeStorageAllocs exec-into-storage and curls the pprof/allocs?debug=1
// endpoint to get a text-format allocation profile. Parses out the two
// analyzer functions we care about plus the overall total.
func scrapeStorageAllocs(t *testing.T) storageAllocStats {
	t.Helper()
	// Find the storage pod. The Kubescape Helm chart labels it with
	// `app.kubernetes.io/name=storage` (see tests/scripts/local-ci.sh
	// for the canonical wait-for-ready call using the same selector).
	// An earlier version of this test used the shorter `app=storage`
	// label which does not exist on chart-deployed pods — the List
	// returned empty and the test failed before the first scrape.
	const (
		storageNs    = "kubescape"
		storageLabel = "app.kubernetes.io/name=storage"
	)
	k8sClient := k8sinterface.NewKubernetesApi()
	pods, err := k8sClient.KubernetesClient.CoreV1().Pods(storageNs).List(context.TODO(), metav1.ListOptions{
		LabelSelector: storageLabel,
	})
	if err != nil || len(pods.Items) == 0 {
		t.Fatalf("could not find storage pod (label %q in %s): %v", storageLabel, storageNs, err)
	}
	podName := pods.Items[0].Name

	out, _, err := testutils.ExecIntoPod(podName, storageNs,
		[]string{"sh", "-c", "wget -qO- http://127.0.0.1:6060/debug/pprof/allocs?debug=1 || curl -s http://127.0.0.1:6060/debug/pprof/allocs?debug=1"},
		"")
	if err != nil {
		t.Fatalf("scrape pprof/allocs from storage pod %s: %v", podName, err)
	}

	stats := storageAllocStats{RawText: out}

	// pprof text dump looks like:
	//   heap profile: 100: 4096 [200: 8192] @ heap/1048576
	//   ...
	//   <count>: <bytes> [<cum_count>: <cum_bytes>] @ <stack-id>
	// Followed by a section like:
	//   # ... frames ...
	// We want per-function counts, which are accessible via "-top" via
	// `pprof`. For the quick in-cluster scrape, the text dump includes
	// a line at the very top: "heap profile: ... @ heap/<total>".
	// We parse that for the overall objects count, and look for lines
	// mentioning our analyzer functions.
	re := regexp.MustCompile(`(?m)^heap profile: (\d+):`)
	if m := re.FindStringSubmatch(out); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &stats.TotalObjects)
	}
	// Rough per-function tally: count matches of symbol names across
	// stack frames. Not exact alloc counts but a cheap proxy that
	// increases with load.
	stats.ProcessSegments = int64(strings.Count(out, "dynamicpathdetector.(*PathAnalyzer).processSegments"))
	stats.AnalyzePath = int64(strings.Count(out, "dynamicpathdetector.(*PathAnalyzer).AnalyzePath"))
	return stats
}

func Test_32_AnalyzerPerfBaseline(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()

	nginx, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	require.NoError(t, err, "create nginx workload")
	require.NoError(t, nginx.WaitForReady(80), "wait for nginx ready")
	require.NoError(t, nginx.WaitForApplicationProfileCompletion(80), "wait for AP complete")

	// Quiet baseline: short settle window with no synthetic load.
	t.Log("capturing quiet baseline (30s)")
	time.Sleep(30 * time.Second)
	baseline := scrapeStorageAllocs(t)
	t.Logf("baseline: total_objects=%d processSegments_frames=%d AnalyzePath_frames=%d",
		baseline.TotalObjects, baseline.ProcessSegments, baseline.AnalyzePath)

	// Heavy file-open load: 10,000 file touches per iteration × 100 iterations
	// = 1M file-open events funnelled through node-agent → storage. This is
	// the workload storage's analyzer has to absorb and dedup.
	t.Log("running heavy load (1M file-open events)")
	loadStart := time.Now()
	for i := 0; i < 100; i++ {
		_, _, err := nginx.ExecIntoPod(
			[]string{"bash", "-c", "for i in $(seq 1 10000); do touch /tmp/perf-$i; done"}, "")
		require.NoError(t, err, "load iteration %d", i)
	}
	t.Logf("load phase took %s", time.Since(loadStart))

	// Let storage catch up + GC.
	t.Log("waiting 60s for storage to process and GC")
	time.Sleep(60 * time.Second)
	loaded := scrapeStorageAllocs(t)
	t.Logf("loaded:   total_objects=%d processSegments_frames=%d AnalyzePath_frames=%d",
		loaded.TotalObjects, loaded.ProcessSegments, loaded.AnalyzePath)

	deltaObjects := loaded.TotalObjects - baseline.TotalObjects
	t.Logf("DELTA under 1M file-opens: total_objects=%+d", deltaObjects)

	// Soft assertion: total objects should not explode. 10× growth is
	// the symptom an allocation-heavy analyzer would produce. This is
	// a loose gate to catch regressions rather than a strict SLO.
	if baseline.TotalObjects > 0 {
		ratio := float64(loaded.TotalObjects) / float64(baseline.TotalObjects)
		t.Logf("loaded/baseline object ratio: %.2f", ratio)
		assert.Less(t, ratio, 10.0,
			"storage allocations grew >10× under 1M-event load — likely analyzer regression")
	}
}

// (testutils already exposes ExecIntoPod; pod lookup inlined above via
// k8sinterface.NewKubernetesApi() to avoid adding a new testutils helper
// for a single call-site.)
