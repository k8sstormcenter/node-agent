package containerprofilecache

import (
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/require"
)

// TestProjectedProfile_SurvivesContainerRemovalGrace pins the end-of-life
// contract for the event pipeline: when a container is removed, events that
// were emitted during its life are still in flight (ordered event queue 50ms
// collection tick + batching + worker pool), and the rule engine resolves the
// projected profile by container ID at evaluation time. Deleting the cache
// entry immediately on the remove callback makes rules with
// ProfileDependency=Required (e.g. R0001) silently suppress the container's
// terminal events as "profile_incomplete".
//
// Evidence: CI run 31846699597 Test_48 — init container "setup"
// (sh -c "sleep 75; /usr/bin/id"): remove processed at 22:44:26, terminal exec
// evaluated afterwards, zero R0001 despite adopted profile and 98 R0003 during
// the container's life.
//
// Contract: the projected profile must remain resolvable for a grace window
// after the remove callback (long enough to cover the event pipeline delay),
// and only then be evicted.
func TestProjectedProfile_SurvivesContainerRemovalGrace(t *testing.T) {
	c, _ := newTestCache(t, &fakeProfileClient{})

	c.SeedEntryForTest("eol-c1", &CachedContainerProfile{
		Projected: &objectcache.ProjectedContainerProfile{},
	})
	require.NotNil(t, c.GetProjectedContainerProfile("eol-c1"), "seeded entry must resolve")

	c.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: eventContainer("eol-c1"),
	})

	// Poll for 300ms: the entry must remain resolvable throughout — this is
	// well inside any reasonable grace window and far beyond the current
	// immediate async delete.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		require.NotNil(t, c.GetProjectedContainerProfile("eol-c1"),
			"projected profile must remain resolvable during the removal grace window so in-flight events can be evaluated")
		time.Sleep(20 * time.Millisecond)
	}
}
