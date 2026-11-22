package containerprofile

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/assert"
)

const saToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"

func processLib(entries []objectcache.OpenEntry, paths ...string) *containerProfileLibrary {
	values := map[string]struct{}{}
	for _, p := range paths {
		values[p] = struct{}{}
	}
	pcp := &objectcache.ProjectedContainerProfile{
		Opens:       objectcache.ProjectedField{All: true, Values: values},
		OpenEntries: entries,
	}
	return &containerProfileLibrary{objectCache: &mockObjectCacheForPattern{pcp: pcp}}
}

func boolOf(v interface{ Value() any }) bool {
	b, _ := v.Value().(bool)
	return b
}

func TestWasPathOpenedBy_TokenAdmitsOnlyTheListedExecutable(t *testing.T) {
	lib := processLib([]objectcache.OpenEntry{{Path: saToken, Processes: []string{"/app/server"}}}, saToken)
	assert.True(t, boolOf(lib.wasPathOpenedBy(types.String("c"), types.String(saToken), types.String("/app/server"))))
	assert.False(t, boolOf(lib.wasPathOpenedBy(types.String("c"), types.String(saToken), types.String("/bin/cat"))))
	assert.False(t, boolOf(lib.wasPathOpenedBy(types.String("c"), types.String(saToken), types.String(""))), "an unknown executable is not admitted")
	assert.True(t, boolOf(lib.wasPathOpened(types.String("c"), types.String(saToken))), "the path-only check ignores processes")
}

func TestWasPathOpenedBy_EntryWithoutProcessesAdmitsAnyExecutable(t *testing.T) {
	lib := processLib([]objectcache.OpenEntry{
		{Path: saToken, Processes: []string{"/app/server"}},
		{Path: "/etc/hosts"},
	}, saToken, "/etc/hosts")
	assert.True(t, boolOf(lib.wasPathOpenedBy(types.String("c"), types.String("/etc/hosts"), types.String("/bin/cat"))))
	assert.True(t, boolOf(lib.wasPathOpenedBy(types.String("c"), types.String("/etc/hosts"), types.String(""))))
}

func TestWasPathOpenedBy_PatternsInPathAndExecutable(t *testing.T) {
	lib := processLib([]objectcache.OpenEntry{{Path: "/var/run/secrets/kubernetes.io/serviceaccount/⋯/token", Processes: []string{"/opt/⋯/agent"}}})
	rotated := "/var/run/secrets/kubernetes.io/serviceaccount/..2026_01_01_00_00_00.1/token"
	assert.True(t, boolOf(lib.wasPathOpenedBy(types.String("c"), types.String(rotated), types.String("/opt/v2/agent"))))
	assert.False(t, boolOf(lib.wasPathOpenedBy(types.String("c"), types.String(rotated), types.String("/usr/bin/nc"))))
}

func TestWasPathOpenedWithSuffixBy_TokenRotationAndExecutable(t *testing.T) {
	lib := processLib([]objectcache.OpenEntry{{Path: saToken, Processes: []string{"/app/server"}}}, saToken)
	assert.True(t, boolOf(lib.wasPathOpenedWithSuffixBy(types.String("c"), types.String("/token"), types.String("/app/server"))))
	assert.False(t, boolOf(lib.wasPathOpenedWithSuffixBy(types.String("c"), types.String("/token"), types.String("/bin/cat"))))
	assert.False(t, boolOf(lib.wasPathOpenedWithSuffixBy(types.String("c"), types.String("/token"), types.String(""))))
}

func TestWasPathOpenedBy_ProfileWithoutProcessesKeepsThePathOnlyAnswer(t *testing.T) {
	lib := processLib(nil, saToken)
	assert.True(t, boolOf(lib.wasPathOpenedBy(types.String("c"), types.String(saToken), types.String("/bin/cat"))))
	assert.True(t, boolOf(lib.wasPathOpenedWithSuffixBy(types.String("c"), types.String("/token"), types.String("/bin/cat"))))
}
