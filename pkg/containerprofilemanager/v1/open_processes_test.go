package containerprofilemanager

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openBy(path, exe string) *utils.StructEvent {
	return &utils.StructEvent{EventType: utils.OpenEventType, Path: path, ExePath: exe, Flags: []string{"O_RDONLY"}}
}

func TestReportFileOpen_RecordsTheExecutablePerPath(t *testing.T) {
	cpm, entry := newTestManager(t, "c")
	cpm.ReportFileOpen("c", openBy("/etc/resolv.conf", "/app/server"))
	cpm.ReportFileOpen("c", openBy("/etc/resolv.conf", "/usr/bin/curl"))
	cpm.ReportFileOpen("c", openBy("/etc/resolv.conf", "/app/server"))
	opens := entry.data.getOpens()
	require.Len(t, opens, 1)
	assert.Equal(t, []string{"/app/server", "/usr/bin/curl"}, opens[0].Processes)
}

func TestReportFileOpen_UnknownExecutableIsSkippedAndCounted(t *testing.T) {
	cpm, entry := newTestManager(t, "c")
	cpm.ReportFileOpen("c", openBy("/etc/hosts", ""))
	assert.Empty(t, entry.data.getOpens())
	assert.Equal(t, uint64(1), cpm.UnknownExeOpens())
	assert.Zero(t, entry.data.size.Load())
}
