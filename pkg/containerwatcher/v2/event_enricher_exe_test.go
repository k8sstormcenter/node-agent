package containerwatcher

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
)

func TestBranchExePath_FindsTheOpeningProcess(t *testing.T) {
	leaf := &armotypes.Process{PID: 42, Path: "/app/server"}
	mid := &armotypes.Process{PID: 7, Path: "/bin/sh", ChildrenMap: map[armotypes.CommPID]*armotypes.Process{{Comm: "server", PID: 42}: leaf}}
	root := &armotypes.Process{PID: 1, Path: "/sbin/init", ChildrenMap: map[armotypes.CommPID]*armotypes.Process{{Comm: "sh", PID: 7}: mid}}
	assert.Equal(t, "/app/server", branchExePath(root, 42))
	assert.Equal(t, "/bin/sh", branchExePath(root, 7))
	assert.Equal(t, "", branchExePath(root, 99))
	assert.Equal(t, "", branchExePath(nil, 1))
}
