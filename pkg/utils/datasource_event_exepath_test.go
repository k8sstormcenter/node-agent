package utils

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/stretchr/testify/require"
)

func TestGetExePath_OpenWithoutTheFieldUsesTheEnrichedValue(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "exepath-fallback-open")
	require.NoError(t, err)
	fname, err := ds.AddField("fname", api.Kind_String)
	require.NoError(t, err)
	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	t.Cleanup(func() { ds.Release(data) })
	require.NoError(t, fname.PutString(data, "/etc/hosts"))
	e := &DatasourceEvent{Data: data, Datasource: ds, EventType: EventType("exepath-fallback-open")}
	require.Equal(t, "", e.GetExePath())
	e.SetExePath("/app/server")
	require.Equal(t, "/app/server", e.GetExePath())
}

func TestGetExePath_TheGadgetFieldWinsWhenPresent(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "exepath-fallback-exec")
	require.NoError(t, err)
	exe, err := ds.AddField("exepath", api.Kind_String)
	require.NoError(t, err)
	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	t.Cleanup(func() { ds.Release(data) })
	require.NoError(t, exe.PutString(data, "/usr/bin/curl"))
	e := &DatasourceEvent{Data: data, Datasource: ds, EventType: EventType("exepath-fallback-exec")}
	e.SetExePath("/app/server")
	require.Equal(t, "/usr/bin/curl", e.GetExePath())
}
