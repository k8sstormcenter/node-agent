package containerprofile

import (
	"slices"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
)

func processAdmitted(processes []string, exe string) bool {
	if len(processes) == 0 {
		return true
	}
	return exe != "" && slices.ContainsFunc(processes, func(p string) bool {
		return p == exe || dynamicpathdetector.CompareDynamic(p, exe)
	})
}

func openEntryAdmits(e objectcache.OpenEntry, path, exe string) bool {
	return (e.Path == path || dynamicpathdetector.CompareDynamic(e.Path, path)) && processAdmitted(e.Processes, exe)
}

func (l *containerProfileLibrary) openEntries(containerID ref.Val) ([]objectcache.OpenEntry, bool, ref.Val) {
	if l.objectCache == nil {
		return nil, false, types.NewErr("objectCache is nil")
	}
	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return nil, false, types.MaybeNoSuchOverloadErr(containerID)
	}
	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return nil, false, cache.NewProfileNotAvailableErr("%v", err)
	}
	return cp.OpenEntries, cp.OpenEntries != nil, nil
}

func (l *containerProfileLibrary) wasPathOpenedBy(containerID, path, exe ref.Val) ref.Val {
	pathStr, ok := path.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(path)
	}
	exeStr, ok := exe.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(exe)
	}
	entries, scoped, errVal := l.openEntries(containerID)
	if errVal != nil {
		return errVal
	}
	if !scoped {
		return l.wasPathOpened(containerID, path)
	}
	return types.Bool(pathStr != "" && slices.ContainsFunc(entries, func(e objectcache.OpenEntry) bool { return openEntryAdmits(e, pathStr, exeStr) }))
}

func (l *containerProfileLibrary) wasPathOpenedWithSuffixBy(containerID, suffix, exe ref.Val) ref.Val {
	suffixStr, ok := suffix.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(suffix)
	}
	exeStr, ok := exe.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(exe)
	}
	entries, scoped, errVal := l.openEntries(containerID)
	if errVal != nil {
		return errVal
	}
	if !scoped {
		return l.wasPathOpenedWithSuffix(containerID, suffix)
	}
	return types.Bool(slices.ContainsFunc(entries, func(e objectcache.OpenEntry) bool {
		return strings.HasSuffix(e.Path, suffixStr) && processAdmitted(e.Processes, exeStr)
	}))
}
