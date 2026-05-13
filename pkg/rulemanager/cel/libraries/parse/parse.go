package parse

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/celparse"
)

func (l *parseLibrary) getExecPath(args ref.Val, comm ref.Val) ref.Val {
	argsList, err := celparse.ParseList[string](args)
	if err != nil {
		return types.NewErr("failed to parse args: %v", err)
	}

	commStr, ok := comm.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(comm)
	}

	// 2-arg overload — back-compat. Resolves args[0] → comm.
	// Callers that have event.exepath SHOULD use the 3-arg overload below
	// to stay symmetric with the recording side's resolveExecPath in
	// pkg/containerprofilemanager/v1/event_reporting.go.
	if len(argsList) > 0 {
		if argsList[0] != "" {
			return types.String(argsList[0])
		}
	}
	return types.String(commStr)
}

// getExecPathWithExePath is the 3-arg overload that mirrors the recording
// side's resolveExecPath: prefer the kernel-authoritative exepath, then
// argv[0], then comm. Used by rule expressions that have event.exepath
// available — keeps the rule-side resolved path identical to what was
// recorded into the ApplicationProfile, so ap.was_executed lookups land.
//
// This closes the spurious-R0001 gap: previously the profile recorded
// "/bin/sh" (kernel exepath) but the rule queried "sh" (argv[0]), so
// shell invocations always alerted as "Unexpected process launched"
// even after the autotuner added "sh" to AllowedProcesses.
func (l *parseLibrary) getExecPathWithExePath(args ref.Val, comm ref.Val, exepath ref.Val) ref.Val {
	exepathStr, ok := exepath.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(exepath)
	}
	if exepathStr != "" {
		return types.String(exepathStr)
	}
	return l.getExecPath(args, comm)
}
