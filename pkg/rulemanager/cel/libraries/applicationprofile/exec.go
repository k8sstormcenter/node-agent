package applicationprofile

import (
	"slices"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/celparse"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	corev1 "k8s.io/api/core/v1"
)

func (l *apLibrary) wasExecuted(containerID, path ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	pathStr, ok := path.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(path)
	}

	// Check if preStop hook was triggered for this container
	if l.preStopCache != nil && l.preStopCache.WasPreStopTriggered(containerIDStr) {
		return types.Bool(true)
	}

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		// Return a special error that will NOT be cached, allowing retry when profile becomes available.
		// The caller should convert this to false after the cache layer.
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	if _, ok := cp.Execs.Values[pathStr]; ok {
		return types.Bool(true)
	}
	// Check Patterns (dynamic-segment entries).
	for _, execPath := range cp.Execs.Patterns {
		if dynamicpathdetector.CompareDynamic(execPath, pathStr) {
			return types.Bool(true)
		}
	}

	if l.isExecInPodSpec(containerID, path).Value().(bool) {
		return types.Bool(true)
	}

	return types.Bool(false)
}

func (l *apLibrary) wasExecutedWithArgs(containerID, path, args ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}

	pathStr, ok := path.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(path)
	}

	// Parse the runtime args list from CEL. Empty list is valid ("exec'd
	// with no args") and matches a profile entry whose Args is also empty
	// or absent (empty profile Args = "no argv constraint").
	runtimeArgs, err := celparse.ParseList[string](args)
	if err != nil {
		return types.NewErr("failed to parse args: %v", err)
	}

	// Check if preStop hook was triggered for this container
	if l.preStopCache != nil && l.preStopCache.WasPreStopTriggered(containerIDStr) {
		return types.Bool(true)
	}

	cp, _, perr := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if perr != nil {
		// Return a special error that will NOT be cached, allowing retry when profile becomes available.
		// The caller should convert this to false after the cache layer.
		return cache.NewProfileNotAvailableErr("%v", perr)
	}

	// Exact path match. ExecsByPath absent-vs-empty asymmetry: three states.
	//
	//  1. Path absent from cp.Execs.Values:
	//        Profile doesn't allow this exec at all → fall through to
	//        the pattern-match loop, then to false.
	//
	//  2. Path in Values, ABSENT from ExecsByPath (map lookup ok=false):
	//        Legacy / pre-args-projection profiles. Treated as
	//        "no argv constraint" — back-compat MATCH any args.
	//        This is the intentional fallback for profiles compiled
	//        against older storage versions that didn't populate the
	//        composite ExecsByPath surface.
	//
	//  3. Path in Values, PRESENT in ExecsByPath:
	//        Match each recorded argv vector with
	//        dynamicpathdetector.MatchExecArgs(profileArgs, true, runtimeArgs).
	//        argsRequired=true selects storage's STRICT anchored matcher:
	//        an empty recorded vector matches ONLY an empty runtime argv, so
	//        a recorder/synthetic "ran with no args" entry does NOT act as a
	//        wildcard and poison the multi-vector OR (the #805 production
	//        failure). The matcher handles WildcardIdentifier "*", bare
	//        DynamicIdentifier "⋯", and embedded-⋯ path tokens (the postgres
	//        versioned-binary case) — see storage's compare_exec_args.go.
	if _, ok := cp.Execs.Values[pathStr]; ok {
		if vectors, ok := cp.ExecsByPath[pathStr]; ok {
			for _, profileArgs := range vectors {
				if dynamicpathdetector.MatchExecArgs(profileArgs, true, runtimeArgs) {
					return types.Bool(true)
				}
			}
		} else {
			// State 2: ExecsByPath absent → back-compat "no argv constraint".
			return types.Bool(true)
		}
	}
	// Pattern path match: dynamic-segment paths in cp.Execs.Patterns.
	// Args matching mirrors the exact-path case — match against any
	// argv vector recorded for that pattern key.
	for _, execPath := range cp.Execs.Patterns {
		if dynamicpathdetector.CompareDynamic(execPath, pathStr) {
			if vectors, ok := cp.ExecsByPath[execPath]; ok {
				for _, profileArgs := range vectors {
					if dynamicpathdetector.MatchExecArgs(profileArgs, true, runtimeArgs) {
						return types.Bool(true)
					}
				}
			} else {
				return types.Bool(true)
			}
		}
	}

	// Pod-spec fallback. Unlike was_executed (which only needs the path to
	// appear in the pod spec), the args-aware query must compare the FULL
	// runtime argv against a declared command vector — the container's
	// startup command (Command ++ Args) or a lifecycle hook's Exec.Command.
	// Path-only matching here would let any exec of a declared binary with
	// unexpected arguments pass silently and suppress R0040.
	if l.isExecWithArgsInPodSpec(containerIDStr, runtimeArgs) {
		return types.Bool(true)
	}

	return types.Bool(false)
}

// isExecWithArgsInPodSpec reports whether the full runtime argv vector exactly
// matches a command vector DECLARED in the pod spec for this container: the
// container's startup command (Command ++ Args) or a lifecycle hook's
// Exec.Command. It is the args-aware counterpart of isExecInPodSpec, used by
// wasExecutedWithArgs so that an exec of a declared binary with unexpected
// arguments is not silently treated as allowed.
func (l *apLibrary) isExecWithArgsInPodSpec(containerIDStr string, runtimeArgs []string) bool {
	if l.objectCache == nil {
		return false
	}

	podSpec, err := profilehelper.GetPodSpec(l.objectCache, containerIDStr)
	if err != nil {
		logger.L().Error("isExecWithArgsInPodSpec - failed to get pod spec", helpers.String("error", err.Error()))
		return false
	}
	containerName := profilehelper.GetContainerName(l.objectCache, containerIDStr)
	if containerName == "" {
		logger.L().Error("isExecWithArgsInPodSpec - failed to get container name", helpers.String("containerID", containerIDStr))
		return false
	}

	// match compares the runtime argv against one declared command vector.
	match := func(declared []string) bool {
		return len(declared) > 0 && slices.Equal(declared, runtimeArgs)
	}
	// startupArgv is the argv the kubelet execs for the entrypoint: Command
	// followed by Args. Only meaningful when Command is explicitly set;
	// otherwise the image ENTRYPOINT is used, which is not visible from the
	// pod spec, so we cannot (and must not) claim a match.
	startupArgv := func(command, args []string) []string {
		if len(command) == 0 {
			return nil
		}
		argv := make([]string, 0, len(command)+len(args))
		argv = append(argv, command...)
		argv = append(argv, args...)
		return argv
	}
	// lifecycleMatch checks PreStop/PostStart exec hooks. It only reports a
	// match for the return decision; marking the PreStop trigger is handled by
	// was_executed (isExecInPodSpec), which the R0040 rule evaluates first.
	lifecycleMatch := func(lc *corev1.Lifecycle) bool {
		if lc == nil {
			return false
		}
		if lc.PreStop != nil && lc.PreStop.Exec != nil && match(lc.PreStop.Exec.Command) {
			return true
		}
		if lc.PostStart != nil && lc.PostStart.Exec != nil && match(lc.PostStart.Exec.Command) {
			return true
		}
		return false
	}

	for _, c := range podSpec.Containers {
		if c.Name == containerName {
			return match(startupArgv(c.Command, c.Args)) || lifecycleMatch(c.Lifecycle)
		}
	}
	for _, c := range podSpec.InitContainers {
		if c.Name == containerName {
			return match(startupArgv(c.Command, c.Args)) || lifecycleMatch(c.Lifecycle)
		}
	}
	for _, c := range podSpec.EphemeralContainers {
		if c.Name == containerName {
			return match(startupArgv(c.Command, c.Args)) || lifecycleMatch(c.Lifecycle)
		}
	}
	return false
}

func (l *apLibrary) isExecInPodSpec(containerID, path ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	pathStr, ok := path.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(path)
	}

	podSpec, err := profilehelper.GetPodSpec(l.objectCache, containerIDStr)
	if err != nil {
		logger.L().Error("isExecInPodSpec - failed to get pod spec", helpers.String("error", err.Error()))
		return types.Bool(false)
	}

	containerName := profilehelper.GetContainerName(l.objectCache, containerIDStr)
	if containerName == "" {
		logger.L().Error("isExecInPodSpec - failed to get container name", helpers.String("containerID", containerIDStr))
		return types.Bool(false)
	}

	if podSpec.Containers != nil {
		for _, container := range podSpec.Containers {
			if container.Name == containerName {
				if container.Command != nil {
					for _, exec := range container.Command {
						if exec == pathStr {
							return types.Bool(true)
						}
					}
				}
				if container.Lifecycle != nil {
					if container.Lifecycle.PreStop != nil && container.Lifecycle.PreStop.Exec != nil && container.Lifecycle.PreStop.Exec.Command != nil {
						for _, exec := range container.Lifecycle.PreStop.Exec.Command {
							if exec == pathStr {
								if l.preStopCache != nil {
									l.preStopCache.MarkPreStopTriggered(containerIDStr)
								}
								return types.Bool(true)
							}
						}
					}
					if container.Lifecycle.PostStart != nil && container.Lifecycle.PostStart.Exec != nil && container.Lifecycle.PostStart.Exec.Command != nil {
						for _, exec := range container.Lifecycle.PostStart.Exec.Command {
							if exec == pathStr {
								return types.Bool(true)
							}
						}
					}
				}
				return types.Bool(false)
			}
		}
	}

	if podSpec.InitContainers != nil {
		for _, container := range podSpec.InitContainers {
			if container.Name == containerName {
				if container.Command != nil {
					for _, exec := range container.Command {
						if exec == pathStr {
							return types.Bool(true)
						}
					}
				}
				if container.Lifecycle != nil {
					if container.Lifecycle.PreStop != nil && container.Lifecycle.PreStop.Exec != nil && container.Lifecycle.PreStop.Exec.Command != nil {
						for _, exec := range container.Lifecycle.PreStop.Exec.Command {
							if exec == pathStr {
								if l.preStopCache != nil {
									l.preStopCache.MarkPreStopTriggered(containerIDStr)
								}
								return types.Bool(true)
							}
						}
					}
					if container.Lifecycle.PostStart != nil && container.Lifecycle.PostStart.Exec != nil && container.Lifecycle.PostStart.Exec.Command != nil {
						for _, exec := range container.Lifecycle.PostStart.Exec.Command {
							if exec == pathStr {
								return types.Bool(true)
							}
						}
					}
				}
				return types.Bool(false)
			}
		}
	}

	if podSpec.EphemeralContainers != nil {
		for _, container := range podSpec.EphemeralContainers {
			if container.Name == containerName {
				if container.Command != nil {
					for _, exec := range container.Command {
						if exec == pathStr {
							return types.Bool(true)
						}
					}
				}
				if container.Lifecycle != nil {
					if container.Lifecycle.PreStop != nil && container.Lifecycle.PreStop.Exec != nil && container.Lifecycle.PreStop.Exec.Command != nil {
						for _, exec := range container.Lifecycle.PreStop.Exec.Command {
							if exec == pathStr {
								if l.preStopCache != nil {
									l.preStopCache.MarkPreStopTriggered(containerIDStr)
								}
								return types.Bool(true)
							}
						}
					}
					if container.Lifecycle.PostStart != nil && container.Lifecycle.PostStart.Exec != nil && container.Lifecycle.PostStart.Exec.Command != nil {
						for _, exec := range container.Lifecycle.PostStart.Exec.Command {
							if exec == pathStr {
								return types.Bool(true)
							}
						}
					}
				}
				return types.Bool(false)
			}
		}
	}

	return types.Bool(false)
}
