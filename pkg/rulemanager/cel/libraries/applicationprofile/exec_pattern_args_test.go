package applicationprofile

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
)

// TestExecWithArgs_PatternPathArgs covers the dynamic-segment exec-path arm of
// wasExecutedWithArgs (exec.go pattern loop): a profile exec whose Path carries
// a "⋯" segment is projected into Execs.Patterns, and a runtime path matching
// it via CompareDynamic must still have its argv vector checked with
// MatchExecArgs. This arm is exercised by NEITHER the existing unit tests (which
// use concrete paths -> Values) NOR component Test_32 (busybox concrete paths),
// so it was a coverage hole on the R0040 contract.
func TestExecWithArgs_PatternPathArgs(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: "test-container"}},
		},
	})

	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "test-container",
		Execs: []v1beta1.ExecCalls{
			// Dynamic-segment Path -> projected into Execs.Patterns, keyed
			// in ExecsByPath under the pattern string. argv vector uses a
			// trailing "*".
			{Path: "/opt/" + dynamicpathdetector.DynamicIdentifier + "/bin/tool", Args: []string{"run", dynamicpathdetector.WildcardIdentifier}},
		},
	})
	objCache.SetApplicationProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("args", cel.ListType(cel.StringType)),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}
	prg, err := compileWasExecutedWithArgs(env)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	cases := []struct {
		name string
		path string
		args []string
		want bool // true = matches profile (R0040 silent)
	}{
		{"pattern path + matching args", "/opt/v2/bin/tool", []string{"run", "--flag", "x"}, true},
		{"pattern path + mismatching args", "/opt/v2/bin/tool", []string{"delete", "x"}, false},
		{"pattern path no version match", "/opt/bin/tool", []string{"run", "x"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _, err := prg.Eval(map[string]any{
				"containerID": "test-container-id",
				"path":        c.path,
				"args":        c.args,
			})
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			got := out.Value().(bool)
			if got != c.want {
				t.Errorf("was_executed_with_args(%q, %v) = %v, want %v", c.path, c.args, got, c.want)
			}
		})
	}
}

func compileWasExecutedWithArgs(env *cel.Env) (cel.Program, error) {
	ast, iss := env.Compile(`ap.was_executed_with_args(containerID, path, args)`)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	return env.Program(ast)
}
