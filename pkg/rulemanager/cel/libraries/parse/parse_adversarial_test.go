package parse

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/node-agent/pkg/config"
)

// Black-box adversarial probes against parse.get_exec_path, in the style used
// to find the #805 bugs: craft an input that targets the security contract and
// assert the actual output through the real CEL boundary.
//
// Contract under attack: get_exec_path must resolve to the kernel-authoritative
// exepath, NOT the user-controllable argv[0]. execve(2) only says argv[0]
// SHOULD be the filename by convention — it is not kernel-verified — so trusting
// an absolute argv[0] reopens process masquerading.
func TestGetExecPath_Adversarial_Argv0Spoofing(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.AnyType),
		Parse(config.Config{}),
	)
	if err != nil {
		t.Fatalf("env: %v", err)
	}

	cases := []struct {
		name string
		expr string
		want string
	}{
		{
			// The canonical repro: `exec -a /bin/sh sleep 2` — argv[0] lies as
			// /bin/sh while the real binary is /usr/bin/sleep. exepath must win.
			name: "exec -a spoof: argv0=/bin/sh but exepath=/usr/bin/sleep",
			expr: `parse.get_exec_path(['/bin/sh', '2'], 'sleep', '/usr/bin/sleep')`,
			want: "/usr/bin/sleep",
		},
		{
			// argv[0] forged to an APPROVED absolute path to slip past a
			// profile; the real exepath is the attacker binary and must win.
			name: "argv0 forged as approved /usr/bin/curl, real exepath /tmp/evil",
			expr: `parse.get_exec_path(['/usr/bin/curl', '-s', 'x'], 'curl', '/tmp/evil')`,
			want: "/tmp/evil",
		},
		{
			// Legitimate empty-exepath case (fexecve / execveat AT_EMPTY_PATH):
			// only here may argv[0] be used.
			name: "exepath empty -> argv0 used",
			expr: `parse.get_exec_path(['/bin/sh', '-c', 'x'], 'sh', '')`,
			want: "/bin/sh",
		},
		{
			name: "exepath empty + argv0 empty -> comm fallback",
			expr: `parse.get_exec_path(['', '-c'], 'sh', '')`,
			want: "sh",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ast, iss := env.Compile(c.expr)
			if iss != nil && iss.Err() != nil {
				t.Fatalf("compile: %v", iss.Err())
			}
			prg, err := env.Program(ast)
			if err != nil {
				t.Fatalf("program: %v", err)
			}
			out, _, err := prg.Eval(map[string]any{"event": map[string]any{}})
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if got := out.Value().(string); got != c.want {
				t.Errorf("%s = %q, want %q (argv[0] must never override exepath)", c.expr, got, c.want)
			}
		})
	}
}
