package celengine

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestEnvCompileRejectsDisallowedConstructs(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	tests := []struct {
		name      string
		eventType jobevent.Type
		source    string
	}{
		{name: "matches", eventType: jobevent.ProcessExec, source: `process.exec_path.matches("/bin/bash")`},
		{name: "add", eventType: jobevent.ProcessExec, source: `"a" + "b" == "ab"`},
		{name: "subtract", eventType: jobevent.ProcessExec, source: `1 - 1 == 0`},
		{name: "multiply", eventType: jobevent.ProcessExec, source: `2 * 3 == 6`},
		{name: "divide", eventType: jobevent.ProcessExec, source: `8 / 2 == 4`},
		{name: "modulo", eventType: jobevent.ProcessExec, source: `7 % 2 == 1`},
		{name: "size", eventType: jobevent.ProcessExec, source: `size(process.argv) > 0`},
		{name: "index", eventType: jobevent.ProcessExec, source: `process.argv[0] == "bash"`},
		{name: "has_macro", eventType: jobevent.NetworkConnect, source: `has(remote_ip)`},
		{name: "all_macro", eventType: jobevent.ProcessExec, source: `process.argv.all(arg, arg != "")`},
		{name: "filter_macro", eventType: jobevent.ProcessExec, source: `process.argv.filter(arg, arg.contains("x")) == process.argv`},
		{name: "map_macro", eventType: jobevent.ProcessExec, source: `process.argv.map(arg, arg) == process.argv`},
		{name: "unknown_file_variable", eventType: jobevent.FileOpen, source: `remote_ip == "example.com"`},
		{name: "invalid_cidr", eventType: jobevent.NetworkConnect, source: `inIpRange(remote_ip, "not-a-cidr")`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := env.Compile("rule-1", tt.eventType, tt.source, nil); err == nil {
				t.Fatal("expected compile error")
			}
		})
	}
}

func TestEnvCompileRejectsUndefinedPredefinedList(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	_, err = env.Compile("rule-1", jobevent.ProcessExec, `list.missing.exists(v, process.exec_path.endsWith(v))`, map[string][]string{
		"present": {"/bash"},
	})
	if err == nil {
		t.Fatal("expected missing list compile error")
	}
}

func TestEnvCompileAllowsNoListReferencesWithEmptyLists(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	if _, err := env.Compile("rule-1", jobevent.ProcessExec, `process.exec_path.endsWith("/bash")`, nil); err != nil {
		t.Fatalf("compile without lists: %v", err)
	}
}

func TestEnvCompileRejectsListReferencesWhenListsAreEmpty(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	tests := []struct {
		name  string
		lists rule.PredefinedLists
	}{
		{name: "nil_lists", lists: nil},
		{name: "empty_lists", lists: rule.PredefinedLists{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := env.Compile("rule-1", jobevent.ProcessExec, `list.shells.exists(v, process.exec_path.endsWith(v))`, tt.lists)
			if err == nil {
				t.Fatal("expected undefined list compile error")
			}
		})
	}
}
