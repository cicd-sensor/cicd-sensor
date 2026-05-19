package celengine

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestCompiledProgramEvalActivationUsesStaticParent(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	lists := rule.NormalizePredefinedLists(map[string][]string{
		"shell_binaries": {"/bash", "/sh"},
	})
	prog, err := env.Compile("rule-1", jobevent.ProcessExec, `list.shell_binaries.exists(b, process.exec_path.endsWith(b))`, lists)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	staticActivation, err := NewListActivation(lists)
	if err != nil {
		t.Fatalf("new list activation: %v", err)
	}

	matched, err := prog.EvalActivation(NewEventActivation(CELInputEvent{
		Process: CELProcess{ExecPath: "/bin/bash"},
	}).WithParent(staticActivation))
	if err != nil {
		t.Fatalf("eval activation: %v", err)
	}
	if !matched {
		t.Fatal("expected match")
	}
}

func TestCompiledProgramEvalActivationRejectsNonBoolResult(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	prog, err := env.Compile("rule-1", jobevent.ProcessExec, `"not-a-bool"`, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	if _, err := prog.EvalActivation(NewEventActivation(CELInputEvent{})); err == nil {
		t.Fatal("expected non-bool evaluation error")
	}
}

// Reset must drop cached values so the reused activation does not retain
// previous-event strings (path, domain, remote_ip, ...) past the event
// boundary. Without the clear, sensitive data would survive in the
// worker's activation until the next Reset overwrites the slot.
func TestEventActivationResetClearsCache(t *testing.T) {
	t.Parallel()

	act := NewEventActivation(CELInputEvent{
		Domain: "example.com",
		Path:   "/etc/passwd",
	})
	if _, ok := act.ResolveName("domain"); !ok {
		t.Fatal("domain should resolve")
	}
	if _, ok := act.ResolveName("path"); !ok {
		t.Fatal("path should resolve")
	}
	if len(act.cache) == 0 {
		t.Fatal("expected cached entries after ResolveName")
	}

	act.Reset(CELInputEvent{})
	if len(act.cache) != 0 {
		t.Fatalf("cache should be empty after Reset; got %d entries", len(act.cache))
	}
}
