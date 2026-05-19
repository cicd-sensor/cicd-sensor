package celengine

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

func TestStringLiteralNormalizationPreservesOriginalSource(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	prog, err := env.Compile("rule-1", jobevent.ProcessExec, `process.exec_path.endsWith("/BASH")`, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	if prog.Source != `process.exec_path.endsWith("/BASH")` {
		t.Fatalf("source: got %q", prog.Source)
	}
	matched, err := prog.EvalActivation(NewEventActivation(CELInputEvent{
		Process: CELProcess{ExecPath: "/bin/bash"},
	}))
	if err != nil {
		t.Fatalf("eval activation: %v", err)
	}
	if !matched {
		t.Fatal("expected normalized string literal to match normalized input")
	}
}
