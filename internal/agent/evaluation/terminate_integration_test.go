//go:build integration && !windows

package evaluation

import (
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestEvaluateEvent_TerminateKillsEventProcessIntegration(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	hostScope := jobscope.NewHost()
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{{
			RuleID:    "terminate",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionTerminate,
		}},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := NewEvaluationState(scopeResolvedRules(hostScope), nil)
	event := testDispatchEvent("/usr/bin/sleep", "example.com", 443)
	event.Process.PID = int32(cmd.Process.Pid)

	EvaluateEvent(testCtx, eval, event, testEvalIdentity, jobcontext.JobMetadata{}, "machine", hostScope, nil, testLogger, testActivation())

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	select {
	case err := <-waitCh:
		if err == nil {
			t.Fatal("sleep exited cleanly, want SIGKILL")
		}
		status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
		if !ok {
			t.Fatalf("process state sys: got %T, want syscall.WaitStatus", cmd.ProcessState.Sys())
		}
		if !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatalf("sleep exit status: got %v, want SIGKILL", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sleep was not killed by terminate rule")
	}
}
