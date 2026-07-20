//go:build integration && !windows

package evaluation

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

const terminateProcessSameGroupHelperEnv = "CICD_SENSOR_TERMINATE_SAME_GROUP_HELPER"

func TestEvaluateEvent_TerminateKillsEventProcessIntegration(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	// Real CI runners launch each step in its own pgid (setsid). Mirror that
	// here so SIGINT-to-pgid in terminateProcess hits only the test target,
	// not the test process itself.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

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

func TestTerminateProcess_SkipsAgentProcessGroupIntegration(t *testing.T) {
	if os.Getenv(terminateProcessSameGroupHelperEnv) != "1" {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTerminateProcess_SkipsAgentProcessGroupIntegration$")
		cmd.Env = append(os.Environ(), terminateProcessSameGroupHelperEnv+"=1")
		// The helper gets its own process group so a regressed guard can only
		// signal the helper, never the parent go test process or its shell.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated terminate helper failed: %v\n%s", err, output)
		}
		return
	}

	var selfLogs bytes.Buffer
	selfLogger := slog.New(slog.NewTextHandler(&selfLogs, nil))
	selfEvent := testDispatchEvent("/usr/bin/test", "example.com", 443)
	selfEvent.Process.PID = int32(os.Getpid())
	terminateProcess(t.Context(), selfEvent, selfLogger)
	if got := selfLogs.String(); !strings.Contains(got, `msg=terminate_process_skipped reason=self_pid`) {
		t.Fatalf("terminate log does not report self pid skip: %s", got)
	}

	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	childPGID, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("get sleep process group: %v", err)
	}
	if helperPGID := syscall.Getpgrp(); childPGID != helperPGID {
		t.Fatalf("sleep process group: got %d, want helper group %d", childPGID, helperPGID)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	event := testDispatchEvent("/usr/bin/sleep", "example.com", 443)
	event.Process.PID = int32(cmd.Process.Pid)

	terminateProcess(t.Context(), event, logger)

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
		t.Fatal("sleep was not killed by terminateProcess")
	}

	if got := logs.String(); !strings.Contains(got, `msg=terminate_process_group_sigint_skipped reason=agent_process_group`) {
		t.Fatalf("terminate log does not report process-group skip: %s", got)
	}
}
