package agent_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/evaluation"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
)

var (
	testCtx      = context.Background()
	testLogger   = slog.New(slog.NewTextHandler(io.Discard, nil))
	testIdentity = jobcontext.GitHubJobIdentity(
		"github.com",
		"example/project",
		"12345",
		"build",
		"1",
		"runner-1",
	)
	testMetadata = jobcontext.JobMetadata{}
)

const testEventChannelSize = 4096

func evaluateTestRules(ctx context.Context, eval *evaluation.EvaluationState, event jobevent.EventRecord, host, project *jobscope.JobScopeState, logger *slog.Logger) {
	activation := celengine.NewEventActivation(celengine.CELInputEvent{})
	evaluation.EvaluateEvent(ctx, eval, event, testIdentity, testMetadata, "machine", host, project, logger, activation)
}

// scopeResolvedRules returns a pointer into a scope's resolved rule storage,
// or nil when the scope itself is nil. Tests use it to feed a host or project
// scope's ResolvedRules into evaluation.NewEvaluationState the same way job.go
// does in production.
func scopeResolvedRules(s *jobscope.JobScopeState) *rule.ResolvedRules {
	if s == nil {
		return nil
	}
	return &s.ResolvedRules
}

func detectHits(snapshot observations.StateSnapshot) observations.HitSnapshot {
	return hitsWithAction(snapshot, rule.RuleActionDetect)
}

func collectHits(snapshot observations.StateSnapshot) observations.HitSnapshot {
	return hitsWithAction(snapshot, rule.RuleActionCollect)
}

func preventHits(snapshot observations.StateSnapshot) observations.HitSnapshot {
	return hitsWithAction(snapshot, rule.RuleActionTerminate)
}

func hitsWithAction(snapshot observations.StateSnapshot, action rule.RuleAction) observations.HitSnapshot {
	return slices.DeleteFunc(slices.Clone(snapshot.Hits), func(hit observations.HitSummary) bool {
		return hit.Action != string(action)
	})
}

func newTestJob(identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, eventChannelSize int) (*job.Job, chan jobevent.EventRecord) {
	eventCh := make(chan jobevent.EventRecord, eventChannelSize)
	return job.NewJob(testLogger, identity, metadata, "machine", eventCh), eventCh
}

func sendTestEvent(t *testing.T, eventCh chan<- jobevent.EventRecord, event jobevent.EventRecord) {
	t.Helper()
	eventCh <- event
}

func finishTestJob(j *job.Job, eventCh chan jobevent.EventRecord) {
	done := j.Done()
	j.MarkClosing()
	close(eventCh)
	<-done
}

func waitForJob(t *testing.T, reason string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		<-ticker.C
	}
	t.Fatalf("timeout waiting: %s", reason)
}

func testDispatchEvent(execPath, host string, port int64) jobevent.EventRecord {
	return jobevent.EventRecord{
		EventType: jobevent.NetworkConnect,
		Timestamp: time.Date(2026, 4, 16, 1, 2, 3, 4, time.UTC),
		Payload: map[string]any{
			"remote_ip":   host,
			"remote_port": port,
			"protocol":    "tcp",
		},
		Process: jobevent.ProcessSummary{
			PID:      int32(os.Getpid()),
			ExecPath: execPath,
		},
		Tags: map[string]string{},
	}
}
