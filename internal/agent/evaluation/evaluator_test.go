package evaluation

import (
	"context"
	"sync"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
	"google.golang.org/protobuf/encoding/protojson"
)

// testActivation is a fresh per-call helper so individual tests don't
// have to thread one through. Production reuses a single activation
// across the worker's event loop.
func testActivation() *celengine.EventActivation {
	return celengine.NewEventActivation(celengine.CELInputEvent{})
}

var testEvalIdentity = jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")

type recordingEvaluationBatches struct {
	mu      sync.Mutex
	records map[managerv1.LogType][][]byte
}

func (r *recordingEvaluationBatches) sendBatch(_ context.Context, batch managerclient.LogBatch) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.records == nil {
		r.records = make(map[managerv1.LogType][][]byte)
	}
	for _, record := range batch.Records {
		if len(record) == 0 {
			continue
		}
		r.records[batch.Type] = append(r.records[batch.Type], append([]byte(nil), record...))
	}
	return nil
}

func (r *recordingEvaluationBatches) detectionEntries(t *testing.T) []*logv1.DetectionLogEntry {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()

	records := r.records[managerv1.LogType_LOG_TYPE_DETECTION]
	out := make([]*logv1.DetectionLogEntry, 0, len(records))
	for _, record := range records {
		entry := &logv1.DetectionLogEntry{}
		if err := protojson.Unmarshal(record, entry); err != nil {
			t.Fatalf("unmarshal detection log record: %v", err)
		}
		out = append(out, entry)
	}
	return out
}

func (r *recordingEvaluationBatches) runtimeEventEntries(t *testing.T) []*logv1.RuntimeEventLogEntry {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()

	records := r.records[managerv1.LogType_LOG_TYPE_RUNTIME_EVENT]
	out := make([]*logv1.RuntimeEventLogEntry, 0, len(records))
	for _, record := range records {
		entry := &logv1.RuntimeEventLogEntry{}
		if err := protojson.Unmarshal(record, entry); err != nil {
			t.Fatalf("unmarshal runtime event log record: %v", err)
		}
		out = append(out, entry)
	}
	return out
}

func TestEvaluateEvent_RecordRegularRuleHitForFedScopes(t *testing.T) {
	t.Parallel()

	rules := []rule.Rule{{
		RuleID:    "detect_curl",
		EventType: jobevent.NetworkConnect,
		Condition: `remote_ip == "example.com"`,
		Action:    rule.RuleActionDetect,
	}}
	host := newCorrelationScope("shared-set", rules)
	project := newProjectScopeWithRules("shared-set", rules)
	eval := NewEvaluationState(scopeResolvedRules(host), scopeResolvedRules(project))

	EvaluateEvent(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), testEvalIdentity, jobcontext.JobMetadata{}, "machine", host, project, testLogger, testActivation())

	identity := rule.RuleIdentity{RulesetID: "shared-set", RuleID: "detect_curl"}
	if got := host.CorrelationHitCountFor(identity); got != 1 {
		t.Fatalf("host hit count: got %d, want 1", got)
	}
	if got := project.CorrelationHitCountFor(identity); got != 1 {
		t.Fatalf("project hit count: got %d, want 1", got)
	}
}

func TestEvaluateEvent_GeneratedEventIDIsSharedByDetectionAndRuntimeEventLogs(t *testing.T) {
	t.Parallel()

	recorder := &recordingEvaluationBatches{}
	host := newCorrelationScope("host-set", []rule.Rule{{
		RuleID:    "detect_curl",
		EventType: jobevent.NetworkConnect,
		Condition: `remote_ip == "example.com"`,
		Action:    rule.RuleActionDetect,
	}})
	host.ManagerJobLogsForTesting().AttachDetectionRecorderForTesting(testEvalIdentity, host.Type, recorder.sendBatch)
	host.ManagerJobLogsForTesting().AttachRuntimeEventRecorderForTesting(testEvalIdentity, host.Type, recorder.sendBatch)
	eval := NewEvaluationState(scopeResolvedRules(host), scopeResolvedRules(nil))

	EvaluateEvent(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), testEvalIdentity, jobcontext.JobMetadata{}, "machine", host, nil, testLogger, testActivation())
	if err := host.FinalizeStreamingLogs(testCtx); err != nil {
		t.Fatalf("finalize logs: %v", err)
	}

	detections := recorder.detectionEntries(t)
	if len(detections) != 1 {
		t.Fatalf("detection entries: got %d, want 1", len(detections))
	}
	events := recorder.runtimeEventEntries(t)
	if len(events) != 1 {
		t.Fatalf("runtime event entries: got %d, want 1", len(events))
	}
	detectionEventID := detections[0].GetEvent().GetId()
	if detectionEventID == "" {
		t.Fatal("detection event id is empty")
	}
	if got := events[0].GetEvent().GetId(); got != detectionEventID {
		t.Fatalf("runtime event event id: got %q, want %q", got, detectionEventID)
	}
}

func TestEvaluateEvent_CorrelationFiresOncePerScope(t *testing.T) {
	t.Parallel()

	host := newCorrelationScope("host-set", []rule.Rule{
		{
			RuleID:    "single",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		},
		{
			RuleID:    "corr",
			Type:      "correlation",
			Condition: `rule["single"].total_count >= 1`,
			Action:    rule.RuleActionTerminate,
		},
	})
	eval := NewEvaluationState(scopeResolvedRules(host), scopeResolvedRules(nil))

	EvaluateEvent(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), testEvalIdentity, jobcontext.JobMetadata{}, "machine", host, nil, testLogger, testActivation())
	EvaluateEvent(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), testEvalIdentity, jobcontext.JobMetadata{}, "machine", host, nil, testLogger, testActivation())

	baseIdentity := rule.RuleIdentity{RulesetID: "host-set", RuleID: "single"}
	if got := host.CorrelationHitCountFor(baseIdentity); got != 2 {
		t.Fatalf("base hit count: got %d, want 2", got)
	}
	correlationIdentity := rule.RuleIdentity{RulesetID: "host-set", RuleID: "corr"}
	if got := host.CorrelationHitCountFor(correlationIdentity); got != 1 {
		t.Fatalf("correlation hit count: got %d, want 1", got)
	}
}

func TestEvaluateEvent_NilInputsAreNoOp(t *testing.T) {
	t.Parallel()

	EvaluateEvent(testCtx, nil, testDispatchEvent("/usr/bin/curl", "example.com", 443), testEvalIdentity, jobcontext.JobMetadata{}, "machine", nil, nil, testLogger, testActivation())

	eval := &EvaluationState{}
	EvaluateEvent(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), testEvalIdentity, jobcontext.JobMetadata{}, "machine", nil, nil, testLogger, testActivation())
}
