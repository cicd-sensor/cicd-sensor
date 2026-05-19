package jobscope_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/joblogs"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	testJobScopeLogger = slog.New(slog.NewTextHandler(io.Discard, nil))
	testJobIdentity    = jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	testJobMetadata    = jobcontext.JobMetadata{CommitSHA: "abc123", Branch: "main"}
	testEventTime      = time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
)

type recordingJobScopeBatches struct {
	mu      sync.Mutex
	records map[managerv1.LogKind][][]byte
}

func (r *recordingJobScopeBatches) sendBatch(_ context.Context, batch managerclient.LogBatch) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.records == nil {
		r.records = make(map[managerv1.LogKind][][]byte)
	}
	for _, record := range batch.Records {
		if len(record) == 0 {
			continue
		}
		r.records[batch.Kind] = append(r.records[batch.Kind], append([]byte(nil), record...))
	}
	return nil
}

func (r *recordingJobScopeBatches) detectionEntries(t *testing.T) []logv1.JobDetectionLogEntry {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()

	records := r.records[managerv1.LogKind_LOG_KIND_JOB_DETECTION]
	out := make([]logv1.JobDetectionLogEntry, 0, len(records))
	for _, record := range records {
		var entry logv1.JobDetectionLogEntry
		if err := protojson.Unmarshal(record, &entry); err != nil {
			t.Fatalf("unmarshal detection log record: %v", err)
		}
		out = append(out, entry)
	}
	return out
}

func (r *recordingJobScopeBatches) runtimeTelemetryEntries(t *testing.T) []logv1.JobRuntimeTelemetryLogEntry {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()

	records := r.records[managerv1.LogKind_LOG_KIND_JOB_RUNTIME_TELEMETRY]
	out := make([]logv1.JobRuntimeTelemetryLogEntry, 0, len(records))
	for _, record := range records {
		var entry logv1.JobRuntimeTelemetryLogEntry
		if err := protojson.Unmarshal(record, &entry); err != nil {
			t.Fatalf("unmarshal runtime telemetry log record: %v", err)
		}
		out = append(out, entry)
	}
	return out
}

func (r *recordingJobScopeBatches) jobResultEntries(t *testing.T) []logv1.JobResultLogEntry {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()

	records := r.records[managerv1.LogKind_LOG_KIND_JOB_RESULT]
	out := make([]logv1.JobResultLogEntry, 0, len(records))
	for _, record := range records {
		var entry logv1.JobResultLogEntry
		if err := protojson.Unmarshal(record, &entry); err != nil {
			t.Fatalf("unmarshal job result log record: %v", err)
		}
		out = append(out, entry)
	}
	return out
}

func TestJobScopeStateWriteDetectionLogForHit_CollectDoesNotEmitDetectionLog(t *testing.T) {
	t.Parallel()

	recorder := &recordingJobScopeBatches{}
	scope := jobscope.NewHost()
	scope.ManagerJobLogsForTesting().AttachDetectionRecorderForTesting(testJobIdentity, scope.Kind, recorder.sendBatch)
	hit := observations.HitEntry{
		Identity:  rule.RuleIdentity{RulesetID: "set", RuleID: "collect_token"},
		Action:    string(rule.RuleActionCollect),
		MaxAlerts: 1,
	}
	event := testJobScopeProcessEvent("event-collect")

	scope.RecordHit(hit, event)
	scope.WriteDetectionLogForHit(context.Background(), testJobIdentity, testJobMetadata, "machine", hit, event, testJobScopeLogger)
	if err := scope.FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize logs: %v", err)
	}

	if got := len(recorder.detectionEntries(t)); got != 0 {
		t.Fatalf("detection entries: got %d, want 0", got)
	}
	if got := scope.CorrelationHitCountFor(hit.Identity); got != 1 {
		t.Fatalf("recorded hit count: got %d, want 1", got)
	}
}

func TestJobScopeStateWriteDetectionLogForHit_MaxAlertsCapsDetectionLog(t *testing.T) {
	t.Parallel()

	recorder := &recordingJobScopeBatches{}
	scope := jobscope.NewHost()
	scope.ConfigRevision = "config-sha"
	scope.ResolvedRules = rule.ResolvedRules{Rules: []rule.ResolvedRule{{
		RulesetID:       "set",
		RulesetRevision: "rules-sha",
		Rule: rule.Rule{
			RuleID:      "detect_token",
			EventKind:   jobevent.ProcessExec,
			RuleName:    "Detect token",
			Description: "flags token-like process arguments",
			Action:      rule.RuleActionDetect,
		},
	}}}
	scope.ManagerJobLogsForTesting().AttachDetectionRecorderForTesting(testJobIdentity, scope.Kind, recorder.sendBatch)
	hit := observations.HitEntry{
		Identity:  rule.RuleIdentity{RulesetID: "set", RuleID: "detect_token"},
		Action:    string(rule.RuleActionDetect),
		MaxAlerts: 2,
	}

	for i := range 3 {
		event := testJobScopeProcessEvent("event-detect-" + string(rune('1'+i)))
		scope.RecordHit(hit, event)
		scope.WriteDetectionLogForHit(context.Background(), testJobIdentity, testJobMetadata, "machine", hit, event, testJobScopeLogger)
	}
	if err := scope.FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize logs: %v", err)
	}

	entries := recorder.detectionEntries(t)
	if len(entries) != 2 {
		t.Fatalf("detection entries: got %d, want 2", len(entries))
	}
	if got, want := entries[0].RuleAlertTruncation, ""; got != want {
		t.Fatalf("first truncation: got %q, want %q", got, want)
	}
	if got, want := entries[1].RuleAlertTruncation, resultdoc.AlertTruncationMaxAlertsReached; got != want {
		t.Fatalf("second truncation: got %q, want %q", got, want)
	}
	if got, want := entries[0].RuleName, "Detect token"; got != want {
		t.Fatalf("rule name: got %q, want %q", got, want)
	}
	if got, want := entries[0].Job.GetRunnerKind(), "machine"; got != want {
		t.Fatalf("runner kind: got %q, want %q", got, want)
	}
	if got, want := entries[0].RuleDescription, "flags token-like process arguments"; got != want {
		t.Fatalf("rule description: got %q, want %q", got, want)
	}
	if got, want := entries[0].RulesetRevision, "rules-sha"; got != want {
		t.Fatalf("ruleset revision: got %q, want %q", got, want)
	}
}

func TestJobScopeStateWriteRuntimeTelemetryLog_EmitsEvent(t *testing.T) {
	t.Parallel()

	recorder := &recordingJobScopeBatches{}
	scope := jobscope.NewProject()
	scope.ManagerJobLogsForTesting().AttachRuntimeTelemetryRecorderForTesting(testJobIdentity, scope.Kind, recorder.sendBatch)
	event := testJobScopeNetworkEvent("event-runtime", "203.0.113.10")

	scope.WriteRuntimeTelemetryLog(context.Background(), testJobIdentity, testJobMetadata, "machine", event, testJobScopeLogger)
	if err := scope.FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize logs: %v", err)
	}

	entries := recorder.runtimeTelemetryEntries(t)
	if len(entries) != 1 {
		t.Fatalf("runtime telemetry entries: got %d, want 1", len(entries))
	}
	if got, want := entries[0].Scope, string(jobcontext.ScopeKindProject); got != want {
		t.Fatalf("scope: got %q, want %q", got, want)
	}
	if got, want := entries[0].Job.GetRunnerKind(), "machine"; got != want {
		t.Fatalf("runner kind: got %q, want %q", got, want)
	}
	if got, want := entries[0].Event.GetId(), event.ID; got != want {
		t.Fatalf("event id: got %q, want %q", got, want)
	}
	if got, want := entries[0].Event.GetNetworkConnect().GetRemoteIp(), "203.0.113.10"; got != want {
		t.Fatalf("remote ip: got %q, want %q", got, want)
	}
}

func TestJobScopeStateEmitJobResultLog_FlushesFinalRecord(t *testing.T) {
	t.Parallel()

	recorder := &recordingJobScopeBatches{}
	scope := jobscope.NewHost()
	scope.ConfigRevision = "config-sha"
	scope.ResolvedRules = rule.ResolvedRules{Rules: []rule.ResolvedRule{{
		RulesetID:       "set",
		RulesetRevision: "rules-sha",
		Rule: rule.Rule{
			RuleID:    "detect_token",
			EventKind: jobevent.ProcessExec,
			Action:    rule.RuleActionDetect,
		},
	}}}
	logs := joblogs.NewForTesting(testJobScopeLogger, recorder.sendBatch)
	logs.AttachJobResultRecorderForTesting(testJobIdentity, scope.Kind, recorder.sendBatch)
	scope.SetManagerJobLogs(logs)
	hit := observations.HitEntry{
		Identity:  rule.RuleIdentity{RulesetID: "set", RuleID: "detect_token"},
		Action:    string(rule.RuleActionDetect),
		MaxAlerts: 1,
	}
	scope.RecordHit(hit, testJobScopeProcessEvent("event-result"))
	scope.Observations.RecordEvent(testJobScopeNetworkEvent("event-network", "203.0.113.20"))

	if err := scope.EmitJobResultLog(context.Background(), jobscope.JobResultLogInputs{
		Identity:   testJobIdentity,
		Metadata:   testJobMetadata,
		RunnerKind: "machine",
		StartedAt:  testEventTime.Add(-time.Minute),
	}, "completed", testEventTime.Add(time.Minute)); err != nil {
		t.Fatalf("emit result log: %v", err)
	}

	entries := recorder.jobResultEntries(t)
	if len(entries) != 1 {
		t.Fatalf("job result entries: got %d, want 1", len(entries))
	}
	entry := entries[0]
	if got, want := entry.Scope, string(jobcontext.ScopeKindHost); got != want {
		t.Fatalf("scope: got %q, want %q", got, want)
	}
	if got, want := entry.Job.GetRunnerKind(), "machine"; got != want {
		t.Fatalf("runner kind: got %q, want %q", got, want)
	}
	if got, want := entry.ConfigRevision, "config-sha"; got != want {
		t.Fatalf("config revision: got %q, want %q", got, want)
	}
	if got, want := entry.FinalizeReason, "completed"; got != want {
		t.Fatalf("finalize reason: got %q, want %q", got, want)
	}
	if len(entry.Rulesets) != 1 || entry.Rulesets[0].RulesetId != "set" || entry.Rulesets[0].Revision != "rules-sha" {
		t.Fatalf("rulesets: got %#v, want set/rules-sha", entry.Rulesets)
	}
	if len(entry.Detections) != 1 || entry.Detections[0].RuleId != "detect_token" || entry.Detections[0].Count != 1 {
		t.Fatalf("detections: got %#v, want detect_token count=1", entry.Detections)
	}
	if len(entry.NetworkConnects) != 1 || entry.NetworkConnects[0] != "203.0.113.20" {
		t.Fatalf("network connects: got %#v, want 203.0.113.20", entry.NetworkConnects)
	}
}

func TestJobScopeStateCorrelationHitCountFor(t *testing.T) {
	t.Parallel()

	identity := rule.RuleIdentity{RulesetID: "set", RuleID: "detect_token"}
	var nilScope *jobscope.JobScopeState
	if got := nilScope.CorrelationHitCountFor(identity); got != 0 {
		t.Fatalf("nil scope hit count: got %d, want 0", got)
	}

	scope := jobscope.NewHost()
	if got := scope.CorrelationHitCountFor(identity); got != 0 {
		t.Fatalf("empty hit count: got %d, want 0", got)
	}
	scope.RecordHit(observations.HitEntry{Identity: identity, Action: string(rule.RuleActionDetect)}, testJobScopeProcessEvent("event-hit"))
	if got := scope.CorrelationHitCountFor(identity); got != 1 {
		t.Fatalf("recorded hit count: got %d, want 1", got)
	}
	scope.Observations = nil
	if got := scope.CorrelationHitCountFor(identity); got != 0 {
		t.Fatalf("nil observations hit count: got %d, want 0", got)
	}
}

func testJobScopeProcessEvent(id string) jobevent.EventRecord {
	return jobevent.EventRecord{
		ID:        id,
		EventKind: jobevent.ProcessExec,
		Timestamp: testEventTime,
		Payload:   map[string]any{"is_memfd": false},
		Process: jobevent.ProcessSummary{
			PID:      100,
			ExecPath: "/usr/bin/curl",
			Argv:     []string{"curl", "--token=secret"},
		},
	}
}

func testJobScopeNetworkEvent(id, remoteIP string) jobevent.EventRecord {
	return jobevent.EventRecord{
		ID:        id,
		EventKind: jobevent.NetworkConnect,
		Timestamp: testEventTime,
		Payload: map[string]any{
			"remote_ip":   remoteIP,
			"remote_port": uint16(443),
			"protocol":    "tcp",
			"family":      "ipv4",
		},
		Process: jobevent.ProcessSummary{
			PID:      101,
			ExecPath: "/usr/bin/curl",
			Argv:     []string{"curl", "https://example.com"},
		},
	}
}
