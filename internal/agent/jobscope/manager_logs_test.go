package jobscope_test

import (
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"os"
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
	testJobMetadata    = jobcontext.JobMetadata{CommitSHA: "abc123", RefName: "main"}
	testEventTime      = time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
)

type recordingJobScopeBatches struct {
	mu      sync.Mutex
	records map[managerv1.LogType][][]byte
}

func (r *recordingJobScopeBatches) sendBatch(_ context.Context, batch managerclient.LogBatch) error {
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

func (r *recordingJobScopeBatches) detectionEntries(t *testing.T) []*logv1.DetectionLogEntry {
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

func (r *recordingJobScopeBatches) runtimeEventEntries(t *testing.T) []*logv1.RuntimeEventLogEntry {
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

func (r *recordingJobScopeBatches) summaryEntries(t *testing.T) []*logv1.SummaryLogEntry {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()

	records := r.records[managerv1.LogType_LOG_TYPE_SUMMARY]
	out := make([]*logv1.SummaryLogEntry, 0, len(records))
	for _, record := range records {
		entry := &logv1.SummaryLogEntry{}
		if err := protojson.Unmarshal(record, entry); err != nil {
			t.Fatalf("unmarshal summary log record: %v", err)
		}
		out = append(out, entry)
	}
	return out
}

func TestJobScopeStateWriteDetectionLogForHit_CollectEmitsDetectionLog(t *testing.T) {
	t.Parallel()

	recorder := &recordingJobScopeBatches{}
	scope := jobscope.NewHost()
	scope.ManagerJobLogsForTesting().AttachDetectionRecorderForTesting(testJobIdentity, scope.Type, recorder.sendBatch)
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

	entries := recorder.detectionEntries(t)
	if len(entries) != 1 {
		t.Fatalf("detection entries: got %d, want 1", len(entries))
	}
	if got, want := entries[0].GetAction(), string(rule.RuleActionCollect); got != want {
		t.Fatalf("action: got %q, want %q", got, want)
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
			EventType:   jobevent.ProcessExec,
			RuleName:    "Detect token",
			Description: "flags token-like process arguments",
			Action:      rule.RuleActionDetect,
		},
	}}}
	scope.ManagerJobLogsForTesting().AttachDetectionRecorderForTesting(testJobIdentity, scope.Type, recorder.sendBatch)
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
	if got, want := entries[0].GetRuleAlertTruncation(), ""; got != want {
		t.Fatalf("first truncation: got %q, want %q", got, want)
	}
	if got, want := entries[1].GetRuleAlertTruncation(), resultdoc.AlertTruncationMaxAlertsReached; got != want {
		t.Fatalf("second truncation: got %q, want %q", got, want)
	}
	if got, want := entries[0].GetRuleName(), "Detect token"; got != want {
		t.Fatalf("rule name: got %q, want %q", got, want)
	}
	if got, want := entries[0].GetRunnerType(), "machine"; got != want {
		t.Fatalf("runner type: got %q, want %q", got, want)
	}
	if got, want := entries[0].GetRuleDescription(), "flags token-like process arguments"; got != want {
		t.Fatalf("rule description: got %q, want %q", got, want)
	}
	if got, want := entries[0].GetRulesetRevision(), "rules-sha"; got != want {
		t.Fatalf("ruleset revision: got %q, want %q", got, want)
	}
}

func TestJobScopeStateWriteRuntimeEventLog_EmitsEvent(t *testing.T) {
	t.Parallel()

	recorder := &recordingJobScopeBatches{}
	scope := jobscope.NewProject()
	scope.ManagerJobLogsForTesting().AttachRuntimeEventRecorderForTesting(testJobIdentity, scope.Type, recorder.sendBatch)
	event := testJobScopeNetworkEvent("event-runtime", "203.0.113.10")

	scope.WriteRuntimeEventLog(context.Background(), testJobIdentity, testJobMetadata, "machine", event, testJobScopeLogger)
	if err := scope.FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize logs: %v", err)
	}

	entries := recorder.runtimeEventEntries(t)
	if len(entries) != 1 {
		t.Fatalf("runtime event entries: got %d, want 1", len(entries))
	}
	if got, want := entries[0].GetScope(), string(jobcontext.ScopeTypeProject); got != want {
		t.Fatalf("scope: got %q, want %q", got, want)
	}
	if got, want := entries[0].GetRunnerType(), "machine"; got != want {
		t.Fatalf("runner type: got %q, want %q", got, want)
	}
	if got, want := entries[0].Event.GetId(), event.ID; got != want {
		t.Fatalf("event id: got %q, want %q", got, want)
	}
	if got, want := entries[0].Event.GetNetworkConnect().GetRemoteIp(), "203.0.113.10"; got != want {
		t.Fatalf("remote ip: got %q, want %q", got, want)
	}
}

func TestJobScopeStateWriteRuntimeEventLog_WritesDebugOutput(t *testing.T) {
	t.Parallel()

	debugDir := t.TempDir()
	scope := jobscope.NewProject()
	debugOutput, err := joblogs.NewDebugOutputForTesting(testJobScopeLogger, debugDir)
	if err != nil {
		t.Fatalf("NewDebugOutput: %v", err)
	}
	scope.SetDebugOutput(debugOutput)

	event := testJobScopeNetworkEvent("event-debug-runtime", "203.0.113.30")
	scope.WriteRuntimeEventLog(context.Background(), testJobIdentity, testJobMetadata, "machine", event, testJobScopeLogger)
	if err := scope.CloseDebugOutput(context.Background()); err != nil {
		t.Fatalf("close debug output: %v", err)
	}

	entry := readDebugRuntimeEventEntry(t, debugDir)
	if got, want := entry.GetEvent().GetId(), event.ID; got != want {
		t.Fatalf("event id: got %q, want %q", got, want)
	}
	if got, want := entry.GetEvent().GetNetworkConnect().GetRemoteIp(), "203.0.113.30"; got != want {
		t.Fatalf("remote ip: got %q, want %q", got, want)
	}
}

func TestJobScopeStateFinalizeStreamingLogs_ClosesDebugOutput(t *testing.T) {
	t.Parallel()

	debugDir := t.TempDir()
	scope := jobscope.NewProject()
	debugOutput, err := joblogs.NewDebugOutputForTesting(testJobScopeLogger, debugDir)
	if err != nil {
		t.Fatalf("NewDebugOutput: %v", err)
	}
	scope.SetDebugOutput(debugOutput)

	event := testJobScopeNetworkEvent("event-debug-finalize", "203.0.113.31")
	scope.WriteRuntimeEventLog(context.Background(), testJobIdentity, testJobMetadata, "machine", event, testJobScopeLogger)
	if err := scope.FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize streaming logs: %v", err)
	}

	entry := readDebugRuntimeEventEntry(t, debugDir)
	if got, want := entry.GetEvent().GetId(), event.ID; got != want {
		t.Fatalf("event id: got %q, want %q", got, want)
	}
}

func TestJobScopeStateEmitSummaryLog_FlushesFinalRecord(t *testing.T) {
	t.Parallel()

	recorder := &recordingJobScopeBatches{}
	scope := jobscope.NewHost()
	scope.ConfigRevision = "config-sha"
	scope.ResolvedRules = rule.ResolvedRules{Rules: []rule.ResolvedRule{{
		RulesetID:       "set",
		RulesetRevision: "rules-sha",
		Rule: rule.Rule{
			RuleID:    "detect_token",
			EventType: jobevent.ProcessExec,
			Action:    rule.RuleActionDetect,
		},
	}}}
	logs := joblogs.NewForTesting(testJobScopeLogger, recorder.sendBatch)
	logs.AttachSummaryRecorderForTesting(testJobIdentity, scope.Type, recorder.sendBatch)
	scope.SetManagerJobLogs(logs)
	hit := observations.HitEntry{
		Identity:  rule.RuleIdentity{RulesetID: "set", RuleID: "detect_token"},
		Action:    string(rule.RuleActionDetect),
		MaxAlerts: 1,
	}
	scope.RecordHit(hit, testJobScopeProcessEvent("event-result"))
	scope.Observations.RecordEvent(testJobScopeNetworkEvent("event-network", "203.0.113.20"))

	if err := scope.EmitSummaryLog(context.Background(), jobscope.SummaryLogInputs{
		Identity:   testJobIdentity,
		Metadata:   testJobMetadata,
		RunnerType: "machine",
		StartedAt:  testEventTime.Add(-time.Minute),
	}, "completed", testEventTime.Add(time.Minute)); err != nil {
		t.Fatalf("emit summary log: %v", err)
	}

	entries := recorder.summaryEntries(t)
	if len(entries) != 1 {
		t.Fatalf("summary entries: got %d, want 1", len(entries))
	}
	entry := entries[0]
	if got, want := entry.GetScope(), string(jobcontext.ScopeTypeHost); got != want {
		t.Fatalf("scope: got %q, want %q", got, want)
	}
	if got, want := entry.GetRunnerType(), "machine"; got != want {
		t.Fatalf("runner type: got %q, want %q", got, want)
	}
	if got, want := entry.GetConfigRevision(), "config-sha"; got != want {
		t.Fatalf("config revision: got %q, want %q", got, want)
	}
	if got, want := entry.GetFinalizeReason(), "completed"; got != want {
		t.Fatalf("finalize reason: got %q, want %q", got, want)
	}
	if len(entry.Rulesets) != 1 || entry.Rulesets[0].GetRulesetId() != "set" || entry.Rulesets[0].GetRevision() != "rules-sha" {
		t.Fatalf("rulesets: got %#v, want set/rules-sha", entry.Rulesets)
	}
	if len(entry.Detections) != 1 || entry.Detections[0].GetRuleId() != "detect_token" || entry.Detections[0].GetCount() != 1 {
		t.Fatalf("detections: got %#v, want detect_token count=1", entry.Detections)
	}
	if len(entry.NetworkConnects) != 1 || entry.NetworkConnects[0] != "203.0.113.20" {
		t.Fatalf("network connects: got %#v, want 203.0.113.20", entry.NetworkConnects)
	}
}

func readDebugRuntimeEventEntry(t *testing.T, debugDir string) *logv1.RuntimeEventLogEntry {
	t.Helper()

	root, err := os.OpenRoot(debugDir)
	if err != nil {
		t.Fatalf("OpenRoot debug dir: %v", err)
	}
	defer root.Close()

	file, err := root.Open(joblogs.DebugRuntimeEventLogFilename)
	if err != nil {
		t.Fatalf("open debug runtime event: %v", err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	var entry logv1.RuntimeEventLogEntry
	if err := protojson.Unmarshal(body, &entry); err != nil {
		t.Fatalf("unmarshal debug runtime event: %v\nbody=%s", err, body)
	}
	return &entry
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
		EventType: jobevent.ProcessExec,
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
		EventType: jobevent.NetworkConnect,
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
