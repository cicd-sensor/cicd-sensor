package jobregistry

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/joblogs"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"google.golang.org/protobuf/encoding/protojson"
)

type recordingManagerBatchPoster struct {
	mu      sync.Mutex
	batches []*managerv1.IngestLogBatch
}

func (r *recordingManagerBatchPoster) sendBatch(_ context.Context, batch managerclient.LogBatch) error {
	msg, err := managerclient.BuildCollectorIngestLogBatch(batch)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batches = append(r.batches, msg)
	return nil
}

func TestJobFinalizeAfterEventWorkerFlushesAllJobLogs(t *testing.T) {
	t.Parallel()

	poster := &recordingManagerBatchPoster{}
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	metadata := jobcontext.JobMetadata{}
	job, eventCh := newTestJob(identity, metadata, testEventChannelSize)
	scope := jobscope.NewHost()
	logs := joblogs.NewForTesting(testLogger, poster.sendBatch)
	logs.AttachDetectionRecorderForTesting(identity, scope.Type, poster.sendBatch)
	logs.AttachRuntimeEventRecorderForTesting(identity, scope.Type, poster.sendBatch)
	logs.AttachSummaryRecorderForTesting(identity, scope.Type, poster.sendBatch)
	scope.SetManagerJobLogs(logs)
	scope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{{
			RuleID:    "curl-egress",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "registry.npmjs.org" && protocol == "tcp"`,
			Action:    rule.RuleActionDetect,
		}},
	}}
	scope.ResolveRules(identity)
	if err := job.SetHostScope(testCtx, scope); err != nil {
		t.Fatalf("SetHostScope: %v", err)
	}

	sendTestEvent(t, eventCh, testDispatchEvent("/usr/bin/curl", "registry.npmjs.org", 443))
	waitForJob(t, "event worker processed detection before finalize", func() bool {
		return len(scope.ObservationSnapshot().Hits) == 1
	})
	// In production KernelTracker.RemoveJob closes this channel. Closing it here
	// pins the post-BPF boundary: finalize waits for the event worker to drain
	// before flushing streaming logs and emitting summary_log.
	close(eventCh)

	jr := New(testLogger)
	finalizedAt := time.Date(2026, 4, 27, 12, 30, 0, 0, time.UTC)
	if err := jr.finalizeTakenJobSync(testCtx, job, kerneltracker.EndShutdown, finalizedAt); err != nil {
		t.Fatalf("finalizeTakenJobSync: %v", err)
	}

	batches := managerBatchPosterSnapshot(poster)
	if len(batches) != 3 {
		t.Fatalf("sent batches: got %d, want 3", len(batches))
	}
	gotTypes := make(map[managerv1.LogType]*managerv1.IngestLogBatch, len(batches))
	for _, batch := range batches {
		gotTypes[batch.LogType] = batch
	}
	for _, logType := range []managerv1.LogType{
		managerv1.LogType_LOG_TYPE_DETECTION,
		managerv1.LogType_LOG_TYPE_RUNTIME_EVENT,
		managerv1.LogType_LOG_TYPE_SUMMARY,
	} {
		if gotTypes[logType] == nil {
			t.Fatalf("missing log type %s in batches %#v", logType, gotTypes)
		}
	}

	summaryRecords := decodeManagerBatchRecords(t, gotTypes[managerv1.LogType_LOG_TYPE_SUMMARY])
	if len(summaryRecords) != 1 {
		t.Fatalf("summary_log records: got %d, want 1", len(summaryRecords))
	}
	var summaryLog logv1.SummaryLogEntry
	if err := protojson.Unmarshal(summaryRecords[0], &summaryLog); err != nil {
		t.Fatalf("unmarshal summary_log: %v", err)
	}
	if got := len(summaryLog.GetDetections()); got != 1 {
		t.Fatalf("detections: got %d, want 1", got)
	}
	if summaryLog.GetDetections()[0].GetRuleId() != "curl-egress" {
		t.Fatalf("detection rule_id: got %q, want curl-egress", summaryLog.GetDetections()[0].GetRuleId())
	}
	if summaryLog.GetFinalizeReason() != string(kerneltracker.EndShutdown) {
		t.Fatalf("finalize_reason: got %q, want %q", summaryLog.GetFinalizeReason(), kerneltracker.EndShutdown)
	}
	if summaryLog.GetEventsTotal() != 1 || summaryLog.GetEventsDropped() != 0 {
		t.Fatalf("event counters: total=%d dropped=%d, want 1/0", summaryLog.GetEventsTotal(), summaryLog.GetEventsDropped())
	}

	detectionRecords := decodeManagerBatchRecords(t, gotTypes[managerv1.LogType_LOG_TYPE_DETECTION])
	runtimeRecords := decodeManagerBatchRecords(t, gotTypes[managerv1.LogType_LOG_TYPE_RUNTIME_EVENT])
	if len(detectionRecords) != 1 || len(runtimeRecords) != 1 {
		t.Fatalf("streaming records: detection=%d runtime=%d, want 1/1", len(detectionRecords), len(runtimeRecords))
	}
	var detectionLog logv1.DetectionLogEntry
	if err := protojson.Unmarshal(detectionRecords[0], &detectionLog); err != nil {
		t.Fatalf("unmarshal detection log: %v", err)
	}
	var runtimeLog logv1.RuntimeEventLogEntry
	if err := protojson.Unmarshal(runtimeRecords[0], &runtimeLog); err != nil {
		t.Fatalf("unmarshal runtime event log: %v", err)
	}
	if detectionLog.GetLogId() == "" || runtimeLog.GetLogId() == "" || summaryLog.GetLogId() == "" {
		t.Fatalf("log_id missing: detection=%q runtime=%q result=%q", detectionLog.GetLogId(), runtimeLog.GetLogId(), summaryLog.GetLogId())
	}
	if detectionLog.GetEvent().GetId() == "" {
		t.Fatal("event id missing from detection log")
	}
	if detectionLog.GetEvent().GetId() != runtimeLog.GetEvent().GetId() {
		t.Fatalf("event id mismatch: detection=%q runtime=%q", detectionLog.GetEvent().GetId(), runtimeLog.GetEvent().GetId())
	}
	if detectionLog.GetJob().GetProjectPath() != identity.ProjectPath || runtimeLog.GetJob().GetProviderHost() != identity.ProviderHost {
		t.Fatalf("job context missing from logs: detection=%+v runtime=%+v", detectionLog.GetJob(), runtimeLog.GetJob())
	}
}

func TestFinalizeTakenJob_EmitsProjectResultWhenHostResultFails(t *testing.T) {
	t.Parallel()

	hostErr := errors.New("host result failed")
	var mu sync.Mutex
	var sent []managerclient.LogBatch
	send := func(_ context.Context, batch managerclient.LogBatch) error {
		if batch.Type == managerv1.LogType_LOG_TYPE_SUMMARY && batch.Scope == managerv1.Scope_SCOPE_HOST {
			return hostErr
		}
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, batch)
		return nil
	}

	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	job, eventCh := newTestJob(identity, jobcontext.JobMetadata{}, 1)
	close(eventCh)

	hostScope := jobscope.NewHost()
	hostLogs := joblogs.NewForTesting(testLogger, send)
	hostLogs.AttachSummaryRecorderForTesting(identity, hostScope.Type, send)
	hostScope.SetManagerJobLogs(hostLogs)
	hostScope.ResolveRules(identity)
	if err := job.SetHostScope(testCtx, hostScope); err != nil {
		t.Fatalf("SetHostScope: %v", err)
	}

	projectScope := jobscope.NewProject()
	projectLogs := joblogs.NewForTesting(testLogger, send)
	projectLogs.AttachSummaryRecorderForTesting(identity, projectScope.Type, send)
	projectScope.SetManagerJobLogs(projectLogs)
	projectScope.ResolveRules(identity)
	if err := job.SetProjectScope(testCtx, projectScope); err != nil {
		t.Fatalf("SetProjectScope: %v", err)
	}

	jr := New(testLogger)
	err := jr.finalizeTakenJobSync(testCtx, job, kerneltracker.EndShutdown, time.Date(2026, 5, 12, 1, 2, 3, 0, time.UTC))
	if !errors.Is(err, hostErr) {
		t.Fatalf("finalizeTakenJobSync error: got %v, want host error", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 1 {
		t.Fatalf("sent batches after host failure: got %d, want 1", len(sent))
	}
	if sent[0].Type != managerv1.LogType_LOG_TYPE_SUMMARY || sent[0].Scope != managerv1.Scope_SCOPE_PROJECT {
		t.Fatalf("sent batch: type=%s scope=%s, want project result", sent[0].Type, sent[0].Scope)
	}
}

func managerBatchPosterSnapshot(poster *recordingManagerBatchPoster) []*managerv1.IngestLogBatch {
	poster.mu.Lock()
	defer poster.mu.Unlock()
	return append([]*managerv1.IngestLogBatch(nil), poster.batches...)
}

func decodeManagerBatchRecords(t *testing.T, batch *managerv1.IngestLogBatch) [][]byte {
	t.Helper()

	reader, err := gzip.NewReader(bytes.NewReader(batch.CompressedJsonl))
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
	lines := bytes.Split(bytes.TrimSuffix(body, []byte("\n")), []byte("\n"))
	records := make([][]byte, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		records = append(records, append([]byte(nil), line...))
	}
	return records
}
