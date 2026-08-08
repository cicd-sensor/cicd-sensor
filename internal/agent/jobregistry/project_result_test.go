package jobregistry_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jobpkg "github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/joblogs"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
)

func TestJobRegistry_RequestGitHubProjectResult_ExistingJob(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	if _, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:   id,
		Metadata:   meta,
		RunnerType: "machine",
	}); err != nil {
		t.Fatalf("apply project start: %v", err)
	}

	body, err := jr.RequestGitHubProjectResult(testCtx, id, 0)
	if err != nil {
		t.Fatalf("request project result: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("result body is empty")
	}
	if !json.Valid(body) {
		t.Fatal("result body is not valid JSON")
	}
	var entry resultdoc.JobEventSummaryForReport
	if err := json.Unmarshal(body, &entry); err != nil {
		t.Fatalf("unmarshal summary: %v", err)
	}
	if entry.JobIdentity != id {
		t.Fatalf("job_identity: got %#v, want %#v", entry.JobIdentity, id)
	}
}

func TestJobRegistry_RequestGitHubProjectResult_ClosesDebugOutputBeforeReturn(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	if _, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:   id,
		Metadata:   meta,
		RunnerType: "machine",
	}); err != nil {
		t.Fatalf("apply project start: %v", err)
	}
	job := registeredJob(jr, id)
	if job == nil || job.ProjectScope() == nil {
		t.Fatal("project job not registered")
	}
	debugDir := t.TempDir()
	debugOutput, err := joblogs.NewDebugOutputForTesting(testLogger, debugDir)
	if err != nil {
		t.Fatalf("NewDebugOutputForTesting: %v", err)
	}
	project := job.ProjectScope()
	project.SetDebugOutput(debugOutput)

	project.WriteRuntimeEventLog(testCtx, id, meta, "machine", testProjectResultEvent("event-before-result"), testLogger)
	if _, err := jr.RequestGitHubProjectResult(testCtx, id, 0); err != nil {
		t.Fatalf("request project result: %v", err)
	}

	body := readProjectResultDebugGzip(t, debugDir)
	if !strings.Contains(body, "event-before-result") {
		t.Fatalf("debug gzip does not contain pre-result event: %s", body)
	}

	project.WriteRuntimeEventLog(testCtx, id, meta, "machine", testProjectResultEvent("event-after-result"), testLogger)
	body = readProjectResultDebugGzip(t, debugDir)
	if strings.Contains(body, "event-after-result") {
		t.Fatalf("debug gzip contains event written after project result: %s", body)
	}
}

func TestJobRegistry_RequestGitHubProjectResult_MissingJob(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "missing")

	_, err := jr.RequestGitHubProjectResult(testCtx, id, 0)
	if !errors.Is(err, jobregistry.ErrJobNotFound) {
		t.Fatalf("request project result error: got %v, want %v", err, jobregistry.ErrJobNotFound)
	}
}

func TestJobRegistry_RequestGitHubProjectResult_ProjectScopeMissing(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	if _, err := jr.ApplyGitHubHostStart(testCtx, id, meta, "machine", 0, managerclient.Connection{}, staticManagerFetcher{}); err != nil {
		t.Fatalf("apply host start: %v", err)
	}
	_, err := jr.RequestGitHubProjectResult(testCtx, id, 0)
	if !errors.Is(err, jobpkg.ErrProjectScopeMissing) {
		t.Fatalf("request project result error: got %v, want %v", err, jobpkg.ErrProjectScopeMissing)
	}
}

func testProjectResultEvent(id string) jobevent.EventRecord {
	return jobevent.EventRecord{
		ID:        id,
		EventType: jobevent.NetworkConnect,
		Timestamp: time.Date(2026, 5, 23, 1, 2, 3, 0, time.UTC),
		Process: jobevent.ProcessSummary{
			PID:      100,
			ExecPath: "/usr/bin/curl",
		},
		Payload: map[string]any{
			"remote_ip":   "203.0.113.10",
			"remote_port": int64(443),
			"protocol":    "tcp",
		},
	}
}

func readProjectResultDebugGzip(t *testing.T, debugDir string) string {
	t.Helper()

	file, err := os.Open(filepath.Join(debugDir, joblogs.DebugRuntimeEventLogFilename))
	if err != nil {
		t.Fatalf("open debug gzip: %v", err)
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
		t.Fatalf("close gzip reader: %v", err)
	}
	return string(body)
}

type recordingProjectLogSender struct {
	mu      sync.Mutex
	err     error
	records [][]byte
}

func (r *recordingProjectLogSender) sendBatch(_ context.Context, batch managerclient.LogBatch) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	for _, record := range batch.Records {
		r.records = append(r.records, append([]byte(nil), record...))
	}
	return nil
}

func (r *recordingProjectLogSender) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.records)
}

func TestJobRegistry_RequestGitHubProjectResult_FlushesBufferedStreamingLogs(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	if _, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:   id,
		Metadata:   meta,
		RunnerType: "machine",
	}); err != nil {
		t.Fatalf("apply project start: %v", err)
	}
	job := registeredJob(jr, id)
	if job == nil || job.ProjectScope() == nil {
		t.Fatal("project job not registered")
	}
	recorder := &recordingProjectLogSender{}
	project := job.ProjectScope()
	project.ManagerJobLogsForTesting().AttachBufferedRuntimeEventRecorderForTesting(id, project.Type, recorder.sendBatch)

	project.WriteRuntimeEventLog(testCtx, id, meta, "machine", testProjectResultEvent("event-before-result"), testLogger)
	if got := recorder.count(); got != 0 {
		t.Fatalf("runtime event records before project result: got %d, want 0", got)
	}

	if _, err := jr.RequestGitHubProjectResult(testCtx, id, 0); err != nil {
		t.Fatalf("request project result: %v", err)
	}
	if got := recorder.count(); got != 1 {
		t.Fatalf("runtime event records after project result: got %d, want 1", got)
	}

	// A repeated project result flushes whatever buffered since.
	project.WriteRuntimeEventLog(testCtx, id, meta, "machine", testProjectResultEvent("event-between-results"), testLogger)
	body, err := jr.RequestGitHubProjectResult(testCtx, id, 0)
	if err != nil {
		t.Fatalf("second project result: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("second project result body is empty")
	}
	if got := recorder.count(); got != 2 {
		t.Fatalf("runtime event records after second call: got %d, want 2", got)
	}
}

func TestJobRegistry_RequestGitHubProjectResult_FlushFailureStillReturnsBody(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	if _, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:   id,
		Metadata:   meta,
		RunnerType: "machine",
	}); err != nil {
		t.Fatalf("apply project start: %v", err)
	}
	job := registeredJob(jr, id)
	if job == nil || job.ProjectScope() == nil {
		t.Fatal("project job not registered")
	}
	recorder := &recordingProjectLogSender{err: errors.New("manager unavailable")}
	project := job.ProjectScope()
	project.ManagerJobLogsForTesting().AttachBufferedRuntimeEventRecorderForTesting(id, project.Type, recorder.sendBatch)
	project.WriteRuntimeEventLog(testCtx, id, meta, "machine", testProjectResultEvent("event-before-result"), testLogger)

	body, err := jr.RequestGitHubProjectResult(testCtx, id, 0)
	if err != nil {
		t.Fatalf("project result with failing flush: %v", err)
	}
	if !json.Valid(body) {
		t.Fatal("result body is not valid JSON")
	}
}
