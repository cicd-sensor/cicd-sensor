package jobregistry_test

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
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

	if _, err := jr.ApplyGitHubProjectStart(testCtx, id, meta, "machine", 0, 0, nil, managerclient.Connection{}, nil, false); err != nil {
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
		t.Fatalf("unmarshal summary_log: %v", err)
	}
	if entry.JobIdentity != id {
		t.Fatalf("job_identity: got %#v, want %#v", entry.JobIdentity, id)
	}
}

func TestJobRegistry_RequestGitHubProjectResult_ClosesDebugOutputBeforeReturn(t *testing.T) {
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}

	if _, err := jr.ApplyGitHubProjectStart(testCtx, id, meta, "machine", 0, 0, nil, managerclient.Connection{}, nil, false); err != nil {
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
