package joblogs

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
)

var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestStartJobLogsAddsManagerDestination(t *testing.T) {
	poster := &recordingLogBatchSender{}
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	settings := &managerv1.OutputSettings{
		JobDetectionLog: &managerv1.OutputSetting{Enabled: true},
	}

	conn := newManagerJobLogsWithSender(testLogger, poster.sendBatch, identity, jobcontext.ScopeKindHost, settings)
	if conn.detection == nil {
		t.Fatal("expected manager detection output")
	}
	if err := conn.WriteDetectionPayload(context.Background(), []byte(`{"rule_id":"a"}`)); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if err := conn.FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize streaming: %v", err)
	}
	if poster.count() != 1 {
		t.Fatalf("sent batches: got %d, want 1", poster.count())
	}
}

func TestStartJobLogsIgnoresDisabledKind(t *testing.T) {
	poster := &recordingLogBatchSender{}
	identity := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	settings := &managerv1.OutputSettings{}

	conn := newManagerJobLogsWithSender(testLogger, poster.sendBatch, identity, jobcontext.ScopeKindHost, settings)
	if conn.detection != nil {
		t.Fatalf("manager output added for disabled log: %T", conn.detection)
	}
}

func TestStartJobLogsDoesNotCreateSenderWithoutEnabledLogs(t *testing.T) {
	conn := NewManagerJobLogs(ManagerJobLogsConfig{
		Logger:         testLogger,
		Connection:     managerclient.Connection{BaseURL: "http://127.0.0.1:1", Token: "sk_csensor_testtoken"},
		Identity:       jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"),
		Kind:           jobcontext.ScopeKindHost,
		OutputSettings: &managerv1.OutputSettings{},
	})

	if conn.sendBatch != nil {
		t.Fatal("manager sender created even though no log kind is enabled")
	}
}

func TestStartJobLogsDoesNotCreateSenderWithoutManagerCredentials(t *testing.T) {
	conn := NewManagerJobLogs(ManagerJobLogsConfig{
		Logger:     testLogger,
		Connection: managerclient.Connection{},
		Identity:   jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"),
		Kind:       jobcontext.ScopeKindHost,
		OutputSettings: &managerv1.OutputSettings{
			JobDetectionLog: &managerv1.OutputSetting{Enabled: true},
		},
	})

	if conn.detection != nil {
		t.Fatal("manager output created without manager credentials")
	}
	if conn.sendBatch != nil {
		t.Fatal("manager sender created without manager credentials")
	}
}

func TestNewForTestingUsesInjectedSender(t *testing.T) {
	poster := &recordingLogBatchSender{}
	conn := NewForTesting(testLogger, poster.sendBatch)

	conn.start(
		jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"),
		jobcontext.ScopeKindHost,
		&managerv1.OutputSettings{
			JobDetectionLog: &managerv1.OutputSetting{Enabled: true},
		},
	)
	if conn.detection == nil {
		t.Fatal("expected test detection output")
	}
	if err := conn.WriteDetectionPayload(context.Background(), []byte(`{"rule_id":"a"}`)); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if err := conn.FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize streaming: %v", err)
	}
	if got := poster.count(); got != 1 {
		t.Fatalf("sent batches: got %d, want 1", got)
	}
}

func TestManagerJobLogsNoOpWhenLogKindsAreNotConfigured(t *testing.T) {
	var conn ManagerJobLogs

	if err := conn.WriteDetectionPayload(context.Background(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("detection write without output: %v", err)
	}
	if err := conn.WriteRuntimeTelemetryPayload(context.Background(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("runtime telemetry write without output: %v", err)
	}
	if err := conn.EmitAndCloseJobResultLog(context.Background(), []byte(`{"final":true}`)); err != nil {
		t.Fatalf("job result write without output: %v", err)
	}
	if conn.HasJobResultLog() {
		t.Fatal("job_result_log reported configured on zero ManagerJobLogs")
	}
	if got := conn.DroppedLogRecords(managerv1.LogKind_LOG_KIND_JOB_DETECTION); got != 0 {
		t.Fatalf("dropped records on zero ManagerJobLogs: got %d, want 0", got)
	}
	if got := conn.DroppedLogRecords(managerv1.LogKind_LOG_KIND_UNSPECIFIED); got != 0 {
		t.Fatalf("dropped records for unknown kind: got %d, want 0", got)
	}
	if err := conn.FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize zero ManagerJobLogs: %v", err)
	}
}

func TestStartJobLogsUsesOneWorkerPerKind(t *testing.T) {
	poster := &recordingLogBatchSender{}
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	settings := &managerv1.OutputSettings{
		JobDetectionLog:        &managerv1.OutputSetting{Enabled: true},
		JobRuntimeTelemetryLog: &managerv1.OutputSetting{Enabled: true},
		JobResultLog:           &managerv1.OutputSetting{Enabled: true},
	}

	conn := newManagerJobLogsWithSender(testLogger, poster.sendBatch, identity, jobcontext.ScopeKindHost, settings)
	if conn.detection == nil || conn.runtimeTelemetry == nil || conn.jobResultLog == nil {
		t.Fatal("expected detection, runtime telemetry, and job_result_log workers")
	}
	if conn.detection.requests == conn.runtimeTelemetry.requests {
		t.Fatal("detection and runtime telemetry must use separate workers")
	}
	if conn.detection.requests == conn.jobResultLog.requests {
		t.Fatal("detection and job_result_log must use separate workers")
	}
}

func TestManagerJobLogsEmitAndCloseJobResultLog(t *testing.T) {
	poster := &recordingLogBatchSender{}
	conn := newManagerJobLogsWithSender(testLogger, poster.sendBatch,
		jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"),
		jobcontext.ScopeKindProject,
		&managerv1.OutputSettings{
			JobResultLog: &managerv1.OutputSetting{Enabled: true},
		},
	)

	if !conn.HasJobResultLog() {
		t.Fatal("expected job_result_log to be configured")
	}
	if err := conn.EmitAndCloseJobResultLog(context.Background(), []byte(`{"final":true}`)); err != nil {
		t.Fatalf("emit job result log: %v", err)
	}
	if got := poster.count(); got != 1 {
		t.Fatalf("sent batches: got %d, want 1", got)
	}
	if got := conn.DroppedLogRecords(managerv1.LogKind_LOG_KIND_JOB_RESULT); got != 0 {
		t.Fatalf("job result drops: got %d, want 0", got)
	}
}

func TestManagerJobLogsRejectsStreamingWritesAfterFinalize(t *testing.T) {
	poster := &recordingLogBatchSender{}
	conn := newManagerJobLogsWithSender(testLogger, poster.sendBatch,
		jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"),
		jobcontext.ScopeKindHost,
		&managerv1.OutputSettings{
			JobDetectionLog:        &managerv1.OutputSetting{Enabled: true},
			JobRuntimeTelemetryLog: &managerv1.OutputSetting{Enabled: true},
		},
	)

	if err := conn.FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize streaming: %v", err)
	}
	if err := conn.WriteDetectionPayload(context.Background(), []byte(`{"late":true}`)); err != errManagerOutputClosed {
		t.Fatalf("late detection write: got %v, want %v", err, errManagerOutputClosed)
	}
	if err := conn.WriteRuntimeTelemetryPayload(context.Background(), []byte(`{"late":true}`)); err != errManagerOutputClosed {
		t.Fatalf("late runtime telemetry write: got %v, want %v", err, errManagerOutputClosed)
	}
	if got := conn.DroppedLogRecords(managerv1.LogKind_LOG_KIND_JOB_DETECTION); got != 0 {
		t.Fatalf("closed detection writes counted as drops: got %d, want 0", got)
	}
}

func TestAttachRecordersForTesting(t *testing.T) {
	poster := &recordingLogBatchSender{}
	var conn ManagerJobLogs
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")

	conn.AttachDetectionRecorderForTesting(identity, jobcontext.ScopeKindProject, poster.sendBatch)
	conn.AttachRuntimeTelemetryRecorderForTesting(identity, jobcontext.ScopeKindProject, poster.sendBatch)

	if err := conn.WriteDetectionPayload(context.Background(), []byte(`{"kind":"detection"}`)); err != nil {
		t.Fatalf("write detection: %v", err)
	}
	if err := conn.WriteRuntimeTelemetryPayload(context.Background(), []byte(`{"kind":"telemetry"}`)); err != nil {
		t.Fatalf("write runtime telemetry: %v", err)
	}
	if err := conn.FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize streaming: %v", err)
	}
	if got := poster.count(); got != 2 {
		t.Fatalf("sent batches: got %d, want 2", got)
	}
}
