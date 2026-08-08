package joblogs

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
)

var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestStartJobLogsAddsManagerDestination(t *testing.T) {
	poster := &recordingLogBatchSender{}
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	settings := &managerv1beta1.OutputSettings{
		Detection: &managerv1beta1.OutputSetting{Enabled: true},
	}

	conn := newManagerJobLogsWithSender(testLogger, poster.sendBatch, identity, jobcontext.ScopeTypeHost, settings)
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

func TestStartJobLogsIgnoresDisabledType(t *testing.T) {
	poster := &recordingLogBatchSender{}
	identity := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	settings := &managerv1beta1.OutputSettings{}

	conn := newManagerJobLogsWithSender(testLogger, poster.sendBatch, identity, jobcontext.ScopeTypeHost, settings)
	if conn.detection != nil {
		t.Fatalf("manager output added for disabled log: %T", conn.detection)
	}
}

func TestStartJobLogsDoesNotCreateSenderWithoutEnabledLogs(t *testing.T) {
	conn := NewManagerJobLogs(ManagerJobLogsConfig{
		Logger:         testLogger,
		Connection:     managerclient.Connection{BaseURL: "http://127.0.0.1:1", Token: "sk_csensor_testtoken"},
		Identity:       jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"),
		Type:           jobcontext.ScopeTypeHost,
		OutputSettings: &managerv1beta1.OutputSettings{},
	})

	if conn.sendBatch != nil {
		t.Fatal("manager sender created even though no log type is enabled")
	}
}

func TestStartJobLogsDoesNotCreateSenderWithoutManagerCredentials(t *testing.T) {
	conn := NewManagerJobLogs(ManagerJobLogsConfig{
		Logger:     testLogger,
		Connection: managerclient.Connection{},
		Identity:   jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"),
		Type:       jobcontext.ScopeTypeHost,
		OutputSettings: &managerv1beta1.OutputSettings{
			Detection: &managerv1beta1.OutputSetting{Enabled: true},
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
		jobcontext.ScopeTypeHost,
		&managerv1beta1.OutputSettings{
			Detection: &managerv1beta1.OutputSetting{Enabled: true},
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

func TestManagerJobLogsNoOpWhenLogTypesAreNotConfigured(t *testing.T) {
	var conn ManagerJobLogs

	if err := conn.WriteDetectionPayload(context.Background(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("detection write without output: %v", err)
	}
	if err := conn.WriteRuntimeEventPayload(context.Background(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("runtime event write without output: %v", err)
	}
	if err := conn.EmitAndCloseSummaryLog(context.Background(), []byte(`{"final":true}`)); err != nil {
		t.Fatalf("summary write without output: %v", err)
	}
	if conn.HasSummaryLog() {
		t.Fatal("summary log reported configured on zero ManagerJobLogs")
	}
	if got := conn.DroppedLogRecords(managerv1beta1.LogType_LOG_TYPE_DETECTION); got != 0 {
		t.Fatalf("dropped records on zero ManagerJobLogs: got %d, want 0", got)
	}
	if got := conn.DroppedLogRecords(managerv1beta1.LogType_LOG_TYPE_UNSPECIFIED); got != 0 {
		t.Fatalf("dropped records for unknown log type: got %d, want 0", got)
	}
	if err := conn.FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize zero ManagerJobLogs: %v", err)
	}
}

func TestStartJobLogsUsesOneWorkerPerType(t *testing.T) {
	poster := &recordingLogBatchSender{}
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	settings := &managerv1beta1.OutputSettings{
		Detection:    &managerv1beta1.OutputSetting{Enabled: true},
		RuntimeEvent: &managerv1beta1.OutputSetting{Enabled: true},
		Summary:      &managerv1beta1.OutputSetting{Enabled: true},
	}

	conn := newManagerJobLogsWithSender(testLogger, poster.sendBatch, identity, jobcontext.ScopeTypeHost, settings)
	if conn.detection == nil || conn.runtimeEvent == nil || conn.summaryLog == nil {
		t.Fatal("expected detection, runtime event, and summary workers")
	}
	if conn.detection.requests == conn.runtimeEvent.requests {
		t.Fatal("detection and runtime event must use separate workers")
	}
	if conn.detection.requests == conn.summaryLog.requests {
		t.Fatal("detection and summary must use separate workers")
	}
	if got := cap(conn.runtimeEvent.requests); got != runtimeEventManagerOutputChannelCap {
		t.Fatalf("runtime event output channel cap: got %d, want %d", got, runtimeEventManagerOutputChannelCap)
	}
	if got := cap(conn.detection.requests); got != managerOutputChannelCap {
		t.Fatalf("detection output channel cap: got %d, want %d", got, managerOutputChannelCap)
	}
	if got := cap(conn.summaryLog.requests); got != managerOutputChannelCap {
		t.Fatalf("summary output channel cap: got %d, want %d", got, managerOutputChannelCap)
	}
}

func TestManagerJobLogsEmitAndCloseSummaryLog(t *testing.T) {
	poster := &recordingLogBatchSender{}
	conn := newManagerJobLogsWithSender(testLogger, poster.sendBatch,
		jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"),
		jobcontext.ScopeTypeProject,
		&managerv1beta1.OutputSettings{
			Summary: &managerv1beta1.OutputSetting{Enabled: true},
		},
	)

	if !conn.HasSummaryLog() {
		t.Fatal("expected summary log to be configured")
	}
	if err := conn.EmitAndCloseSummaryLog(context.Background(), []byte(`{"final":true}`)); err != nil {
		t.Fatalf("emit summary log: %v", err)
	}
	if got := poster.count(); got != 1 {
		t.Fatalf("sent batches: got %d, want 1", got)
	}
	if got := conn.DroppedLogRecords(managerv1beta1.LogType_LOG_TYPE_SUMMARY); got != 0 {
		t.Fatalf("summary drops: got %d, want 0", got)
	}
}

func TestManagerJobLogsFlushStreamingLogsSendsBufferedRecords(t *testing.T) {
	poster := &recordingLogBatchSender{}
	conn := newManagerJobLogsWithSender(testLogger, poster.sendBatch,
		jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"),
		jobcontext.ScopeTypeProject,
		&managerv1beta1.OutputSettings{
			Detection:    &managerv1beta1.OutputSetting{Enabled: true},
			RuntimeEvent: &managerv1beta1.OutputSetting{Enabled: true},
		},
	)

	if err := conn.WriteDetectionPayload(context.Background(), []byte(`{"type":"detection"}`)); err != nil {
		t.Fatalf("write detection: %v", err)
	}
	if err := conn.WriteRuntimeEventPayload(context.Background(), []byte(`{"type":"runtime_event"}`)); err != nil {
		t.Fatalf("write runtime event: %v", err)
	}
	if err := conn.FlushStreamingLogs(context.Background()); err != nil {
		t.Fatalf("flush streaming: %v", err)
	}
	if got := poster.count(); got != 2 {
		t.Fatalf("batches after flush: got %d, want 2", got)
	}
	// Workers stay open: later records still deliver at finalize.
	if err := conn.WriteRuntimeEventPayload(context.Background(), []byte(`{"type":"runtime_event_late"}`)); err != nil {
		t.Fatalf("write runtime event after flush: %v", err)
	}
	if err := conn.FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize streaming: %v", err)
	}
	if got := poster.count(); got != 3 {
		t.Fatalf("batches after finalize: got %d, want 3", got)
	}
}

func TestManagerJobLogsFlushStreamingLogsWithoutWorkersIsNoOp(t *testing.T) {
	var conn ManagerJobLogs

	if err := conn.FlushStreamingLogs(context.Background()); err != nil {
		t.Fatalf("flush without workers: %v", err)
	}
}

func TestManagerJobLogsRejectsStreamingWritesAfterFinalize(t *testing.T) {
	poster := &recordingLogBatchSender{}
	conn := newManagerJobLogsWithSender(testLogger, poster.sendBatch,
		jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"),
		jobcontext.ScopeTypeHost,
		&managerv1beta1.OutputSettings{
			Detection:    &managerv1beta1.OutputSetting{Enabled: true},
			RuntimeEvent: &managerv1beta1.OutputSetting{Enabled: true},
		},
	)

	if err := conn.FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize streaming: %v", err)
	}
	if err := conn.WriteDetectionPayload(context.Background(), []byte(`{"late":true}`)); err != errManagerOutputClosed {
		t.Fatalf("late detection write: got %v, want %v", err, errManagerOutputClosed)
	}
	if err := conn.WriteRuntimeEventPayload(context.Background(), []byte(`{"late":true}`)); err != errManagerOutputClosed {
		t.Fatalf("late runtime event write: got %v, want %v", err, errManagerOutputClosed)
	}
	if got := conn.DroppedLogRecords(managerv1beta1.LogType_LOG_TYPE_DETECTION); got != 0 {
		t.Fatalf("closed detection writes counted as drops: got %d, want 0", got)
	}
}

func TestAttachRecordersForTesting(t *testing.T) {
	poster := &recordingLogBatchSender{}
	var conn ManagerJobLogs
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")

	conn.AttachDetectionRecorderForTesting(identity, jobcontext.ScopeTypeProject, poster.sendBatch)
	conn.AttachRuntimeEventRecorderForTesting(identity, jobcontext.ScopeTypeProject, poster.sendBatch)

	if err := conn.WriteDetectionPayload(context.Background(), []byte(`{"type":"detection"}`)); err != nil {
		t.Fatalf("write detection: %v", err)
	}
	if err := conn.WriteRuntimeEventPayload(context.Background(), []byte(`{"type":"runtime_event"}`)); err != nil {
		t.Fatalf("write runtime event: %v", err)
	}
	if err := conn.FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize streaming: %v", err)
	}
	if got := poster.count(); got != 2 {
		t.Fatalf("sent batches: got %d, want 2", got)
	}
}

func TestManagerJobLogsFinalizeStreamingLogsClosesWorkersInParallel(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	blockingSend := func(ctx context.Context, _ managerclient.LogBatch) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	poster := &recordingLogBatchSender{}
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	var conn ManagerJobLogs
	conn.AttachDetectionRecorderForTesting(identity, jobcontext.ScopeTypeProject, blockingSend)
	conn.AttachRuntimeEventRecorderForTesting(identity, jobcontext.ScopeTypeProject, poster.sendBatch)

	if err := conn.WriteDetectionPayload(context.Background(), []byte(`{"type":"detection"}`)); err != nil {
		t.Fatalf("write detection: %v", err)
	}
	<-entered
	if err := conn.WriteRuntimeEventPayload(context.Background(), []byte(`{"type":"runtime_event"}`)); err != nil {
		t.Fatalf("write runtime event: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- conn.FinalizeStreamingLogs(context.Background()) }()

	// While the detection worker is blocked in its send, the runtime event
	// close must still drain: the closes run in parallel.
	waitForBatchCount(t, poster, 1)

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("finalize streaming: %v", err)
	}
}
