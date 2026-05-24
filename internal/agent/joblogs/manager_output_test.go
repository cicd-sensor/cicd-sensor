package joblogs

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
)

type recordingLogBatchSender struct {
	mu      sync.Mutex
	batches []managerclient.LogBatch
	err     error
}

func (s *recordingLogBatchSender) sendBatch(_ context.Context, batch managerclient.LogBatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.batches = append(s.batches, batch)
	return nil
}

func (s *recordingLogBatchSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.batches)
}

func TestNewManagerOutputNilSenderReturnsNil(t *testing.T) {
	t.Parallel()

	if got := testManagerOutput(nil, &managerv1.OutputSetting{}); got != nil {
		t.Fatalf("new manager output with nil sender: got %#v, want nil", got)
	}
}

func TestManagerOutput_EmptyPayloadIsIgnored(t *testing.T) {
	poster := &recordingLogBatchSender{}
	out := testManagerOutput(poster.sendBatch, &managerv1.OutputSetting{FlushThresholdBytes: 1})

	if err := out.Emit(context.Background(), nil); err != nil {
		t.Fatalf("emit nil payload: %v", err)
	}
	if err := out.Emit(context.Background(), []byte{}); err != nil {
		t.Fatalf("emit empty payload: %v", err)
	}
	if err := out.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := poster.count(); got != 0 {
		t.Fatalf("sent batches: got %d, want 0", got)
	}
}

func TestManagerOutput_FlushesOnFlushThresholdBytes(t *testing.T) {
	poster := &recordingLogBatchSender{}
	out := testManagerOutput(poster.sendBatch, &managerv1.OutputSetting{FlushThresholdBytes: 4})

	if err := out.Emit(context.Background(), []byte(`a`)); err != nil {
		t.Fatalf("emit first: %v", err)
	}
	if poster.count() != 0 {
		t.Fatalf("batches before threshold: got %d, want 0", poster.count())
	}
	if err := out.Emit(context.Background(), []byte(`b`)); err != nil {
		t.Fatalf("emit second: %v", err)
	}
	if err := out.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if poster.count() != 1 {
		t.Fatalf("batches after threshold: got %d, want 1", poster.count())
	}
}

func TestManagerOutput_FlushesBeforeFlushThresholdBytesWouldBeExceeded(t *testing.T) {
	poster := &recordingLogBatchSender{}
	out := testManagerOutput(poster.sendBatch, &managerv1.OutputSetting{FlushThresholdBytes: 16})

	if err := out.Emit(context.Background(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("emit first: %v", err)
	}
	if poster.count() != 0 {
		t.Fatalf("batches before byte threshold: got %d, want 0", poster.count())
	}
	if err := out.Emit(context.Background(), []byte(`{"n":2}`)); err != nil {
		t.Fatalf("emit second: %v", err)
	}
	if err := out.Emit(context.Background(), []byte(`{"n":3}`)); err != nil {
		t.Fatalf("emit third: %v", err)
	}
	if err := out.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := poster.count(); got != 2 {
		t.Fatalf("batches after byte threshold and close: got %d, want 2", got)
	}
	if got := len(poster.batches[0].Records); got != 2 {
		t.Fatalf("first batch records: got %d, want 2", got)
	}
	if got := len(poster.batches[1].Records); got != 1 {
		t.Fatalf("second batch records: got %d, want 1", got)
	}
}

func TestManagerOutput_CloseFlushesPendingRecords(t *testing.T) {
	poster := &recordingLogBatchSender{}
	out := testManagerOutput(poster.sendBatch, &managerv1.OutputSetting{})

	if err := out.Emit(context.Background(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if err := out.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if poster.count() != 1 {
		t.Fatalf("batches after close: got %d, want 1", poster.count())
	}
}

func TestManagerOutput_CloseReturnsFlushErrorAndStaysClosed(t *testing.T) {
	poster := &recordingLogBatchSender{err: errors.New("manager unavailable")}
	out := testManagerOutput(poster.sendBatch, &managerv1.OutputSetting{})

	if err := out.Emit(context.Background(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if err := out.Close(context.Background()); err == nil {
		t.Fatal("close: got nil, want send error")
	}
	if err := out.Emit(context.Background(), []byte(`{"n":2}`)); err != errManagerOutputClosed {
		t.Fatalf("emit after failed close: got %v, want %v", err, errManagerOutputClosed)
	}
	if got := poster.count(); got != 0 {
		t.Fatalf("sent successful batches: got %d, want 0", got)
	}
}

func TestManagerOutput_TimerFlushesPendingRecords(t *testing.T) {
	poster := &recordingLogBatchSender{}
	out := testManagerOutput(poster.sendBatch, &managerv1.OutputSetting{FlushIntervalSeconds: 1})

	if err := out.Emit(context.Background(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("emit: %v", err)
	}
	waitForBatchCount(t, poster, 1)
	if err := out.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestManagerOutput_EmitAndCloseFlushesFinalRecord(t *testing.T) {
	poster := &recordingLogBatchSender{}
	out := testManagerOutput(poster.sendBatch, &managerv1.OutputSetting{})

	if err := out.EmitAndClose(context.Background(), []byte(`{"final":true}`)); err != nil {
		t.Fatalf("emit and close: %v", err)
	}
	if poster.count() != 1 {
		t.Fatalf("batches after emit and close: got %d, want 1", poster.count())
	}
	if err := out.Emit(context.Background(), []byte(`{"late":true}`)); err != errManagerOutputClosed {
		t.Fatalf("emit after close: got %v, want %v", err, errManagerOutputClosed)
	}
}

func TestManagerOutput_CloseIsIdempotent(t *testing.T) {
	poster := &recordingLogBatchSender{}
	out := testManagerOutput(poster.sendBatch, &managerv1.OutputSetting{})

	if err := out.Close(context.Background()); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := out.Close(context.Background()); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestManagerOutput_SendsSequentially(t *testing.T) {
	poster := &blockingLogBatchSender{
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	out := testManagerOutput(poster.sendBatch, &managerv1.OutputSetting{FlushThresholdBytes: 1})

	if err := out.Emit(context.Background(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("emit first: %v", err)
	}
	select {
	case <-poster.entered:
	case <-time.After(time.Second):
		t.Fatal("first send did not start")
	}
	if err := out.Emit(context.Background(), []byte(`{"n":2}`)); err != nil {
		t.Fatalf("emit second: %v", err)
	}
	select {
	case <-poster.entered:
		t.Fatal("second send started before first send completed")
	case <-time.After(20 * time.Millisecond):
	}

	close(poster.release)
	if err := out.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := poster.count(); got != 2 {
		t.Fatalf("send count: got %d, want 2", got)
	}
}

func TestManagerOutput_StreamEmitReturnsBacklogFull(t *testing.T) {
	poster := &blockingLogBatchSender{
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	out := &managerOutput{
		requests: make(chan managerOutputRequest, 1),
		done:     make(chan struct{}),
	}
	go newManagerWorker(managerWorkerConfig{
		logger:    testLogger,
		sendBatch: poster.sendBatch,
		identity:  jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"),
		scope:     managerv1.Scope_SCOPE_HOST,
		logType:   managerv1.LogType_LOG_TYPE_DETECTION,
		setting:   &managerv1.OutputSetting{FlushThresholdBytes: 1},
	}).run(out.requests, out.done)

	if err := out.Emit(context.Background(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("emit first: %v", err)
	}
	select {
	case <-poster.entered:
	case <-time.After(time.Second):
		t.Fatal("first send did not start")
	}
	if err := out.Emit(context.Background(), []byte(`{"n":2}`)); err != nil {
		t.Fatalf("emit second: %v", err)
	}
	if err := out.Emit(context.Background(), []byte(`{"n":3}`)); err != errManagerOutputBacklogFull {
		t.Fatalf("emit third: got %v, want %v", err, errManagerOutputBacklogFull)
	}
	if got := out.droppedCount(); got != 1 {
		t.Fatalf("dropped records: got %d, want 1", got)
	}

	close(poster.release)
	if err := out.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func testManagerOutput(sendBatch func(context.Context, managerclient.LogBatch) error, setting *managerv1.OutputSetting) *managerOutput {
	return newManagerOutput(
		testLogger,
		sendBatch,
		jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"),
		jobcontext.ScopeTypeHost,
		managerv1.LogType_LOG_TYPE_DETECTION,
		setting,
	)
}

func waitForBatchCount(t *testing.T, poster *recordingLogBatchSender, want int) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if got := poster.count(); got == want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("batch count: got %d, want %d", poster.count(), want)
		case <-tick.C:
		}
	}
}

type blockingLogBatchSender struct {
	mu      sync.Mutex
	counted int
	entered chan struct{}
	release chan struct{}
}

func (s *blockingLogBatchSender) sendBatch(ctx context.Context, _ managerclient.LogBatch) error {
	s.mu.Lock()
	s.counted++
	s.mu.Unlock()
	s.entered <- struct{}{}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.release:
		return nil
	}
}

func (s *blockingLogBatchSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counted
}
