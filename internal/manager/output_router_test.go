package manager

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	"github.com/cicd-sensor/cicd-sensor/internal/manager/sink"
	"github.com/cicd-sensor/cicd-sensor/internal/manager/sink/sinktest"
)

func TestOutputRouter_Write_HappyPath(t *testing.T) {
	dst := sinktest.New("primary")
	router := newOutputRouterForTest(map[logtype.LogType]sink.Sink{
		logtype.Detection: dst,
	})
	batch := routerTestBatch(logtype.Detection)

	if err := router.Write(context.Background(), batch); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := dst.Batches()
	if len(got) != 1 {
		t.Fatalf("batches: got %d, want 1", len(got))
	}
	if string(got[0].Body) != string(batch.Body) {
		t.Fatal("body changed")
	}
	if got[0].LogType != batch.LogType || got[0].Scope != batch.Scope {
		t.Fatalf("batch: got %+v, want %+v", got[0], batch)
	}
}

func TestOutputRouter_Write_KindNotConfigured(t *testing.T) {
	router := newOutputRouterForTest(map[logtype.LogType]sink.Sink{
		logtype.Summary: sinktest.New("result"),
	})
	err := router.Write(context.Background(), routerTestBatch(logtype.Detection))
	if !errors.Is(err, errNoCollectorSinks) {
		t.Fatalf("err: got %v, want no sinks", err)
	}
}

func TestOutputRouter_Write_NilReceiverReturnsErr(t *testing.T) {
	var router *OutputRouter
	err := router.Write(context.Background(), routerTestBatch(logtype.Detection))
	if !errors.Is(err, errNoCollectorSinks) {
		t.Fatalf("err: got %v, want no sinks", err)
	}
}

func TestOutputRouter_Write_ReturnsErrThrottled(t *testing.T) {
	dst := sinktest.New("bad")
	dst.SetErrors(sink.ErrThrottled, sink.ErrThrottled, sink.ErrThrottled)
	router := newOutputRouterForTest(map[logtype.LogType]sink.Sink{
		logtype.Detection: dst,
	})

	err := router.Write(context.Background(), routerTestBatch(logtype.Detection))
	if !errors.Is(err, sink.ErrThrottled) {
		t.Fatalf("err: got %v, want throttled", err)
	}
}

func TestOutputRouter_Write_RetrySleepContextCanceled(t *testing.T) {
	dst := sinktest.New("retry")
	dst.SetErrors(sink.ErrThrottled)
	router := newOutputRouterForTest(map[logtype.LogType]sink.Sink{
		logtype.Detection: dst,
	})
	ctx, cancel := context.WithCancel(context.Background())
	router.sleep = func(context.Context, time.Duration) error {
		cancel()
		return ctx.Err()
	}

	err := router.Write(ctx, routerTestBatch(logtype.Detection))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err: got %v, want context canceled", err)
	}
	if got := dst.Calls(); got != 1 {
		t.Fatalf("calls: got %d, want 1", got)
	}
}

func TestOutputRouter_Write_RetriesThrottledThenSucceeds(t *testing.T) {
	dst := sinktest.New("retry")
	dst.SetErrors(sink.ErrThrottled, nil)
	router := newOutputRouterForTest(map[logtype.LogType]sink.Sink{
		logtype.Detection: dst,
	})

	err := router.Write(context.Background(), routerTestBatch(logtype.Detection))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := dst.Calls(); got != 2 {
		t.Fatalf("calls: got %d, want 2", got)
	}
}

func TestOutputRouter_Write_ExhaustsRetriesOnPersistentThrottle(t *testing.T) {
	dst := sinktest.New("retry")
	dst.SetErrors(sink.ErrThrottled, sink.ErrThrottled, sink.ErrThrottled)
	router := newOutputRouterForTest(map[logtype.LogType]sink.Sink{
		logtype.Detection: dst,
	})

	err := router.Write(context.Background(), routerTestBatch(logtype.Detection))
	if !errors.Is(err, sink.ErrThrottled) {
		t.Fatalf("err: got %v, want throttled", err)
	}
	if got := dst.Calls(); got != outputRetryAttempts {
		t.Fatalf("calls: got %d, want %d", got, outputRetryAttempts)
	}
}

func TestOutputRouter_OutputSettings_UsesSinkFlushPolicy(t *testing.T) {
	detection := sinktest.New("detection")
	detection.SetFlushPolicy(sink.FlushPolicy{FlushThresholdBytes: 1, FlushIntervalSeconds: 1})
	runtimeEvent := sinktest.New("runtime_event")
	runtimeEvent.SetFlushPolicy(sink.FlushPolicy{FlushThresholdBytes: 4 * 1024 * 1024, FlushIntervalSeconds: 60})

	router := newOutputRouterForTest(map[logtype.LogType]sink.Sink{
		logtype.Detection:    detection,
		logtype.RuntimeEvent: runtimeEvent,
	})

	got := router.OutputSettings()
	if !got.GetDetectionLog().GetEnabled() ||
		got.GetDetectionLog().GetFlushThresholdBytes() != 1 ||
		got.GetDetectionLog().GetFlushIntervalSeconds() != 1 {
		t.Fatalf("detection output setting: got %+v", got.GetDetectionLog())
	}
	if !got.GetRuntimeEventLog().GetEnabled() ||
		got.GetRuntimeEventLog().GetFlushThresholdBytes() != 4*1024*1024 ||
		got.GetRuntimeEventLog().GetFlushIntervalSeconds() != 60 {
		t.Fatalf("runtime event output setting: got %+v", got.GetRuntimeEventLog())
	}
	if got.GetSummaryLog().GetEnabled() {
		t.Fatalf("result output setting: got enabled")
	}
}

func TestBuildOutputs_NoOutputReturnsNil(t *testing.T) {
	router, err := BuildOutputs(context.Background(), testLogger, nil, nil)
	if err != nil {
		t.Fatalf("build outputs: %v", err)
	}
	if router != nil {
		t.Fatalf("router: got %#v, want nil", router)
	}
}

func TestBuildOutputs_ClosesCreatedSinksOnBuildFailure(t *testing.T) {
	originalBuilder := buildSink
	created := sinktest.New("created")
	calls := 0
	buildSink = func(context.Context, *slog.Logger, SinkConfig) (sink.Sink, error) {
		calls++
		if calls == 1 {
			return created, nil
		}
		return nil, errors.New("boom")
	}
	t.Cleanup(func() { buildSink = originalBuilder })

	_, err := BuildOutputs(
		context.Background(),
		testLogger,
		SinksConfig{
			"first":  {Type: "gcs", URI: "gs://first"},
			"second": {Type: "gcs", URI: "gs://second"},
		},
		LogsConfig{
			"detection_log": {Sink: "first"},
		},
	)
	if err == nil {
		t.Fatal("expected build error")
	}
	if got := created.Closes(); got != 1 {
		t.Fatalf("created sink closes: got %d, want 1", got)
	}
}

func TestOutputRouter_CloseClosesSinksOnce(t *testing.T) {
	dst := sinktest.New("primary")
	router := newOutputRouterForTest(map[logtype.LogType]sink.Sink{
		logtype.Detection: dst,
	})

	if err := router.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := router.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if got := dst.Closes(); got != 1 {
		t.Fatalf("closes: got %d, want 1", got)
	}
}

func TestRetryDelay(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 1, want: outputRetryBaseDelay},
		{attempt: 2, want: outputRetryBaseDelay * 2},
		{attempt: 3, want: outputRetryMaxDelay},
	}
	for _, tt := range tests {
		if got := retryDelay(tt.attempt); got != tt.want {
			t.Fatalf("retryDelay(%d): got %s, want %s", tt.attempt, got, tt.want)
		}
	}
}

func newOutputRouterForTest(perKind map[logtype.LogType]sink.Sink) *OutputRouter {
	sinks := make([]sink.Sink, 0, len(perKind))
	for _, dst := range perKind {
		sinks = append(sinks, dst)
	}
	return &OutputRouter{
		logger:  testLogger,
		perKind: perKind,
		sinks:   sinks,
		sleep:   func(context.Context, time.Duration) error { return nil },
		jitter:  func(d time.Duration) time.Duration { return d },
	}
}

func routerTestBatch(logKind logtype.LogType) sink.IngestLogBatch {
	return sink.IngestLogBatch{
		LogType: logKind,
		Identity: jobcontext.GitHubJobIdentity(
			"github.com",
			"acme/example",
			"123",
			"build",
			"1",
			"runner-1",
		),
		Scope:      sink.ScopeHost,
		FlushAt:    fixtureFlushAtTime,
		ReceivedAt: time.Date(2026, 4, 26, 7, 0, 0, 0, time.UTC),
		Body:       []byte{0x1f, 0x8b},
	}
}
