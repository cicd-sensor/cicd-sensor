package manager

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	"github.com/cicd-sensor/cicd-sensor/internal/manager/sink"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
)

const (
	outputRetryAttempts   = 3
	outputRetryBaseDelay  = 500 * time.Millisecond
	outputRetryMaxDelay   = 2 * time.Second
	outputRetryJitterFrac = 0.30
)

var errNoCollectorSinks = errors.New("collector sinks are not configured")

// OutputRouter owns the manager sinks selected by manager.yaml log routing.
type OutputRouter struct {
	logger  *slog.Logger
	perKind map[logtype.LogType]sink.Sink
	sinks   []sink.Sink

	sleep  func(context.Context, time.Duration) error
	jitter func(time.Duration) time.Duration
}

var buildSink = buildNamedSink

// BuildOutputs wires validated startup config into per-log-kind routing.
// Returning nil means the manager accepts no collector ingest destination.
func BuildOutputs(ctx context.Context, logger *slog.Logger, sinks SinksConfig, logs LogsConfig) (*OutputRouter, error) {
	if len(logs) == 0 {
		return nil, nil
	}

	namedSinks := make(map[string]sink.Sink, len(sinks))
	createdSinks := make([]sink.Sink, 0, len(sinks))
	for name, sc := range sinks {
		dst, err := buildSink(ctx, logger, sc)
		if err != nil {
			if closeErr := closeSinks(createdSinks); closeErr != nil {
				return nil, fmt.Errorf("build sink %s: %w (cleanup: %v)", name, err, closeErr)
			}
			return nil, fmt.Errorf("build sink %s: %w", name, err)
		}
		namedSinks[name] = dst
		createdSinks = append(createdSinks, dst)
	}

	perKind := make(map[logtype.LogType]sink.Sink, len(logs))
	for logName, logOutput := range logs {
		logKind, ok := logtype.Parse(logName)
		if !ok {
			if closeErr := closeSinks(createdSinks); closeErr != nil {
				return nil, fmt.Errorf("unknown log type %q (cleanup: %v)", logName, closeErr)
			}
			return nil, fmt.Errorf("unknown log type %q", logName)
		}
		dst, ok := namedSinks[logOutput.Sink]
		if !ok {
			if closeErr := closeSinks(createdSinks); closeErr != nil {
				return nil, fmt.Errorf("logs.%s.sink %q is not a defined sink name (cleanup: %v)", logName, logOutput.Sink, closeErr)
			}
			return nil, fmt.Errorf("logs.%s.sink %q is not a defined sink name", logName, logOutput.Sink)
		}
		perKind[logKind] = dst
	}
	if len(perKind) == 0 {
		if closeErr := closeSinks(createdSinks); closeErr != nil {
			return nil, closeErr
		}
		return nil, nil
	}
	return &OutputRouter{
		logger:  logger.With("component", "output_router"),
		perKind: perKind,
		sinks:   createdSinks,
		sleep:   sleepContext,
		jitter:  jitterDelay,
	}, nil
}

func buildNamedSink(ctx context.Context, logger *slog.Logger, sc SinkConfig) (sink.Sink, error) {
	switch sc.Type {
	case "aws_s3":
		return sink.NewS3(ctx, sc.URI, sc.Region, sc.UsePathStyle)
	case "google_storage":
		return sink.NewGCS(ctx, sc.URI)
	case "google_pubsub":
		return sink.NewPubSub(ctx, logger, sc.ProjectID, sc.Topic)
	default:
		return nil, fmt.Errorf("unknown sink type %q", sc.Type)
	}
}

// OutputSettings exposes manager-owned batching policy to agents.
func (r *OutputRouter) OutputSettings() *managerv1beta1.OutputSettings {
	if r == nil || len(r.perKind) == 0 {
		return nil
	}
	return &managerv1beta1.OutputSettings{
		Detection:    r.outputSetting(logtype.Detection),
		RuntimeEvent: r.outputSetting(logtype.RuntimeEvent),
		Summary:      r.outputSetting(logtype.Summary),
	}
}

func (r *OutputRouter) outputSetting(logKind logtype.LogType) *managerv1beta1.OutputSetting {
	dst := r.perKind[logKind]
	if dst == nil {
		return &managerv1beta1.OutputSetting{}
	}
	policy := dst.FlushPolicy(logKind)
	return &managerv1beta1.OutputSetting{
		Enabled:              true,
		FlushThresholdBytes:  policy.FlushThresholdBytes,
		FlushIntervalSeconds: policy.FlushIntervalSeconds,
	}
}

// Write sends one validated batch to the sink configured for its log type.
func (r *OutputRouter) Write(ctx context.Context, batch sink.IngestLogBatch) error {
	if r == nil {
		return errNoCollectorSinks
	}
	dst := r.perKind[batch.LogType]
	if dst == nil {
		return errNoCollectorSinks
	}
	return r.writeWithRetry(ctx, dst, batch)
}

func (r *OutputRouter) writeWithRetry(ctx context.Context, dst sink.Sink, batch sink.IngestLogBatch) error {
	startedAt := time.Now()
	var lastErr error
	for attempt := 1; attempt <= outputRetryAttempts; attempt++ {
		if r.logger != nil {
			r.logger.InfoContext(ctx, "manager_object_upload_started",
				"destination", dst.Name(),
				"attempt", attempt,
			)
		}
		err := dst.Write(ctx, batch)
		if err == nil {
			if r.logger != nil {
				r.logger.InfoContext(ctx, "manager_object_upload_succeeded",
					"destination", dst.Name(),
					"attempt", attempt,
					"duration_ms", time.Since(startedAt).Milliseconds(),
				)
			}
			return nil
		}
		lastErr = err
		// Only provider throttling is retried here. Other errors are usually
		// auth/config/data-shape problems and should surface immediately.
		if !errors.Is(err, sink.ErrThrottled) || attempt == outputRetryAttempts {
			break
		}
		if sleepErr := r.sleep(ctx, r.jitter(retryDelay(attempt))); sleepErr != nil {
			return fmt.Errorf("retry wait for sink %s: %w", dst.Name(), sleepErr)
		}
	}
	if r.logger != nil {
		r.logger.ErrorContext(ctx, "manager_object_upload_failed",
			"destination", dst.Name(),
			"error", lastErr,
			"throttled", errors.Is(lastErr, sink.ErrThrottled),
			"duration_ms", time.Since(startedAt).Milliseconds(),
		)
	}
	return fmt.Errorf("write sink %s: %w", dst.Name(), lastErr)
}

func (r *OutputRouter) Close() error {
	if r == nil {
		return nil
	}
	sinks := r.sinks
	r.sinks = nil
	return closeSinks(sinks)
}

func closeSinks(sinks []sink.Sink) error {
	var errs []error
	for _, dst := range sinks {
		if dst == nil {
			continue
		}
		if err := dst.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close sink %s: %w", dst.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func retryDelay(attempt int) time.Duration {
	delay := outputRetryBaseDelay
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= outputRetryMaxDelay {
			return outputRetryMaxDelay
		}
	}
	return delay
}

func jitterDelay(delay time.Duration) time.Duration {
	// Jitter avoids synchronized retries when many agents flush at once.
	jitter := 1 - outputRetryJitterFrac + rand.Float64()*outputRetryJitterFrac*2
	return time.Duration(float64(delay) * jitter)
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
