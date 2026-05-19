package sink

import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/pubsub/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type pubsubSink struct {
	client    *pubsub.Client
	projectID string
	publisher *pubsub.Publisher
	topicName string
}

const (
	pubsubImmediateFlushBytes   = 1
	pubsubImmediateFlushSeconds = 1

	pubsubRuntimeTelemetryFlushBytes   = 256 * 1024 // 256 KiB
	pubsubRuntimeTelemetryFlushSeconds = 5
)

// NewPubSub creates a Pub/Sub-backed Sink using Google Application Default
// Credentials.
func NewPubSub(ctx context.Context, projectID, topicName string) (Sink, error) {
	if projectID == "" {
		return nil, fmt.Errorf("pubsub project_id is required")
	}
	if topicName == "" {
		return nil, fmt.Errorf("pubsub topic is required")
	}
	client, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("create pubsub client: %w", err)
	}
	publisher := client.Publisher(topicName)
	return &pubsubSink{
		client:    client,
		projectID: projectID,
		publisher: publisher,
		topicName: topicName,
	}, nil
}

func (s *pubsubSink) Write(ctx context.Context, batch IngestLogBatch) error {
	result := s.publisher.Publish(ctx, &pubsub.Message{
		Data:       batch.Body,
		Attributes: pubsubAttributes(batch),
	})
	if _, err := result.Get(ctx); err != nil {
		if isPubSubThrottle(err) {
			return fmt.Errorf("%w: %v", ErrThrottled, err)
		}
		return fmt.Errorf("publish pubsub message: %w", err)
	}
	return nil
}

func (s *pubsubSink) Close() error {
	s.publisher.Stop()
	return s.client.Close()
}

func pubsubAttributes(batch IngestLogBatch) map[string]string {
	return map[string]string{
		"content_encoding": ContentEncoding,
		"content_type":     ContentTypeJSONL,
		"flush_at":         formatFlushAt(batch.FlushAt),
		"log_kind":         string(batch.LogKind),
		"scope":            string(batch.Scope),
	}
}

func (s *pubsubSink) Name() string {
	return "pubsub://" + s.projectID + "/" + s.topicName
}

func (s *pubsubSink) FlushPolicy(logKind LogKind) FlushPolicy {
	if logKind == LogKindJobRuntimeTelemetry {
		return FlushPolicy{
			FlushThresholdBytes:  pubsubRuntimeTelemetryFlushBytes,
			FlushIntervalSeconds: pubsubRuntimeTelemetryFlushSeconds,
		}
	}
	return FlushPolicy{
		FlushThresholdBytes:  pubsubImmediateFlushBytes,
		FlushIntervalSeconds: pubsubImmediateFlushSeconds,
	}
}

func isPubSubThrottle(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return status.Code(err) == codes.ResourceExhausted
}
