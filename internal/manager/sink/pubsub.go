package sink

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"log/slog"

	"cloud.google.com/go/pubsub/v2"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
)

type pubsubSink struct {
	client    *pubsub.Client
	projectID string
	publisher *pubsub.Publisher
	topicName string
	logger    *slog.Logger
}

const (
	pubsubImmediateFlushBytes   = 1
	pubsubImmediateFlushSeconds = 1

	pubsubRuntimeEventFlushBytes   = 256 * 1024 // 256 KiB
	pubsubRuntimeEventFlushSeconds = 5
)

// NewPubSub creates a Pub/Sub-backed Sink using Google Application Default
// Credentials.
func NewPubSub(ctx context.Context, logger *slog.Logger, projectID, topicName string) (Sink, error) {
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
	// Wire-only gzip; does not reduce Pub/Sub billing.
	publisher.PublishSettings.EnableCompression = true
	// Block when the in-flight queue is full so we get backpressure
	// instead of unbounded memory growth on Pub/Sub slowdowns.
	publisher.PublishSettings.FlowControlSettings = pubsub.FlowControlSettings{
		MaxOutstandingMessages: 1000,
		MaxOutstandingBytes:    50 * 1024 * 1024,
		LimitExceededBehavior:  pubsub.FlowControlBlock,
	}
	return &pubsubSink{
		client:    client,
		projectID: projectID,
		publisher: publisher,
		topicName: topicName,
		logger:    logger.With("component", "pubsub_sink"),
	}, nil
}

// Write decompresses the gzipped JSONL batch and publishes one Pub/Sub
// message per record. Each publish is drained asynchronously and only
// warning-logged on failure: the SDK already retries transient errors,
// and FlowControlBlock provides backpressure when the queue fills.
func (s *pubsubSink) Write(ctx context.Context, batch IngestLogBatch) error {
	reader, err := gzip.NewReader(bytes.NewReader(batch.Body))
	if err != nil {
		return fmt.Errorf("decode pubsub batch: %w", err)
	}
	defer reader.Close()

	attrs := pubsubAttributes(batch)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		record := append([]byte(nil), line...)
		result := s.publisher.Publish(ctx, &pubsub.Message{
			Data:       record,
			Attributes: attrs,
		})
		go func() {
			if _, err := result.Get(ctx); err != nil {
				s.logger.WarnContext(ctx, "pubsub_publish_failed", "error", err)
			}
		}()
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan pubsub batch: %w", err)
	}
	return nil
}

func (s *pubsubSink) Close() error {
	s.publisher.Stop()
	return s.client.Close()
}

func pubsubAttributes(batch IngestLogBatch) map[string]string {
	return map[string]string{
		"content_type": "application/json",
		"flush_at":     formatFlushAt(batch.FlushAt),
		"log_type":     string(batch.LogType),
		"scope":        string(batch.Scope),
	}
}

func (s *pubsubSink) Name() string {
	return "pubsub://" + s.projectID + "/" + s.topicName
}

func (s *pubsubSink) FlushPolicy(logKind logtype.LogType) FlushPolicy {
	if logKind == logtype.RuntimeEvent {
		return FlushPolicy{
			FlushThresholdBytes:  pubsubRuntimeEventFlushBytes,
			FlushIntervalSeconds: pubsubRuntimeEventFlushSeconds,
		}
	}
	return FlushPolicy{
		FlushThresholdBytes:  pubsubImmediateFlushBytes,
		FlushIntervalSeconds: pubsubImmediateFlushSeconds,
	}
}
