package sink

import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
)

type gcsSink struct {
	client *storage.Client
	bucket string
	prefix string
}

const (
	gcsImmediateFlushBytes   = 1
	gcsImmediateFlushSeconds = 1

	gcsRuntimeTelemetryFlushBytes   = 4 * 1024 * 1024 // 4 MiB
	gcsRuntimeTelemetryFlushSeconds = 60
)

// NewGCS creates a GCS-backed Sink using Google Application Default
// Credentials.
func NewGCS(ctx context.Context, bucket, prefix string) (Sink, error) {
	bucket, normalizedPrefix, err := normalizeObjectLocation("gs", bucket, prefix)
	if err != nil {
		return nil, fmt.Errorf("invalid gcs location: %w", err)
	}
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create gcs client: %w", err)
	}
	return &gcsSink{
		client: client,
		bucket: bucket,
		prefix: normalizedPrefix,
	}, nil
}

func (s *gcsSink) Write(ctx context.Context, batch IngestLogBatch) error {
	key, err := objectKey(batch)
	if err != nil {
		return err
	}
	writer := s.client.Bucket(s.bucket).Object(joinPrefix(s.prefix, key)).NewWriter(ctx)
	writer.ContentType = ContentTypeJSONL
	writer.ContentEncoding = ContentEncoding
	writer.Metadata = map[string]string{"flush_at": formatFlushAt(batch.FlushAt)}
	if _, err := writer.Write(batch.Body); err != nil {
		_ = writer.Close()
		if isGCSThrottle(err) {
			return fmt.Errorf("%w: %v", ErrThrottled, err)
		}
		return fmt.Errorf("write gcs object: %w", err)
	}
	if err := writer.Close(); err != nil {
		if isGCSThrottle(err) {
			return fmt.Errorf("%w: %v", ErrThrottled, err)
		}
		return fmt.Errorf("close gcs object writer: %w", err)
	}
	return nil
}

func (s *gcsSink) Close() error {
	return s.client.Close()
}

func (s *gcsSink) Name() string {
	name := "gs://" + s.bucket
	if s.prefix != "" {
		name += "/" + s.prefix
	}
	return name
}

func (s *gcsSink) FlushPolicy(logKind LogKind) FlushPolicy {
	switch logKind {
	case LogKindJobRuntimeTelemetry:
		return FlushPolicy{
			FlushThresholdBytes:  gcsRuntimeTelemetryFlushBytes,
			FlushIntervalSeconds: gcsRuntimeTelemetryFlushSeconds,
		}
	default:
		return FlushPolicy{
			FlushThresholdBytes:  gcsImmediateFlushBytes,
			FlushIntervalSeconds: gcsImmediateFlushSeconds,
		}
	}
}

func isGCSThrottle(err error) bool {
	var apiErr *googleapi.Error
	return errors.As(err, &apiErr) && apiErr.Code == 429
}
