package sink

import (
	"context"
	"errors"
	"fmt"
	"path"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
)

type gcsSink struct {
	client *storage.Client
	bucket string
	prefix string
}

const (
	gcsImmediateFlushBytes   = 1
	gcsImmediateFlushSeconds = 1

	// Uncompressed JSONL threshold; see s3.go for the sizing rationale.
	gcsRuntimeEventFlushBytes   = 128 * 1024 * 1024
	gcsRuntimeEventFlushSeconds = 60
)

// NewGCS creates a GCS-backed Sink using Google Application Default
// Credentials. uri must be a gs:// URI; any path component becomes the
// object key prefix.
func NewGCS(ctx context.Context, uri string) (Sink, error) {
	bucket, prefix, err := parseObjectURI("gs", uri)
	if err != nil {
		return nil, fmt.Errorf("invalid gcs uri: %w", err)
	}
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create gcs client: %w", err)
	}
	return &gcsSink{
		client: client,
		bucket: bucket,
		prefix: prefix,
	}, nil
}

func (s *gcsSink) Write(ctx context.Context, batch IngestLogBatch) error {
	key, err := objectKey(batch)
	if err != nil {
		return err
	}
	fullKey := joinPrefix(s.prefix, key)
	writer := s.client.Bucket(s.bucket).Object(fullKey).NewWriter(ctx)
	writer.ContentType = ContentTypeGzip
	writer.ContentDisposition = `attachment; filename="` + path.Base(fullKey) + `"`
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
	return formatObjectURI("gs", s.bucket, s.prefix)
}

func (s *gcsSink) FlushPolicy(logKind logtype.LogType) FlushPolicy {
	switch logKind {
	case logtype.RuntimeEvent:
		return FlushPolicy{
			FlushThresholdBytes:  gcsRuntimeEventFlushBytes,
			FlushIntervalSeconds: gcsRuntimeEventFlushSeconds,
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
