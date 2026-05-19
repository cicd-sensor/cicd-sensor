package sink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

type s3Sink struct {
	client *s3.Client
	bucket string
	prefix string
}

const (
	s3ImmediateFlushBytes   = 1
	s3ImmediateFlushSeconds = 1

	s3RuntimeTelemetryFlushBytes   = 4 * 1024 * 1024 // 4 MiB
	s3RuntimeTelemetryFlushSeconds = 60
)

// NewS3 creates an S3-backed Sink using the AWS default credential chain.
func NewS3(ctx context.Context, bucket, region, prefix string) (Sink, error) {
	bucket, normalizedPrefix, err := normalizeObjectLocation("s3", bucket, prefix)
	if err != nil {
		return nil, fmt.Errorf("invalid s3 location: %w", err)
	}
	opts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &s3Sink{
		client: s3.NewFromConfig(cfg),
		bucket: bucket,
		prefix: normalizedPrefix,
	}, nil
}

func (s *s3Sink) Write(ctx context.Context, batch IngestLogBatch) error {
	key, err := objectKey(batch)
	if err != nil {
		return err
	}
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          aws.String(s.bucket),
		Key:             aws.String(joinPrefix(s.prefix, key)),
		Body:            bytes.NewReader(batch.Body),
		ContentType:     aws.String(ContentTypeJSONL),
		ContentEncoding: aws.String(ContentEncoding),
		Metadata:        map[string]string{"flush_at": formatFlushAt(batch.FlushAt)},
	})
	if err != nil {
		if isS3Throttle(err) {
			return fmt.Errorf("%w: %v", ErrThrottled, err)
		}
		return fmt.Errorf("put s3 object: %w", err)
	}
	return nil
}

func (s *s3Sink) Close() error {
	return nil
}

func (s *s3Sink) Name() string {
	name := "s3://" + s.bucket
	if s.prefix != "" {
		name += "/" + s.prefix
	}
	return name
}

func (s *s3Sink) FlushPolicy(logKind LogKind) FlushPolicy {
	switch logKind {
	case LogKindJobRuntimeTelemetry:
		return FlushPolicy{
			FlushThresholdBytes:  s3RuntimeTelemetryFlushBytes,
			FlushIntervalSeconds: s3RuntimeTelemetryFlushSeconds,
		}
	default:
		return FlushPolicy{
			FlushThresholdBytes:  s3ImmediateFlushBytes,
			FlushIntervalSeconds: s3ImmediateFlushSeconds,
		}
	}
}

func isS3Throttle(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "RequestThrottled", "RequestLimitExceeded", "SlowDown", "Throttling", "ThrottlingException", "TooManyRequestsException":
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "throttl") || strings.Contains(msg, "slowdown")
}
