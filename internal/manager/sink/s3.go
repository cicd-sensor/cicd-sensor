package sink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
)

type s3Sink struct {
	client *s3.Client
	bucket string
	prefix string
}

const (
	s3ImmediateFlushBytes   = 1
	s3ImmediateFlushSeconds = 1

	// Uncompressed JSONL threshold. Gzip on the agent typically shrinks
	// runtime event ~25-30x, so 128 MiB lands around 4-5 MB per S3
	// object — large enough to keep the bucket listing readable while
	// staying well under managerMaxRequestBytes (16 MiB compressed).
	s3RuntimeEventFlushBytes   = 128 * 1024 * 1024
	s3RuntimeEventFlushSeconds = 60
)

// NewS3 creates an S3-backed Sink using the AWS default credential chain.
// uri must be an s3:// URI; any path component becomes the object key prefix.
func NewS3(ctx context.Context, uri, region string) (Sink, error) {
	bucket, prefix, err := parseObjectURI("s3", uri)
	if err != nil {
		return nil, fmt.Errorf("invalid s3 uri: %w", err)
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
		prefix: prefix,
	}, nil
}

func (s *s3Sink) Write(ctx context.Context, batch IngestLogBatch) error {
	key, err := objectKey(batch)
	if err != nil {
		return err
	}
	fullKey := joinPrefix(s.prefix, key)
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:             aws.String(s.bucket),
		Key:                aws.String(fullKey),
		Body:               bytes.NewReader(batch.Body),
		ContentType:        aws.String(ContentTypeGzip),
		ContentDisposition: aws.String(`attachment; filename="` + path.Base(fullKey) + `"`),
		Metadata:           map[string]string{"flush_at": formatFlushAt(batch.FlushAt)},
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
	return formatObjectURI("s3", s.bucket, s.prefix)
}

func (s *s3Sink) FlushPolicy(logKind logtype.LogType) FlushPolicy {
	switch logKind {
	case logtype.RuntimeEvent:
		return FlushPolicy{
			FlushThresholdBytes:  s3RuntimeEventFlushBytes,
			FlushIntervalSeconds: s3RuntimeEventFlushSeconds,
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
