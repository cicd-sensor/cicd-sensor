package manager

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	"github.com/cicd-sensor/cicd-sensor/internal/manager/sink"
	"github.com/cicd-sensor/cicd-sensor/internal/manager/sink/sinktest"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1/managerv1connect"
)

var (
	fixtureFlushAtTime = time.Date(2026, 4, 26, 7, 30, 45, 123_000_000, time.UTC)
	fixtureFlushAt     = timestamppb.New(fixtureFlushAtTime)
)

func TestCollectorService_IngestLog(t *testing.T) {
	payload := gzipPayload(t, `{"message":"hello"}`+"\n")
	validIdentity := &managerv1.JobIdentity{
		Provider:               "github",
		ProviderHost:           "github.com",
		ProjectPath:            "acme/example",
		GithubRunId:            "123",
		GithubJob:              "build",
		GithubRunAttempt:       "1",
		GithubRunnerTrackingId: "runner-1",
	}
	unsupportedProviderIdentity := proto.Clone(validIdentity).(*managerv1.JobIdentity)
	unsupportedProviderIdentity.Provider = "bitbucket"
	emptyProviderIdentity := proto.Clone(validIdentity).(*managerv1.JobIdentity)
	emptyProviderIdentity.Provider = ""
	badFlushAtNil := validIngestLogBatch(validIdentity, payload)
	badFlushAtNil.FlushAt = nil
	badFlushAtBeforeRange := validIngestLogBatch(validIdentity, payload)
	badFlushAtBeforeRange.FlushAt = timestamppb.New(time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC))
	badFlushAtAfterRange := validIngestLogBatch(validIdentity, payload)
	badFlushAtAfterRange.FlushAt = timestamppb.New(time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC))
	badFlushAtInvalidProto := validIngestLogBatch(validIdentity, payload)
	badFlushAtInvalidProto.FlushAt = &timestamppb.Timestamp{Seconds: -1, Nanos: -1}
	unsupportedLogType := validIngestLogBatch(validIdentity, payload)
	unsupportedLogType.LogType = managerv1.LogType_LOG_TYPE_UNSPECIFIED
	unsupportedScope := validIngestLogBatch(validIdentity, payload)
	unsupportedScope.Scope = managerv1.Scope_SCOPE_UNSPECIFIED

	tests := []struct {
		name     string
		sink     *sinktest.Sink
		batch    *managerv1.IngestLogBatch
		wantCode connect.Code
	}{
		{
			name:  "configured sink writes opaque gzip bytes",
			sink:  sinktest.New("primary"),
			batch: validIngestLogBatch(validIdentity, payload),
		},
		{
			name:     "nil batch returns invalid_argument",
			sink:     sinktest.New("primary"),
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "invalid gzip magic is rejected before output",
			sink:     sinktest.New("primary"),
			batch:    validIngestLogBatch(validIdentity, []byte("not gzip")),
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "missing sinks fails closed",
			batch:    validIngestLogBatch(validIdentity, payload),
			wantCode: connect.CodeFailedPrecondition,
		},
		{
			name:     "flush_at is required",
			sink:     sinktest.New("primary"),
			batch:    badFlushAtNil,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "flush_at year must not be before range",
			sink:     sinktest.New("primary"),
			batch:    badFlushAtBeforeRange,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "flush_at year must not be after range",
			sink:     sinktest.New("primary"),
			batch:    badFlushAtAfterRange,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "flush_at must be a valid proto timestamp",
			sink:     sinktest.New("primary"),
			batch:    badFlushAtInvalidProto,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "unsupported log type returns invalid_argument",
			sink:     sinktest.New("primary"),
			batch:    unsupportedLogType,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "unsupported scope returns invalid_argument",
			sink:     sinktest.New("primary"),
			batch:    unsupportedScope,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "unsupported provider returns invalid_argument",
			sink:     sinktest.New("primary"),
			batch:    validIngestLogBatch(unsupportedProviderIdentity, payload),
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "empty provider returns invalid_argument",
			sink:     sinktest.New("primary"),
			batch:    validIngestLogBatch(emptyProviderIdentity, payload),
			wantCode: connect.CodeInvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := callCollector(t, tt.sink, tt.batch)
			if tt.wantCode != 0 {
				if err == nil {
					t.Fatalf("expected code %v, got nil", tt.wantCode)
				}
				if got := connect.CodeOf(err); got != tt.wantCode {
					t.Fatalf("code: got %v, want %v (err=%v)", got, tt.wantCode, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ingest: %v", err)
			}
			if resp.Msg.ReceivedBatches != 1 {
				t.Fatalf("received_batches: got %d, want 1", resp.Msg.ReceivedBatches)
			}
			if resp.Msg.BytesWritten != uint64(len(tt.batch.CompressedJsonl)) {
				t.Fatalf("bytes_written: got %d, want %d", resp.Msg.BytesWritten, len(tt.batch.CompressedJsonl))
			}
			batches := tt.sink.Batches()
			if len(batches) != 1 {
				t.Fatalf("%s batches: got %d, want 1", tt.sink.Name(), len(batches))
			}
			batch := batches[0]
			if batch.LogType != logtype.Detection {
				t.Fatalf("log type: got %q, want detection", batch.LogType)
			}
			if batch.Scope != sink.ScopeHost {
				t.Fatalf("scope: got %q, want host", batch.Scope)
			}
			if !batch.FlushAt.Equal(fixtureFlushAtTime) {
				t.Fatalf("flush_at: got %s, want %s", batch.FlushAt, fixtureFlushAtTime)
			}
			if !bytes.Equal(batch.Body, payload) {
				t.Fatalf("body changed in transit")
			}
		})
	}
}

func TestCollectorService_IngestMapsSinkFailures(t *testing.T) {
	payload := gzipPayload(t, `{"message":"hello"}`+"\n")
	identity := &managerv1.JobIdentity{
		Provider:               "github",
		ProviderHost:           "github.com",
		ProjectPath:            "acme/example",
		GithubRunId:            "123",
		GithubJob:              "build",
		GithubRunAttempt:       "1",
		GithubRunnerTrackingId: "runner-1",
	}

	tests := []struct {
		name     string
		err      error
		wantCode connect.Code
	}{
		{
			name:     "generic sink error returns internal",
			err:      errors.New("boom"),
			wantCode: connect.CodeInternal,
		},
		{
			name:     "throttled sink error returns resource exhausted",
			err:      sink.ErrThrottled,
			wantCode: connect.CodeResourceExhausted,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bad := sinktest.New("bad")
			bad.SetErrors(tt.err, tt.err, tt.err)
			_, err := callCollector(t, bad, validIngestLogBatch(identity, payload))
			if got := connect.CodeOf(err); got != tt.wantCode {
				t.Fatalf("code: got %v, want %v (err=%v)", got, tt.wantCode, err)
			}
			if bad.Calls() == 0 {
				t.Fatal("failing sink was not attempted")
			}
		})
	}
}

func TestValidateFlushAt(t *testing.T) {
	tests := []struct {
		name    string
		value   *timestamppb.Timestamp
		wantErr bool
	}{
		{
			name:  "accepts valid UTC timestamp",
			value: fixtureFlushAt,
		},
		{
			name:    "rejects nil timestamp",
			wantErr: true,
		},
		{
			name:    "rejects invalid proto timestamp",
			value:   &timestamppb.Timestamp{Seconds: -1, Nanos: -1},
			wantErr: true,
		},
		{
			name:    "rejects year before 2000",
			value:   timestamppb.New(time.Date(1999, 12, 31, 23, 59, 59, 999_000_000, time.UTC)),
			wantErr: true,
		},
		{
			name:    "rejects year after 2999",
			value:   timestamppb.New(time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFlushAt(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("validateFlushAt: %v", err)
			}
		})
	}
}

func callCollector(t *testing.T, dst *sinktest.Sink, batch *managerv1.IngestLogBatch) (*connect.Response[managerv1.IngestLogResponse], error) {
	t.Helper()
	var router *OutputRouter
	if dst != nil {
		router = newOutputRouterForTest(map[logtype.LogType]sink.Sink{
			logtype.Detection: dst,
		})
	}
	server := NewServer(testLogger, ":0", testManagerTokens, &ServedConfig{}, "", &StartupConfig{}, router)
	server.now = func() time.Time {
		return time.Date(2026, 4, 26, 7, 0, 0, 0, time.UTC)
	}
	ts := newManagerHTTPTestServer(t, server.Handler())
	defer ts.Close()

	client := managerv1connect.NewCollectorServiceClient(ts.Client(), ts.URL)
	req := connect.NewRequest(&managerv1.IngestLogRequest{Batch: batch})
	req.Header().Set("Authorization", managerBearer(testManagerSecret))
	return client.IngestLog(context.Background(), req)
}

func validIngestLogBatch(identity *managerv1.JobIdentity, payload []byte) *managerv1.IngestLogBatch {
	return &managerv1.IngestLogBatch{
		JobIdentity:     identity,
		Scope:           managerv1.Scope_SCOPE_HOST,
		LogType:         managerv1.LogType_LOG_TYPE_DETECTION,
		CompressedJsonl: payload,
		FlushAt:         fixtureFlushAt,
	}
}

func gzipPayload(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(body)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}
