package managerclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1/managerv1connect"
)

const testOutputManagerToken = managerauth.TokenPrefix + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var testCollectorServiceLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeCollectorService struct {
	calls   int
	handler func(context.Context, *connect.Request[managerv1.IngestLogRequest]) (*connect.Response[managerv1.IngestLogResponse], error)
}

func (s *fakeCollectorService) IngestLog(ctx context.Context, req *connect.Request[managerv1.IngestLogRequest]) (*connect.Response[managerv1.IngestLogResponse], error) {
	s.calls++
	return s.handler(ctx, req)
}

func TestCollectorServiceClient_SendLogBatchAddsAuthHeader(t *testing.T) {
	svc := &fakeCollectorService{
		handler: func(_ context.Context, req *connect.Request[managerv1.IngestLogRequest]) (*connect.Response[managerv1.IngestLogResponse], error) {
			if got, want := req.Header().Get("Authorization"), "Bearer "+testOutputManagerToken; got != want {
				t.Fatalf("authorization: got %q, want %q", got, want)
			}
			return connect.NewResponse(&managerv1.IngestLogResponse{ReceivedBatches: 1}), nil
		},
	}
	server := newFakeCollectorServer(t, svc)
	defer server.Close()

	client := NewCollectorServiceClient(testCollectorServiceLogger, server.Client(), Connection{BaseURL: server.URL, Token: testOutputManagerToken})
	if err := client.SendLogBatch(context.Background(), LogBatch{
		Scope:   managerv1.Scope_SCOPE_HOST,
		Type:    managerv1.LogType_LOG_TYPE_DETECTION,
		Records: [][]byte{[]byte(`{"ok":true}`)},
		FlushAt: time.Now(),
	}); err != nil {
		t.Fatalf("send log batch: %v", err)
	}
}

func TestCollectorServiceClient_SendLogBatchRejectsEmptyBatchBeforeRequest(t *testing.T) {
	svc := &fakeCollectorService{
		handler: func(context.Context, *connect.Request[managerv1.IngestLogRequest]) (*connect.Response[managerv1.IngestLogResponse], error) {
			t.Fatal("collector service should not be called for an empty batch")
			return nil, nil
		},
	}
	client := &CollectorServiceClient{client: svc, token: testOutputManagerToken}
	err := client.SendLogBatch(context.Background(), LogBatch{
		Scope: managerv1.Scope_SCOPE_HOST,
		Type:  managerv1.LogType_LOG_TYPE_DETECTION,
	})
	if err == nil || !strings.Contains(err.Error(), "no records") {
		t.Fatalf("error: got %v, want no records", err)
	}
	if svc.calls != 0 {
		t.Fatalf("calls: got %d, want 0", svc.calls)
	}
}

func TestCollectorServiceClient_SendBatchRejectsInvalidTokenBeforeRequest(t *testing.T) {
	svc := &fakeCollectorService{
		handler: func(context.Context, *connect.Request[managerv1.IngestLogRequest]) (*connect.Response[managerv1.IngestLogResponse], error) {
			t.Fatal("collector service should not be called with an invalid token")
			return nil, nil
		},
	}
	client := &CollectorServiceClient{client: svc, token: "short-token"}
	err := client.sendIngestLogBatch(context.Background(), &managerv1.IngestLogBatch{CompressedJsonl: []byte{0x1f, 0x8b}})
	if err == nil || !strings.Contains(err.Error(), managerauth.ValidTokenDescription()) {
		t.Fatalf("error: got %v, want token validation error", err)
	}
	if svc.calls != 0 {
		t.Fatalf("calls: got %d, want 0", svc.calls)
	}
}

func TestCollectorServiceClient_SendBatchRejectsNilBatch(t *testing.T) {
	client := NewCollectorServiceClient(testCollectorServiceLogger, nil, Connection{BaseURL: "http://127.0.0.1", Token: testOutputManagerToken})
	err := client.sendIngestLogBatch(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "collector ingest log batch is nil") {
		t.Fatalf("error: got %v, want nil batch error", err)
	}
}

func TestCollectorServiceClient_SendBatchNilClient(t *testing.T) {
	var client *CollectorServiceClient
	err := client.sendIngestLogBatch(context.Background(), &managerv1.IngestLogBatch{CompressedJsonl: []byte{0x1f, 0x8b}})
	if err == nil || !strings.Contains(err.Error(), "collector service client is nil") {
		t.Fatalf("error: got %v, want nil client error", err)
	}
}

func TestCollectorServiceClient_SendBatchRetriesResourceExhausted(t *testing.T) {
	var svc *fakeCollectorService
	svc = &fakeCollectorService{
		handler: func(context.Context, *connect.Request[managerv1.IngestLogRequest]) (*connect.Response[managerv1.IngestLogResponse], error) {
			if svc.calls == 1 {
				return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("throttled"))
			}
			return connect.NewResponse(&managerv1.IngestLogResponse{ReceivedBatches: 1}), nil
		},
	}
	server := newFakeCollectorServer(t, svc)
	defer server.Close()

	client := newCollectorServiceClient(testCollectorServiceLogger, server.Client(), Connection{BaseURL: server.URL, Token: testOutputManagerToken}, func(context.Context, time.Duration) error { return nil }, func(d time.Duration) time.Duration { return d })
	if err := client.sendIngestLogBatch(context.Background(), &managerv1.IngestLogBatch{CompressedJsonl: []byte{0x1f, 0x8b}}); err != nil {
		t.Fatalf("send batch: %v", err)
	}
	if svc.calls != 2 {
		t.Fatalf("calls: got %d, want 2", svc.calls)
	}
}

func TestCollectorServiceClient_SendBatchDoesNotRetryInvalidArgument(t *testing.T) {
	svc := &fakeCollectorService{
		handler: func(context.Context, *connect.Request[managerv1.IngestLogRequest]) (*connect.Response[managerv1.IngestLogResponse], error) {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad batch"))
		},
	}
	server := newFakeCollectorServer(t, svc)
	defer server.Close()

	client := NewCollectorServiceClient(testCollectorServiceLogger, server.Client(), Connection{BaseURL: server.URL, Token: testOutputManagerToken})
	err := client.sendIngestLogBatch(context.Background(), &managerv1.IngestLogBatch{CompressedJsonl: []byte("bad")})
	if err == nil {
		t.Fatal("expected invalid argument error")
	}
	if svc.calls != 1 {
		t.Fatalf("calls: got %d, want 1", svc.calls)
	}
}

func TestCollectorServiceClient_SendBatchStopsAfterRetryBudget(t *testing.T) {
	svc := &fakeCollectorService{
		handler: func(context.Context, *connect.Request[managerv1.IngestLogRequest]) (*connect.Response[managerv1.IngestLogResponse], error) {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("manager unavailable"))
		},
	}
	server := newFakeCollectorServer(t, svc)
	defer server.Close()

	client := newCollectorServiceClient(testCollectorServiceLogger, server.Client(), Connection{BaseURL: server.URL, Token: testOutputManagerToken}, func(context.Context, time.Duration) error { return nil }, func(d time.Duration) time.Duration { return d })
	err := client.sendIngestLogBatch(context.Background(), &managerv1.IngestLogBatch{CompressedJsonl: []byte{0x1f, 0x8b}})
	if err == nil {
		t.Fatal("expected retry budget error")
	}
	if want := collectorServiceRetryAttempts + 1; svc.calls != want {
		t.Fatalf("calls: got %d, want %d", svc.calls, want)
	}
}

func TestCollectorServiceClient_SendBatchStopsWhenContextCanceledDuringRetrySleep(t *testing.T) {
	svc := &fakeCollectorService{
		handler: func(context.Context, *connect.Request[managerv1.IngestLogRequest]) (*connect.Response[managerv1.IngestLogResponse], error) {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("manager unavailable"))
		},
	}
	server := newFakeCollectorServer(t, svc)
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	client := newCollectorServiceClient(testCollectorServiceLogger, server.Client(), Connection{BaseURL: server.URL, Token: testOutputManagerToken}, func(context.Context, time.Duration) error {
		cancel()
		return context.Canceled
	}, func(d time.Duration) time.Duration { return d })
	err := client.sendIngestLogBatch(ctx, &managerv1.IngestLogBatch{CompressedJsonl: []byte{0x1f, 0x8b}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error: got %v, want context.Canceled", err)
	}
	if svc.calls != 1 {
		t.Fatalf("calls: got %d, want 1", svc.calls)
	}
}

func TestIsCollectorServiceRetryable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "resource exhausted",
			err:  connect.NewError(connect.CodeResourceExhausted, errors.New("throttled")),
			want: true,
		},
		{
			name: "unavailable",
			err:  connect.NewError(connect.CodeUnavailable, errors.New("unavailable")),
			want: true,
		},
		{
			name: "deadline exceeded connect code",
			err:  connect.NewError(connect.CodeDeadlineExceeded, errors.New("deadline")),
			want: true,
		},
		{
			name: "context deadline exceeded",
			err:  context.DeadlineExceeded,
			want: true,
		},
		{
			name: "timeout net error",
			err:  timeoutNetError{},
			want: true,
		},
		{
			name: "invalid argument",
			err:  connect.NewError(connect.CodeInvalidArgument, errors.New("bad request")),
			want: false,
		},
		{
			name: "unknown plain error",
			err:  errors.New("plain"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCollectorServiceRetryable(tt.err); got != tt.want {
				t.Fatalf("isCollectorServiceRetryable: got %v, want %v", got, tt.want)
			}
		})
	}
}

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return false }

func newFakeCollectorServer(t *testing.T, svc managerv1connect.CollectorServiceHandler) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := managerv1connect.NewCollectorServiceHandler(svc)
	mux.Handle(path, handler)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("tcp listen is not permitted in this test environment: %v", err)
		}
		t.Fatalf("listen fake collector server: %v", err)
	}
	server := httptest.NewUnstartedServer(mux)
	server.Listener = ln
	server.Start()
	return server
}
