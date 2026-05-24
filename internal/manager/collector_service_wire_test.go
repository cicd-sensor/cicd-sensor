package manager

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	"github.com/cicd-sensor/cicd-sensor/internal/manager/sink"
	"github.com/cicd-sensor/cicd-sensor/internal/manager/sink/sinktest"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1/managerv1connect"
)

func TestCollectorWire_HappyPath_WritesToConfiguredSink(t *testing.T) {
	dst := sinktest.New("s3-prod")
	client, cleanup := newCollectorWireClient(t, testManagerSecret, newOutputRouterForTest(map[logtype.LogType]sink.Sink{
		logtype.Detection: dst,
	}))
	defer cleanup()

	payload := gzipPayload(t, `{"message":"hello"}`+"\n")
	_, err := client.send(context.Background(), testManagerSecret, validIngestLogBatch(validCollectorIdentity(), payload))
	if err != nil {
		t.Fatalf("send batch: %v", err)
	}

	batches := dst.Batches()
	if len(batches) != 1 {
		t.Fatalf("%s batches: got %d, want 1", dst.Name(), len(batches))
	}
	if !bytes.Equal(batches[0].Body, payload) {
		t.Fatalf("%s body changed in transit", dst.Name())
	}
}

func TestCollectorWire_ManagerClientRoundTrip(t *testing.T) {
	dst := sinktest.New("s3-prod")
	server := NewServer(testLogger, ":0", testManagerTokens, &ServedConfig{}, "", &StartupConfig{}, newOutputRouterForTest(map[logtype.LogType]sink.Sink{
		logtype.Detection: dst,
	}))
	server.now = func() time.Time {
		return time.Date(2026, 4, 26, 7, 0, 0, 0, time.UTC)
	}
	ts := newManagerHTTPTestServer(t, server.Handler())
	defer ts.Close()

	client := managerclient.NewCollectorServiceClient(testLogger, ts.Client(), managerclient.Connection{BaseURL: ts.URL, Token: testManagerSecret})
	flushAt := time.Date(2026, 4, 26, 7, 30, 45, 123_000_000, time.UTC)
	if err := client.SendLogBatch(context.Background(), managerclient.LogBatch{
		Identity: jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"),
		Scope:    managerv1.Scope_SCOPE_HOST,
		Type:     managerv1.LogType_LOG_TYPE_DETECTION,
		Records:  [][]byte{[]byte(`{"rule_id":"a"}`), []byte(`{"rule_id":"b"}`)},
		FlushAt:  flushAt,
	}); err != nil {
		t.Fatalf("send log batch: %v", err)
	}

	batches := dst.Batches()
	if len(batches) != 1 {
		t.Fatalf("batches: got %d, want 1", len(batches))
	}
	if got, want := gunzipString(t, batches[0].Body), "{\"rule_id\":\"a\"}\n{\"rule_id\":\"b\"}\n"; got != want {
		t.Fatalf("jsonl: got %q, want %q", got, want)
	}
	if !batches[0].FlushAt.Equal(flushAt) {
		t.Fatalf("flush_at: got %s, want %s", batches[0].FlushAt, flushAt)
	}
}

func TestCollectorWire_SinkThrottle_ReturnsResourceExhausted(t *testing.T) {
	bad := sinktest.New("bad")
	bad.SetErrors(sink.ErrThrottled, sink.ErrThrottled, sink.ErrThrottled)
	client, cleanup := newCollectorWireClient(t, testManagerSecret, newOutputRouterForTest(map[logtype.LogType]sink.Sink{
		logtype.Detection: bad,
	}))
	defer cleanup()

	_, err := client.send(context.Background(), testManagerSecret, validIngestLogBatch(validCollectorIdentity(), gzipPayload(t, `{"message":"hello"}`+"\n")))
	if got := connect.CodeOf(err); got != connect.CodeResourceExhausted {
		t.Fatalf("code: got %v, want %v (err=%v)", got, connect.CodeResourceExhausted, err)
	}
}

func TestCollectorWire_DuplicateFlushAt_PreservesFlushTimestamp(t *testing.T) {
	dst := sinktest.New("s3-prod")
	client, cleanup := newCollectorWireClient(t, testManagerSecret, newOutputRouterForTest(map[logtype.LogType]sink.Sink{
		logtype.Detection: dst,
	}))
	defer cleanup()

	first := gzipPayload(t, `{"message":"first"}`+"\n")
	second := gzipPayload(t, `{"message":"second"}`+"\n")
	if _, err := client.send(context.Background(), testManagerSecret, validIngestLogBatch(validCollectorIdentity(), first)); err != nil {
		t.Fatalf("send first batch: %v", err)
	}
	if _, err := client.send(context.Background(), testManagerSecret, validIngestLogBatch(validCollectorIdentity(), second)); err != nil {
		t.Fatalf("send second batch: %v", err)
	}

	if got := dst.Calls(); got != 2 {
		t.Fatalf("calls: got %d, want 2", got)
	}
	batches := dst.Batches()
	if len(batches) != 2 {
		t.Fatalf("batches: got %d, want 2", len(batches))
	}
	if !batches[0].FlushAt.Equal(batches[1].FlushAt) {
		t.Fatalf("flush_at changed between duplicate sends")
	}
	if !bytes.Equal(batches[1].Body, second) {
		t.Fatalf("body: got first/other payload, want second payload")
	}
}

func TestCollectorWire_UnauthorizedToken_ReturnsUnauthenticated(t *testing.T) {
	client, cleanup := newCollectorWireClient(t, testManagerSecret, newOutputRouterForTest(map[logtype.LogType]sink.Sink{
		logtype.Detection: sinktest.New("s3-prod"),
	}))
	defer cleanup()

	_, err := client.send(context.Background(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", validIngestLogBatch(validCollectorIdentity(), gzipPayload(t, `{"message":"hello"}`+"\n")))
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("code: got %v, want %v (err=%v)", got, connect.CodeUnauthenticated, err)
	}
}

type collectorWireClient struct {
	client managerv1connect.CollectorServiceClient
}

func newCollectorWireClient(t *testing.T, token string, router *OutputRouter) (*collectorWireClient, func()) {
	t.Helper()
	server := NewServer(testLogger, ":0", []string{token}, &ServedConfig{}, "", &StartupConfig{}, router)
	server.now = func() time.Time {
		return time.Date(2026, 4, 26, 7, 0, 0, 0, time.UTC)
	}
	ts := newManagerHTTPTestServer(t, server.Handler())
	client := managerv1connect.NewCollectorServiceClient(ts.Client(), ts.URL)
	return &collectorWireClient{client: client}, ts.Close
}

func (c *collectorWireClient) send(ctx context.Context, token string, batch *managerv1.IngestLogBatch) (*connect.Response[managerv1.IngestLogResponse], error) {
	req := connect.NewRequest(&managerv1.IngestLogRequest{Batch: batch})
	req.Header().Set("Authorization", managerBearer(token))
	return c.client.IngestLog(ctx, req)
}

func validCollectorIdentity() *managerv1.JobIdentity {
	return &managerv1.JobIdentity{
		Provider:               "github",
		ProviderHost:           "github.com",
		ProjectPath:            "acme/example",
		GithubRunId:            "123",
		GithubJob:              "build",
		GithubRunAttempt:       "1",
		GithubRunnerTrackingId: "runner-1",
	}
}

func gunzipString(t *testing.T, compressed []byte) string {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return string(body)
}
