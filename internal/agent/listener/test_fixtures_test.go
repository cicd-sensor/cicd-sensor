package listener_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"connectrpc.com/connect"

	jobpkg "github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/listener"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1/managerv1connect"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeConfigService struct {
	handler func(ctx context.Context, req *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error)
}

func (f *fakeConfigService) FetchConfig(ctx context.Context, req *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error) {
	return f.handler(ctx, req)
}

type staticManagerFetcher struct{}

func (staticManagerFetcher) FetchConfig(context.Context, *managerv1.FetchConfigRequest) (*managerclient.FetchResult, error) {
	return &managerclient.FetchResult{}, nil
}

func newFakeConfigServer(t *testing.T, svc *fakeConfigService) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := managerv1connect.NewConfigServiceHandler(svc)
	mux.Handle(path, handler)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		skipIfListenPermissionDenied(t, err)
		t.Fatalf("listen fake manager config server: %v", err)
	}
	server := httptest.NewUnstartedServer(mux)
	server.Listener = ln
	server.Start()
	return server
}

func setupListenerWithRegistryAndRoot(t *testing.T) (*http.Client, *jobregistry.JobRegistry, string, func()) {
	t.Helper()
	return setupListenerWithRegistryAndRootForProvider(t, jobcontext.ProviderGitHub)
}

func setupListenerWithRegistryAndRootForProvider(t *testing.T, provider jobcontext.Provider) (*http.Client, *jobregistry.JobRegistry, string, func()) {
	t.Helper()
	return setupListenerWithRegistryAndRootForProviderWithHostManager(t, provider, staticManagerFetcher{})
}

func setupListenerWithRegistryAndRootForProviderWithHostManager(t *testing.T, provider jobcontext.Provider, hostManagerClient jobregistry.ManagerConfigFetcher) (*http.Client, *jobregistry.JobRegistry, string, func()) {
	t.Helper()
	dir := newTestSocketDir(t, "cicd-sensor-test-")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "t.sock")

	jobRegistry := jobregistry.New(testLogger)
	jobRegistry.SetBaselineLoadForTesting(func(context.Context, *slog.Logger, string) (rulesource.LoadedRules, error) {
		return rulesource.LoadedRules{}, nil
	})
	l := listener.New(listener.Config{
		Logger:                testLogger,
		JobRegistry:           jobRegistry,
		SocketPath:            sock,
		HostManagerConnection: managerclient.Connection{},
		HostManagerClient:     hostManagerClient,
		RunnerType:            "machine",
		Provider:              provider,
	})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- l.Serve(ctx) }()

	deadline := time.After(3 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		select {
		case err := <-errCh:
			skipIfListenPermissionDenied(t, err)
			t.Fatalf("listener failed to start: %v", err)
		case <-deadline:
			t.Fatal("socket did not appear within timeout")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
	}

	cleanup := func() {
		cancel()
		<-errCh
	}
	return client, jobRegistry, dir, cleanup
}

func setupListenerWithRegistry(t *testing.T) (*http.Client, *jobregistry.JobRegistry, func()) {
	t.Helper()
	client, jobRegistry, _, cleanup := setupListenerWithRegistryAndRoot(t)
	return client, jobRegistry, cleanup
}

func setupListener(t *testing.T) (*http.Client, func()) {
	t.Helper()
	client, _, cleanup := setupListenerWithRegistry(t)
	return client, cleanup
}

func listenerRegisteredJob(registry *jobregistry.JobRegistry, identity jobcontext.JobIdentity) *jobpkg.Job {
	for _, j := range registry.All() {
		if j.Identity() == identity {
			return j
		}
	}
	return nil
}

func newTestSocketDir(t *testing.T, prefix string) string {
	t.Helper()

	dir, err := os.MkdirTemp(testSocketBaseDir(), prefix)
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	return dir
}

func testSocketBaseDir() string {
	if base := os.Getenv("CICD_SENSOR_TEST_SOCKET_DIR"); base != "" {
		return base
	}
	if runtime.GOOS == "darwin" {
		return "/private/tmp"
	}
	return ""
}

func skipIfListenPermissionDenied(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, os.ErrPermission) {
		t.Skipf("socket listen is not permitted in this test environment: %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return data
}

func mustRuleSources(t *testing.T, sets []rule.RuleSet, modifiers []rule.RuleModifier) []*managerv1.RuleSource {
	t.Helper()
	return protoconv.ToProtoRuleSources([]rulesource.LoadedRules{{
		RuleSets:      sets,
		RuleModifiers: modifiers,
	}})
}
