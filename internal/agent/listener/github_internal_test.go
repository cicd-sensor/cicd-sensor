package listener

import (
	"bytes"
	"context"
	"encoding/json"
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

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
)

type staticManagerFetcher struct{}

func (staticManagerFetcher) FetchConfig(context.Context, *managerv1.FetchConfigRequest) (*managerclient.FetchResult, error) {
	return &managerclient.FetchResult{}, nil
}

func TestGitHubJobHealth_RequiresPeerPID(t *testing.T) {
	registry := jobregistry.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "host-health-auth", "build", "1", "runner-health-auth")
	if _, err := registry.ApplyGitHubHostStart(context.Background(), identity, jobcontext.JobMetadata{}, "machine", 0, managerclient.Connection{}, staticManagerFetcher{}); err != nil {
		t.Fatalf("host start: %v", err)
	}

	l := New(Config{
		Logger:                slog.New(slog.NewTextHandler(io.Discard, nil)),
		JobRegistry:           registry,
		HostManagerConnection: managerclient.Connection{},
		RunnerType:            "machine",
		Provider:              jobcontext.ProviderGitHub,
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/github/job/health", bytes.NewReader(mustMarshal(t, identity)))
	rec := httptest.NewRecorder()

	l.handleGitHubJobHealth(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if got := registry.All(); len(got) != 1 {
		t.Fatalf("job health should not remove jobs, got %d jobs", len(got))
	}
}

func TestGitHubHostEnd_RequiresPeerPIDBeforeFinalizing(t *testing.T) {
	registry := jobregistry.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "host-end-auth", "build", "1", "runner-end-auth")
	if _, err := registry.ApplyGitHubHostStart(context.Background(), identity, jobcontext.JobMetadata{}, "machine", 0, managerclient.Connection{}, staticManagerFetcher{}); err != nil {
		t.Fatalf("host start: %v", err)
	}

	l := New(Config{
		Logger:                slog.New(slog.NewTextHandler(io.Discard, nil)),
		JobRegistry:           registry,
		HostManagerConnection: managerclient.Connection{},
		RunnerType:            "machine",
		Provider:              jobcontext.ProviderGitHub,
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/github/host/end", bytes.NewReader(mustMarshal(t, identity)))
	rec := httptest.NewRecorder()

	l.handleGitHubHostEnd(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if got := registry.All(); len(got) != 1 {
		t.Fatalf("host/end without peer pid should not remove jobs, got %d jobs", len(got))
	}
}

// On a GitHub host the proxy forwards basename + peer_pid; the listener
// resolves identity via cgroup chain. With pid 1 (init) the lookup misses
// and the request is silently ignored.
func TestGitHubStagingPut_NoCgroupHitIgnored(t *testing.T) {
	matchAgentOwnerUIDToPeerCred(t)

	client, _, cleanup := setupGitHubStagingListener(t)
	defer cleanup()

	body := mustMarshal(t, jobcontext.GitHubStagingPutRequest{
		Basename: "docker-cafef00d.scope",
		PeerPID:  1,
	})

	resp, err := client.Post("http://cicd-sensor/v1/github/staging/put", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusOK, dump)
	}

	var got struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != "ignored" {
		t.Fatalf("status: got %q, want %q", got.Status, "ignored")
	}
}

func TestGitHubStagingPut_WrongUIDForbidden(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED owner gate is enforced only on linux")
	}

	original := agentOwnerUID
	agentOwnerUID = func() int {
		return os.Geteuid() + 1
	}
	t.Cleanup(func() { agentOwnerUID = original })

	client, _, cleanup := setupGitHubStagingListener(t)
	defer cleanup()

	body := mustMarshal(t, jobcontext.GitHubStagingPutRequest{
		Basename: "docker-cafef00d.scope",
	})

	resp, err := client.Post("http://cicd-sensor/v1/github/staging/put", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestGitHubStagingPut_BadBody(t *testing.T) {
	matchAgentOwnerUIDToPeerCred(t)

	client, _, cleanup := setupGitHubStagingListener(t)
	defer cleanup()

	cases := []struct {
		name string
		body []byte
	}{
		{name: "not json", body: []byte("not json")},
		{name: "missing basename", body: mustMarshal(t, jobcontext.GitHubStagingPutRequest{})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.Post("http://cicd-sensor/v1/github/staging/put", "application/json", bytes.NewReader(tc.body))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				dump, _ := io.ReadAll(resp.Body)
				t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusBadRequest, dump)
			}
		})
	}
}

// setupGitHubStagingListener wires a Listener bound to a real KernelTracker.
// The engine loop must run because staging waits for a KernelTracker reply.
func setupGitHubStagingListener(t *testing.T) (*http.Client, *jobregistry.JobRegistry, func()) {
	t.Helper()

	dir := newTestSocketDir(t, "cicd-sensor-staging-test-")
	t.Cleanup(func() { os.RemoveAll(dir) })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := jobregistry.New(logger)

	engine, err := kerneltracker.New(logger, registry)
	if err != nil {
		t.Skipf("kernel tracker unavailable: %v", err)
	}
	registry.BindKernelTracker(engine)
	engineCtx, engineCancel := context.WithCancel(context.Background())
	engineDone := make(chan error, 1)
	go func() { engineDone <- engine.Run(engineCtx) }()

	sock := filepath.Join(dir, "t.sock")
	l := New(Config{
		Logger:                logger,
		JobRegistry:           registry,
		SocketPath:            sock,
		HostManagerConnection: managerclient.Connection{},
		RunnerType:            "machine",
		Provider:              jobcontext.ProviderGitHub,
	})

	listenerCtx, listenerCancel := context.WithCancel(context.Background())
	listenerErrCh := make(chan error, 1)
	go func() { listenerErrCh <- l.Serve(listenerCtx) }()

	deadline := time.After(3 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		select {
		case err := <-listenerErrCh:
			skipIfListenPermissionDenied(t, err)
			t.Fatalf("listener failed to start: %v", err)
		case <-deadline:
			t.Fatal("staging listener socket did not appear within timeout")
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
		listenerCancel()
		<-listenerErrCh
		_ = engine.Close()
		engineCancel()
		<-engineDone
	}
	return client, registry, cleanup
}

// matchAgentOwnerUIDToPeerCred exists for call-site clarity; non-linux owner
// gates are no-op and Linux uses the real process uid.
func matchAgentOwnerUIDToPeerCred(t *testing.T) {
	t.Helper()
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// A GitHub-mounted listener must reject a request whose body declares
// provider=gitlab even though the GitHub route accepts it. Without this
// gate the shared JobIdentity would build a GitLab JobIdentity
// from a /v1/github/* endpoint and cross the provider boundary.
func TestGitHubHandlers_RejectGitLabProviderInBody(t *testing.T) {
	matchAgentOwnerUIDToPeerCred(t)

	client, _, cleanup := setupGitHubStagingListener(t)
	defer cleanup()

	body := mustMarshal(t, map[string]any{
		"provider":      "gitlab",
		"provider_host": "gitlab.com",
		"project_path":  "acme/example",
		"gitlab_job_id": "999",
	})

	cases := []string{
		"http://cicd-sensor/v1/github/job/health",
		"http://cicd-sensor/v1/github/host/start",
		"http://cicd-sensor/v1/github/host/end",
		"http://cicd-sensor/v1/github/project/start",
		"http://cicd-sensor/v1/github/project/result",
	}
	for _, url := range cases {
		t.Run(url, func(t *testing.T) {
			resp, err := client.Post(url, "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				dump, _ := io.ReadAll(resp.Body)
				t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusBadRequest, dump)
			}
		})
	}
}

// Provider boundary in the other direction: a GitHub-configured listener
// must not expose GitLab routes at all.
func TestListener_GitHubProvider_RejectsGitLabRoutes(t *testing.T) {
	matchAgentOwnerUIDToPeerCred(t)

	client, _, cleanup := setupGitHubStagingListener(t)
	defer cleanup()

	cases := []string{
		"http://cicd-sensor/v1/gitlab/host/start",
		"http://cicd-sensor/v1/gitlab/staging/put",
	}
	for _, url := range cases {
		t.Run(url, func(t *testing.T) {
			resp, err := client.Post(url, "application/json", bytes.NewReader([]byte("{}")))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusNotFound)
			}
		})
	}
}
