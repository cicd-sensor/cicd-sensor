package listener_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/listener"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestGitHubK8sStart_SetsHostScope(t *testing.T) {
	client, registry, cleanup := setupGitHubK8sStartListener(t)
	defer cleanup()

	body := mustJSON(t, map[string]any{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "123",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "github_k8s_tracking_host_scope",
		"metadata": map[string]string{
			"commit_sha":      "abc123",
			"ref_name":        "main",
			"trigger":         "push",
			"github_workflow": "build",
		},
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/k8s/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusOK, dump)
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "github_k8s_tracking_host_scope")
	job := listenerRegisteredJob(registry, id)
	if job == nil {
		t.Fatal("expected job to be registered")
	}
	if job.HostScope() == nil {
		t.Fatal("expected host scope to be set")
	}
	if job.RunnerType() != "kubernetes" {
		t.Fatalf("job runner_type: got %q, want %q", job.RunnerType(), "kubernetes")
	}
	if job.Metadata().CommitSHA != "abc123" {
		t.Fatalf("job metadata commit_sha: got %q, want abc123", job.Metadata().CommitSHA)
	}
}

func TestGitHubK8sStart_ExposesOnlyStartRoute(t *testing.T) {
	client, _, cleanup := setupGitHubK8sStartListener(t)
	defer cleanup()

	body := mustJSON(t, map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "124",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "github_k8s_tracking_route_scope",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusNotFound, dump)
	}

	for _, url := range []string{
		"http://cicd-sensor/v1/github/k8s/staging/put",
		"http://cicd-sensor/v1/gitlab/staging/put",
		"http://cicd-sensor/v1/gitlab/k8s/staging/put",
	} {
		t.Run(url, func(t *testing.T) {
			resp, err = client.Post(url, "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("k8s staging request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNotFound {
				dump, _ := io.ReadAll(resp.Body)
				t.Fatalf("k8s staging status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusNotFound, dump)
			}
		})
	}
}

func setupGitHubK8sStartListener(t *testing.T) (*http.Client, *jobregistry.JobRegistry, func()) {
	t.Helper()

	dir := newTestSocketDir(t, "cicd-sensor-github-k8s-start-test-")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "start.sock")

	registry := jobregistry.New(testLogger)
	l := listener.NewGitHubK8sStart(listener.Config{
		Logger:                testLogger,
		JobRegistry:           registry,
		SocketPath:            sock,
		HostManagerConnection: managerclient.Connection{},
		HostManagerClient:     staticManagerFetcher{},
		RunnerType:            "kubernetes",
		Provider:              jobcontext.ProviderGitHub,
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
	return client, registry, cleanup
}
