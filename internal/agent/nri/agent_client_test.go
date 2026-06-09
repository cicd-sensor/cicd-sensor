package nri

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestAgentClient_StageGitLabWithIdentityAndMetadata(t *testing.T) {
	var calls []string
	socket := startNRIUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		switch r.URL.Path {
		case "/v1/gitlab/k8s/staging/put":
			var req jobcontext.GitLabK8sStagingPutRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode staging: %v", err)
			}
			if req.Basename != "cri-containerd-build.scope" {
				t.Fatalf("staging request: %+v", req)
			}
			if req.JobIdentity != jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123") {
				t.Fatalf("identity: %+v", req.JobIdentity)
			}
			if req.Metadata.CommitSHA != "abc123" {
				t.Fatalf("metadata: %+v", req.Metadata)
			}
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"staged"}`))
	}))
	client := &agentClient{socketPath: socket}
	decision := stagingDecision{
		Provider: jobcontext.ProviderGitLab,
		Basename: "cri-containerd-build.scope",
		Identity: jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"),
		Metadata: jobcontext.JobMetadata{CommitSHA: "abc123"},
	}

	if err := client.stage(context.Background(), decision); err != nil {
		t.Fatalf("stage: %v", err)
	}
	wantCalls := []string{"/v1/gitlab/k8s/staging/put"}
	if len(calls) != len(wantCalls) || calls[0] != wantCalls[0] {
		t.Fatalf("calls: got %#v, want %#v", calls, wantCalls)
	}
}

func TestAgentClient_StageGitLabLazyCreatesAfterJobNotFound(t *testing.T) {
	var calls []string
	stageCalls := 0
	identity := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	socket := startNRIUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		switch r.URL.Path {
		case "/v1/gitlab/k8s/staging/put":
			stageCalls++
			var req jobcontext.GitLabK8sStagingPutRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode staging: %v", err)
			}
			if req.Basename != "cri-containerd-build.scope" || req.JobIdentity != identity {
				t.Fatalf("staging request: %+v", req)
			}
			if stageCalls == 1 {
				http.Error(w, "job_not_found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"staged"}`))
		case "/v1/gitlab/host/start":
			var req jobcontext.GitLabHostStartRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode host start: %v", err)
			}
			if req.JobIdentity != identity {
				t.Fatalf("host start identity: %+v", req.JobIdentity)
			}
			if req.Metadata.CommitSHA != "abc123" {
				t.Fatalf("host start metadata: %+v", req.Metadata)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	client := &agentClient{socketPath: socket}
	decision := stagingDecision{
		Provider: jobcontext.ProviderGitLab,
		Basename: "cri-containerd-build.scope",
		Identity: identity,
		Metadata: jobcontext.JobMetadata{CommitSHA: "abc123"},
	}

	if err := client.stage(context.Background(), decision); err != nil {
		t.Fatalf("stage: %v", err)
	}
	wantCalls := []string{
		"/v1/gitlab/k8s/staging/put",
		"/v1/gitlab/host/start",
		"/v1/gitlab/k8s/staging/put",
	}
	if len(calls) != len(wantCalls) {
		t.Fatalf("calls: got %#v, want %#v", calls, wantCalls)
	}
	for i := range wantCalls {
		if calls[i] != wantCalls[i] {
			t.Fatalf("calls: got %#v, want %#v", calls, wantCalls)
		}
	}
}

func TestAgentClient_StageGitLabDoesNotStartOnNonJobNotFoundError(t *testing.T) {
	var calls []string
	socket := startNRIUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		if r.URL.Path != "/v1/gitlab/k8s/staging/put" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		http.Error(w, "agent boom", http.StatusTeapot)
	}))
	client := &agentClient{socketPath: socket}

	err := client.stage(context.Background(), stagingDecision{
		Provider: jobcontext.ProviderGitLab,
		Basename: "cri-containerd-build.scope",
		Identity: jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"),
	})
	if err == nil {
		t.Fatal("stage error is nil")
	}
	wantCalls := []string{"/v1/gitlab/k8s/staging/put"}
	if len(calls) != len(wantCalls) || calls[0] != wantCalls[0] {
		t.Fatalf("calls: got %#v, want %#v", calls, wantCalls)
	}
}

func TestAgentClient_StageGitHubWithIdentity(t *testing.T) {
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	socket := startNRIUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/github/k8s/staging/put" {
			t.Fatalf("path: got %q", r.URL.Path)
		}
		var req jobcontext.GitHubK8sStagingPutRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if req.Basename != "cri-containerd-job.scope" || req.JobIdentity != identity {
			t.Fatalf("request: %+v", req)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"staged"}`))
	}))
	client := &agentClient{socketPath: socket}

	err := client.stage(context.Background(), stagingDecision{
		Provider: jobcontext.ProviderGitHub,
		Basename: "cri-containerd-job.scope",
		Identity: identity,
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
}

func startNRIUnixServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "cicd-sensor-nri-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "agent.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	server := &http.Server{Handler: handler}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Errorf("server: %v", err)
		}
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = os.Remove(socketPath)
	})
	return socketPath
}
