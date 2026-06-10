package nri

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

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
	client := newAgentClient(socket, jobcontext.ProviderGitLab)
	decision := stagingDecision{
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

func TestAgentClient_StageGitLabDoesNotCallHostStartOnJobNotFound(t *testing.T) {
	var calls []string
	identity := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	socket := startNRIUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		switch r.URL.Path {
		case "/v1/gitlab/k8s/staging/put":
			var req jobcontext.GitLabK8sStagingPutRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode staging: %v", err)
			}
			if req.Basename != "cri-containerd-build.scope" || req.JobIdentity != identity {
				t.Fatalf("staging request: %+v", req)
			}
			if req.Metadata.CommitSHA != "abc123" {
				t.Fatalf("staging metadata: %+v", req.Metadata)
			}
			http.Error(w, "job_not_found", http.StatusNotFound)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	client := newAgentClient(socket, jobcontext.ProviderGitLab)
	decision := stagingDecision{
		Basename: "cri-containerd-build.scope",
		Identity: identity,
		Metadata: jobcontext.JobMetadata{CommitSHA: "abc123"},
	}

	if err := client.stage(context.Background(), decision); err == nil {
		t.Fatal("stage error is nil")
	}
	wantCalls := []string{"/v1/gitlab/k8s/staging/put"}
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
	client := newAgentClient(socket, jobcontext.ProviderGitLab)

	err := client.stage(context.Background(), stagingDecision{
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
	client := newAgentClient(socket, jobcontext.ProviderGitHub)

	err := client.stage(context.Background(), stagingDecision{
		Basename: "cri-containerd-job.scope",
		Identity: identity,
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
}

func TestAgentClient_PostReusesUnixHTTPClient(t *testing.T) {
	var newConnections int64
	socket := startNRIUnixServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}), func(server *http.Server) {
		server.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				atomic.AddInt64(&newConnections, 1)
			}
		}
	})
	client := newAgentClient(socket, jobcontext.ProviderGitLab)

	for range 2 {
		status, _, err := client.post(context.Background(), "/v1/test", []byte(`{}`))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		if status != http.StatusOK {
			t.Fatalf("status: got %d, want %d", status, http.StatusOK)
		}
	}
	if got := atomic.LoadInt64(&newConnections); got != 1 {
		t.Fatalf("new unix connections: got %d, want 1", got)
	}
}

func TestNewAgentClient_ConfiguresIdleTimeoutBelowListener(t *testing.T) {
	client := newAgentClient("/tmp/agent.sock", jobcontext.ProviderGitLab)
	transport, ok := client.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type: got %T, want *http.Transport", client.client.Transport)
	}
	if transport.IdleConnTimeout != 30*time.Second {
		t.Fatalf("IdleConnTimeout: got %s, want 30s", transport.IdleConnTimeout)
	}
}

func startNRIUnixServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	return startNRIUnixServerWithConfig(t, handler, nil)
}

func startNRIUnixServerWithConfig(t *testing.T, handler http.Handler, configure func(*http.Server)) string {
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
	if configure != nil {
		configure(server)
	}
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
