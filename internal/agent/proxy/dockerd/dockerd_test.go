package dockerd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestCheckDriver_Systemd(t *testing.T) {
	t.Parallel()

	socket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/info" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		writeJSON(t, w, http.StatusOK, driverInfo{CgroupDriver: "systemd"})
	}))

	if err := checkDriver(context.Background(), socket); err != nil {
		t.Fatalf("checkDriver: %v", err)
	}
}

func TestCheckDriver_RejectsCgroupfs(t *testing.T) {
	t.Parallel()

	socket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, driverInfo{CgroupDriver: "cgroupfs"})
	}))

	if err := checkDriver(context.Background(), socket); err == nil {
		t.Fatalf("checkDriver returned nil for cgroupfs")
	}
}

func TestCheckDriver_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		handler   http.Handler
		socket    string
		errSubstr string
	}{
		{
			name: "non-200",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "nope", http.StatusServiceUnavailable)
			}),
			errSubstr: "status 503",
		},
		{
			name: "invalid json",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("{"))
			}),
			errSubstr: "decode /info",
		},
		{
			name:      "unreachable socket",
			socket:    filepath.Join(t.TempDir(), "missing.sock"),
			errSubstr: "dockerd /info",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			socket := tc.socket
			if socket == "" {
				socket = startUnixServer(t, tc.handler)
			}
			err := checkDriver(context.Background(), socket)
			if err == nil {
				t.Fatalf("checkDriver returned nil")
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Fatalf("error %q does not contain %q", err, tc.errSubstr)
			}
		})
	}
}

func TestRunValidationErrors(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tests := []struct {
		name      string
		opts      Options
		errSubstr string
	}{
		{
			name:      "missing sockets",
			opts:      Options{Provider: jobcontext.ProviderGitHub},
			errSubstr: "required",
		},
		{
			name: "invalid provider",
			opts: Options{
				DockerDaemonSocket: filepath.Join(t.TempDir(), "daemon.sock"),
				DockerProxySocket:  filepath.Join(t.TempDir(), "proxy.sock"),
				AgentSocket:        filepath.Join(t.TempDir(), "agent.sock"),
				Provider:           jobcontext.Provider("unknown"),
			},
			errSubstr: "provider must be github or gitlab",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Run(context.Background(), logger, tc.opts)
			if err == nil {
				t.Fatalf("Run returned nil")
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Fatalf("error %q does not contain %q", err, tc.errSubstr)
			}
		})
	}
}

func TestRunRejectsSameDockerDaemonAndProxySocket(t *testing.T) {
	t.Parallel()

	err := Run(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), Options{
		DockerDaemonSocket: "/tmp/docker.sock",
		DockerProxySocket:  "/tmp/docker.sock",
		AgentSocket:        "/tmp/agent.sock",
		Provider:           jobcontext.ProviderGitHub,
	})
	if err == nil {
		t.Fatal("Run returned nil for overlapping docker daemon/proxy socket")
	}
	if !strings.Contains(err.Error(), "upstream-socket and listen-socket must be different") {
		t.Fatalf("error: got %q, want docker daemon/proxy overlap message", err)
	}
}

func TestRunStopsOnContextCancelAndRemovesProxySocket(t *testing.T) {
	t.Parallel()

	upstreamSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/info" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		writeJSON(t, w, http.StatusOK, driverInfo{CgroupDriver: "systemd"})
	}))
	agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{"status": "staged"})
	}))
	proxySocket := filepath.Join(shortTempDir(t), "proxy.sock")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{
			DockerDaemonSocket: upstreamSocket,
			DockerProxySocket:  proxySocket,
			AgentSocket:        agentSocket,
			Provider:           jobcontext.ProviderGitHub,
		})
	}()

	waitForSocketOrRunExit(t, proxySocket, errCh)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after context cancel")
	}
	if _, err := os.Stat(proxySocket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("proxy socket cleanup: got err %v, want not exist", err)
	}
}

func TestSameUnixSocketPathResolvesSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	realPath := filepath.Join(dir, "docker.sock")
	if err := os.WriteFile(realPath, []byte("socket placeholder"), 0o600); err != nil {
		t.Fatalf("write real path: %v", err)
	}
	linkPath := filepath.Join(dir, "docker-link.sock")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if !sameUnixSocketPath(realPath, linkPath) {
		t.Fatalf("sameUnixSocketPath(%q, %q) = false, want true", realPath, linkPath)
	}
}

func TestIsContainerCreate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{name: "unversioned create", method: http.MethodPost, path: "/containers/create", want: true},
		{name: "versioned create", method: http.MethodPost, path: "/v1.43/containers/create", want: true},
		{name: "get create", method: http.MethodGet, path: "/containers/create", want: false},
		{name: "similar suffix", method: http.MethodPost, path: "/containers/createx", want: false},
		{name: "nested suffix", method: http.MethodPost, path: "/foo/containers/create", want: true},
		{name: "nil", method: "", path: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.name != "nil" {
				req = &http.Request{Method: tc.method, URL: mustURL(t, tc.path)}
			}
			if got := isContainerCreate(req); got != tc.want {
				t.Fatalf("isContainerCreate() = %v, want %v", got, tc.want)
			}
		})
	}
}

// On a successful container create the proxy must (1) pass the response
// through to the docker CLI unmodified and (2) synchronously POST a
// staging request containing only basename + peer_pid to the agent.
// GitHub identity is resolved agent-side from peer-pid → cgroup, so the
// proxy never reads the create body for env extraction.
func TestProxy_ContainerCreate_StagesBasenameOnly(t *testing.T) {
	t.Parallel()

	const containerID = "deadbeefcafef00d000000000000000000000000000000000000000000000000"
	const expectedBasename = "docker-" + containerID + ".scope"

	upstreamSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isContainerCreate(r) {
			t.Errorf("upstream got non-create path: %q", r.URL.Path)
		}
		writeJSON(t, w, http.StatusCreated, containerCreateResponse{ID: containerID})
	}))

	got := make(chan jobcontext.GitHubStagingPutRequest, 1)
	agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/github/staging/put" {
			t.Errorf("unexpected agent path: %q", r.URL.Path)
		}
		var req jobcontext.GitHubStagingPutRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
		}
		got <- req
		writeJSON(t, w, http.StatusOK, map[string]string{"status": "staged"})
	}))

	proxyClient := startProxy(t, upstreamSocket, agentSocket)

	createBody := map[string]any{"Image": "alpine"}
	body, err := json.Marshal(createBody)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	resp, err := proxyClient.Post("http://docker/v1.43/containers/create", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("proxy create: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	var echoed containerCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&echoed); err != nil {
		t.Fatalf("decode echoed body: %v", err)
	}
	if echoed.ID != containerID {
		t.Fatalf("client received Id %q, want %q", echoed.ID, containerID)
	}

	select {
	case stage := <-got:
		if stage.Basename != expectedBasename {
			t.Fatalf("staging basename: got %q, want %q", stage.Basename, expectedBasename)
		}
		assertPositivePeerPIDOnLinux(t, stage.PeerPID)
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not receive staging put within 2s")
	}
}

func TestProxy_NonCreatePath_DoesNotPostStaging(t *testing.T) {
	t.Parallel()

	upstreamSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"hello": "world"})
	}))

	agentCalled := make(chan struct{}, 1)
	agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case agentCalled <- struct{}{}:
		default:
		}
		writeJSON(t, w, http.StatusOK, map[string]string{"status": "staged"})
	}))

	proxyClient := startProxy(t, upstreamSocket, agentSocket)

	resp, err := proxyClient.Get("http://docker/_ping")
	if err != nil {
		t.Fatalf("proxy ping: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	select {
	case <-agentCalled:
		t.Fatal("agent unexpectedly received a request for a non-create path")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestProxy_AgentFailureFallsThrough(t *testing.T) {
	t.Parallel()

	const containerID = "deadbeef00000000000000000000000000000000000000000000000000000000"

	upstreamSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusCreated, containerCreateResponse{ID: containerID})
	}))

	agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))

	proxyClient := startProxy(t, upstreamSocket, agentSocket)

	resp, err := proxyClient.Post("http://docker/v1.43/containers/create", "application/json",
		bytes.NewReader([]byte(`{"Image":"alpine"}`)))
	if err != nil {
		t.Fatalf("proxy create: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want %d (proxy must transparently pass through on agent failure)", resp.StatusCode, http.StatusCreated)
	}
}

// On a successful container_create with non-spoofable gitlab-runner labels
// the proxy must (1) pass the request and response through unchanged and
// (2) POST a basename + identity pair derived from the labels to
// /v1/gitlab/staging/put. host_start must NOT be invoked by the proxy.
func TestProxy_GitLab_StagingHappyPath(t *testing.T) {
	t.Parallel()

	const containerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const expectedBasename = "docker-" + containerID + ".scope"

	labels := map[string]string{
		gitLabRunnerJobURLLabel: "https://gitlab.com/cicd-sensor/cicd-sensor-testing/-/jobs/14202203981",
		gitLabRunnerJobIDLabel:  "14202203981",
	}

	createBody, err := json.Marshal(map[string]any{"Image": "alpine", "Labels": labels})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	upstreamSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isContainerCreate(r) {
			t.Errorf("upstream got non-create path: %q", r.URL.Path)
		}
		gotBody, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream body read: %v", err)
		}
		if !bytes.Equal(gotBody, createBody) {
			t.Errorf("upstream body diverged from client body")
		}
		writeJSON(t, w, http.StatusCreated, containerCreateResponse{ID: containerID})
	}))

	type agentCall struct {
		path string
		body []byte
	}
	got := make(chan agentCall, 4)
	agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		got <- agentCall{path: r.URL.Path, body: buf}
		writeJSON(t, w, http.StatusOK, map[string]string{"status": "staged"})
	}))

	proxyClient := startProxyGitLab(t, upstreamSocket, agentSocket)

	resp, err := proxyClient.Post("http://docker/v1.43/containers/create", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("proxy create: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	select {
	case call := <-got:
		if call.path != "/v1/gitlab/staging/put" {
			t.Fatalf("agent path: got %q, want /v1/gitlab/staging/put", call.path)
		}
		var stage jobcontext.GitLabStagingPutRequest
		if err := json.Unmarshal(call.body, &stage); err != nil {
			t.Fatalf("decode staging body: %v", err)
		}
		if stage.Basename != expectedBasename {
			t.Fatalf("basename: got %q, want %q", stage.Basename, expectedBasename)
		}
		assertPositivePeerPIDOnLinux(t, stage.PeerPID)
		if stage.JobIdentity == nil {
			t.Fatal("job_identity is nil")
		}
		if stage.JobIdentity.Provider != jobcontext.ProviderGitLab {
			t.Fatalf("identity.provider: got %q, want gitlab", stage.JobIdentity.Provider)
		}
		if stage.JobIdentity.GitLabJobID != "14202203981" {
			t.Fatalf("identity.gitlab_job_id: got %q, want 14202203981", stage.JobIdentity.GitLabJobID)
		}
		if stage.JobIdentity.ProjectPath != "cicd-sensor/cicd-sensor-testing" {
			t.Fatalf("identity.project_path: got %q, want cicd-sensor/cicd-sensor-testing", stage.JobIdentity.ProjectPath)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not receive staging put within 2s")
	}

	select {
	case extra := <-got:
		t.Fatalf("unexpected second agent call: %s", extra.path)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestProxy_GitLab_StagesPeerPIDWithoutLabels(t *testing.T) {
	t.Parallel()

	const containerID = "feedface0123456789abcdef0123456789abcdef0123456789abcdef01234567"
	const expectedBasename = "docker-" + containerID + ".scope"

	upstreamSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isContainerCreate(r) {
			t.Errorf("upstream got non-create path: %q", r.URL.Path)
		}
		writeJSON(t, w, http.StatusCreated, containerCreateResponse{ID: containerID})
	}))

	got := make(chan jobcontext.GitLabStagingPutRequest, 1)
	agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/gitlab/staging/put" {
			t.Errorf("unexpected agent path: %q", r.URL.Path)
		}
		var req jobcontext.GitLabStagingPutRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
		}
		got <- req
		writeJSON(t, w, http.StatusOK, map[string]string{"status": "staged"})
	}))

	proxyClient := startProxyGitLab(t, upstreamSocket, agentSocket)

	createBody, err := json.Marshal(map[string]any{"Image": "alpine"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := proxyClient.Post("http://docker/v1.43/containers/create", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("proxy create: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	select {
	case stage := <-got:
		if stage.Basename != expectedBasename {
			t.Fatalf("basename: got %q, want %q", stage.Basename, expectedBasename)
		}
		assertPositivePeerPIDOnLinux(t, stage.PeerPID)
		if stage.JobIdentity != nil {
			t.Fatalf("job_identity: got %+v, want nil", *stage.JobIdentity)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not receive staging put within 2s")
	}
}

func TestProxy_GitLab_StagingNotFoundWithoutIdentityDoesNotHostStart(t *testing.T) {
	t.Parallel()

	const containerID = "1111111111111111111111111111111111111111111111111111111111111111"

	upstreamSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusCreated, containerCreateResponse{ID: containerID})
	}))

	got := make(chan string, 4)
	agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.Path
		switch r.URL.Path {
		case "/v1/gitlab/staging/put":
			writeJSON(t, w, http.StatusNotFound, map[string]string{"error": "job_not_found"})
		case "/v1/gitlab/host/start":
			t.Errorf("host_start must not be called without labels identity")
			writeJSON(t, w, http.StatusOK, map[string]string{"status": "ok"})
		default:
			t.Errorf("unexpected agent path: %q", r.URL.Path)
		}
	}))

	proxyClient := startProxyGitLab(t, upstreamSocket, agentSocket)
	resp, err := proxyClient.Post("http://docker/v1.43/containers/create", "application/json",
		bytes.NewReader([]byte(`{"Image":"alpine"}`)))
	if err != nil {
		t.Fatalf("proxy create: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	assertAgentCalls(t, got, []string{"/v1/gitlab/staging/put"})
}

func TestProxy_GitLab_StagingServerErrorDoesNotHostStart(t *testing.T) {
	t.Parallel()

	const containerID = "2222222222222222222222222222222222222222222222222222222222222222"
	labels := map[string]string{
		gitLabRunnerJobURLLabel: "https://gitlab.com/cicd-sensor/cicd-sensor-testing/-/jobs/777",
		gitLabRunnerJobIDLabel:  "777",
	}
	createBody, err := json.Marshal(map[string]any{"Image": "alpine", "Labels": labels})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	upstreamSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusCreated, containerCreateResponse{ID: containerID})
	}))

	got := make(chan string, 4)
	agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.Path
		if r.URL.Path == "/v1/gitlab/host/start" {
			t.Errorf("host_start must not be called for non-404 staging errors")
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))

	proxyClient := startProxyGitLab(t, upstreamSocket, agentSocket)
	resp, err := proxyClient.Post("http://docker/v1.43/containers/create", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("proxy create: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	assertAgentCalls(t, got, []string{"/v1/gitlab/staging/put"})
}

func TestProxy_GitLab_StagingNotFoundWithIdentityFallsThrough(t *testing.T) {
	t.Parallel()

	const containerID = "3333333333333333333333333333333333333333333333333333333333333333"
	labels := map[string]string{
		gitLabRunnerJobURLLabel: "https://gitlab.com/cicd-sensor/cicd-sensor-testing/-/jobs/777",
		gitLabRunnerJobIDLabel:  "777",
	}
	createBody, err := json.Marshal(map[string]any{"Image": "alpine", "Labels": labels})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	upstreamSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusCreated, containerCreateResponse{ID: containerID})
	}))

	got := make(chan string, 4)
	agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.Path
		switch r.URL.Path {
		case "/v1/gitlab/staging/put":
			writeJSON(t, w, http.StatusNotFound, map[string]string{"error": "job_not_found"})
		case "/v1/gitlab/host/start":
			t.Errorf("host_start must not be called; GitLab staging endpoint owns lazy start")
			writeJSON(t, w, http.StatusOK, map[string]string{"status": "ok"})
		default:
			t.Errorf("unexpected agent path: %q", r.URL.Path)
		}
	}))

	proxyClient := startProxyGitLab(t, upstreamSocket, agentSocket)
	resp, err := proxyClient.Post("http://docker/v1.43/containers/create", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("proxy create: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	assertAgentCalls(t, got, []string{"/v1/gitlab/staging/put"})
}

func TestProxy_GitLab_InvalidCreateResponseFallsThroughWithoutStaging(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "invalid json", body: "{"},
		{name: "missing id", body: `{"Warnings":[]}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstreamSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(tc.body))
			}))

			agentCalled := make(chan struct{}, 1)
			agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				agentCalled <- struct{}{}
				writeJSON(t, w, http.StatusOK, map[string]string{"status": "staged"})
			}))

			proxyClient := startProxyGitLab(t, upstreamSocket, agentSocket)
			resp, err := proxyClient.Post("http://docker/v1.43/containers/create", "application/json",
				bytes.NewReader([]byte(`{"Image":"alpine"}`)))
			if err != nil {
				t.Fatalf("proxy create: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusCreated)
			}
			gotBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}
			if string(gotBody) != tc.body {
				t.Fatalf("body: got %q, want %q", gotBody, tc.body)
			}

			select {
			case <-agentCalled:
				t.Fatal("agent unexpectedly received staging for invalid create response")
			case <-time.After(150 * time.Millisecond):
			}
		})
	}
}

// GitLab Job creation belongs to /v1/gitlab/staging/put. The proxy sends one
// request carrying peer PID plus labels identity; the listener creates a
// missing Job and stages the basename behind that route.
func TestProxy_GitLab_StagingCarriesIdentityForListenerLazyStart(t *testing.T) {
	t.Parallel()

	const containerID = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	labels := map[string]string{
		gitLabRunnerJobURLLabel: "https://gitlab.com/cicd-sensor/cicd-sensor-testing/-/jobs/777",
		gitLabRunnerJobIDLabel:  "777",
	}

	upstreamSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusCreated, containerCreateResponse{ID: containerID})
	}))

	type agentCall struct {
		path string
		body []byte
	}
	calls := make(chan agentCall, 4)
	agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls <- agentCall{path: r.URL.Path, body: body}
		switch r.URL.Path {
		case "/v1/gitlab/staging/put":
			writeJSON(t, w, http.StatusOK, map[string]string{"status": "staged"})
		case "/v1/gitlab/host/start":
			t.Errorf("host_start must not be called; GitLab staging endpoint owns lazy start")
			writeJSON(t, w, http.StatusOK, map[string]string{"status": "ok"})
		default:
			t.Errorf("unexpected agent path: %q", r.URL.Path)
		}
	}))

	proxyClient := startProxyGitLab(t, upstreamSocket, agentSocket)

	createBody, err := json.Marshal(map[string]any{"Image": "alpine", "Labels": labels})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := proxyClient.Post("http://docker/v1.43/containers/create", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("proxy create: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	select {
	case call := <-calls:
		if call.path != "/v1/gitlab/staging/put" {
			t.Fatalf("agent path: got %q, want /v1/gitlab/staging/put", call.path)
		}
		var req jobcontext.GitLabStagingPutRequest
		if err := json.Unmarshal(call.body, &req); err != nil {
			t.Fatalf("decode staging body: %v", err)
		}
		if req.JobIdentity == nil {
			t.Fatal("staging request missing job_identity")
		}
		if *req.JobIdentity != jobcontext.GitLabJobIdentity("gitlab.com", "cicd-sensor/cicd-sensor-testing", "777") {
			t.Fatalf("staging identity: got %+v", *req.JobIdentity)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("staging call not seen within 2s")
	}
	select {
	case extra := <-calls:
		t.Fatalf("unexpected extra agent call: %s", extra.path)
	case <-time.After(150 * time.Millisecond):
	}
}

// staging receives metadata from labels (trusted) and env (best-effort), with
// first-wins on env discarding `.gitlab-ci.yml variables:` spoof attempts.
func TestProxy_GitLab_StagingPropagatesMetadata(t *testing.T) {
	t.Parallel()

	const containerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	labels := map[string]string{
		gitLabRunnerJobURLLabel: "https://gitlab.com/rung/girogiro-testing/-/jobs/14499483701",
		gitLabRunnerJobIDLabel:  "14499483701",
		gitLabRunnerJobSHALabel: "c4c41b82483929ffab3abae20b60dd9f793400ba",
		gitLabRunnerJobRefLabel: "main",
	}
	env := []string{
		// gitlab-runner-injected predefined vars (these come first).
		"CI_PIPELINE_SOURCE=api",
		"CI_JOB_NAME=jirojiro-smoke",
		"GITLAB_USER_LOGIN=rung",
		// User-spoofed .gitlab-ci.yml `variables:` overrides (come later).
		// staging metadata must NOT pick these up (first-wins).
		"CI_PIPELINE_SOURCE=web",
		"GITLAB_USER_LOGIN=attacker",
	}

	upstreamSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusCreated, containerCreateResponse{ID: containerID})
	}))

	stagingReq := make(chan jobcontext.GitLabStagingPutRequest, 1)
	agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/gitlab/staging/put":
			body, _ := io.ReadAll(r.Body)
			var req jobcontext.GitLabStagingPutRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Errorf("decode staging body: %v", err)
			}
			stagingReq <- req
			writeJSON(t, w, http.StatusOK, map[string]string{"status": "staged"})
		case "/v1/gitlab/host/start":
			t.Errorf("host_start must not be called; GitLab staging endpoint owns lazy start")
			writeJSON(t, w, http.StatusOK, map[string]string{"status": "ok"})
		default:
			t.Errorf("unexpected agent path: %q", r.URL.Path)
		}
	}))

	proxyClient := startProxyGitLab(t, upstreamSocket, agentSocket)
	createBody, err := json.Marshal(map[string]any{"Image": "alpine", "Labels": labels, "Env": env})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := proxyClient.Post("http://docker/v1.43/containers/create", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("proxy create: %v", err)
	}
	resp.Body.Close()

	select {
	case got := <-stagingReq:
		wantIdentity := jobcontext.GitLabJobIdentity("gitlab.com", "rung/girogiro-testing", "14499483701")
		if got.JobIdentity == nil {
			t.Fatal("staging request missing job_identity")
		}
		if *got.JobIdentity != wantIdentity {
			t.Fatalf("identity: got %+v, want %+v", *got.JobIdentity, wantIdentity)
		}
		wantMetadata := jobcontext.JobMetadata{
			CommitSHA:     "c4c41b82483929ffab3abae20b60dd9f793400ba",
			RefName:       "main",
			Trigger:       "api",            // first-occurrence wins, not "web"
			ActorName:     "rung",           // first-occurrence wins, not "attacker"
			GitLabJobName: "jirojiro-smoke", // from CI_JOB_NAME
		}
		if got.Metadata != wantMetadata {
			t.Fatalf("metadata: got %+v, want %+v", got.Metadata, wantMetadata)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("staging request not seen within 2s")
	}
}

// cache-init carries labels but no env; the proxy must defer Job creation to
// predefined/build so env-sourced metadata makes it into the staging request.
func TestProxy_GitLab_CacheInitSkipped(t *testing.T) {
	t.Parallel()

	const containerID = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	labels := map[string]string{
		gitLabRunnerJobURLLabel: "https://gitlab.com/group/project/-/jobs/14499483701",
		gitLabRunnerJobIDLabel:  "14499483701",
		gitLabRunnerJobSHALabel: "c4c41b82483929ffab3abae20b60dd9f793400ba",
		gitLabRunnerJobRefLabel: "main",
		gitLabRunnerTypeLabel:   "cache-init",
	}

	upstreamSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusCreated, containerCreateResponse{ID: containerID})
	}))

	calls := make(chan string, 4)
	agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls <- r.URL.Path
		writeJSON(t, w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	proxyClient := startProxyGitLab(t, upstreamSocket, agentSocket)
	createBody, err := json.Marshal(map[string]any{"Image": "alpine", "Labels": labels})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := proxyClient.Post("http://docker/v1.43/containers/create", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("proxy create: %v", err)
	}
	resp.Body.Close()

	select {
	case path := <-calls:
		// staging without identity (peer_pid path) is acceptable; host_start is not.
		if path == "/v1/gitlab/host/start" {
			t.Fatalf("cache-init must not trigger host_start, but received call to %q", path)
		}
	case <-time.After(150 * time.Millisecond):
		// No call is also acceptable — proxy may skip both staging and host_start.
	}
	select {
	case path := <-calls:
		if path == "/v1/gitlab/host/start" {
			t.Fatalf("cache-init must not trigger host_start, but received call to %q", path)
		}
	case <-time.After(150 * time.Millisecond):
	}
}

// Multiple concurrent containers/create for the same identity must still make
// one staging request per container. The listener owns the per-identity lazy
// start barrier; the proxy must not add its own host/start sequence.
func TestProxy_GitLab_ConcurrentStagingRequests(t *testing.T) {
	t.Parallel()

	const N = 4
	labels := map[string]string{
		gitLabRunnerJobURLLabel: "https://gitlab.com/cicd-sensor/cicd-sensor-testing/-/jobs/14202203981",
		gitLabRunnerJobIDLabel:  "14202203981",
	}

	var counter atomic.Int32
	upstreamSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Each containers/create gets a distinct fake container id so
		// basenames do not collide across concurrent calls.
		n := counter.Add(1)
		cid := fmt.Sprintf("%064d", n)
		writeJSON(t, w, http.StatusCreated, containerCreateResponse{ID: cid})
	}))

	var stagingCalls atomic.Int32
	agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/gitlab/staging/put":
			stagingCalls.Add(1)
			writeJSON(t, w, http.StatusOK, map[string]string{"status": "staged"})
		case "/v1/gitlab/host/start":
			t.Errorf("host_start must not be called; GitLab staging endpoint owns lazy start")
			writeJSON(t, w, http.StatusOK, map[string]string{"status": "ok"})
		default:
			t.Errorf("unexpected agent path: %q", r.URL.Path)
		}
	}))

	proxyClient := startProxyGitLab(t, upstreamSocket, agentSocket)

	createBody, err := json.Marshal(map[string]any{"Image": "alpine", "Labels": labels})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			resp, err := proxyClient.Post("http://docker/v1.43/containers/create", "application/json", bytes.NewReader(createBody))
			if err != nil {
				errs[idx] = fmt.Errorf("post: %w", err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				errs[idx] = fmt.Errorf("status %d", resp.StatusCode)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		if e != nil {
			t.Errorf("goroutine %d: %v", i, e)
		}
	}
	if stagingCalls.Load() != N {
		t.Errorf("expected %d staging calls, got %d", N, stagingCalls.Load())
	}
}

func TestPostStagingErrorsIncludeResponseBody(t *testing.T) {
	t.Parallel()

	agentSocket := startUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/github/staging/put", "/v1/gitlab/staging/put":
			http.Error(w, "agent boom", http.StatusTeapot)
		default:
			t.Errorf("unexpected path: %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))

	if err := postGitHubStaging(context.Background(), agentSocket, jobcontext.GitHubStagingPutRequest{
		Basename: "docker-deadbeef.scope",
		PeerPID:  int32(os.Getpid()),
	}); err == nil || !strings.Contains(err.Error(), "agent boom") {
		t.Fatalf("postGitHubStaging error = %v, want body included", err)
	}

	identity := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "42")
	if err := postGitLabStaging(context.Background(), agentSocket, "docker-deadbeef.scope", int32(os.Getpid()), &identity, jobcontext.JobMetadata{}); err == nil || !strings.Contains(err.Error(), "agent boom") {
		t.Fatalf("postGitLabStaging error = %v, want body included", err)
	}
}

// startProxy listens on a fresh unix socket, returns an http.Client whose
// transport dials it, and registers cleanup. The proxy forwards to
// upstreamSocket and stages container ids via agentSocket using the
// GitHub-mode handler.
func startProxy(t *testing.T, upstreamSocket, agentSocket string) *http.Client {
	t.Helper()
	return startProxyWithHandler(t, proxyHandlerGitHub(slog.New(slog.NewTextHandler(io.Discard, nil)), upstreamSocket, agentSocket))
}

// startProxyGitLab is the GitLab-mode counterpart to startProxy.
func startProxyGitLab(t *testing.T, upstreamSocket, agentSocket string) *http.Client {
	t.Helper()
	return startProxyWithHandler(t, proxyHandlerGitLab(slog.New(slog.NewTextHandler(io.Discard, nil)), upstreamSocket, agentSocket))
}

func startProxyWithHandler(t *testing.T, handler http.Handler) *http.Client {
	t.Helper()

	dir, err := os.MkdirTemp("", "proxy-test-")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	listenSocket := filepath.Join(dir, "proxy.sock")
	ln, err := net.Listen("unix", listenSocket)
	if err != nil {
		t.Fatalf("listen %s: %v", listenSocket, err)
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext:       connContext,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ln) }()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		<-done
	})

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", listenSocket)
			},
		},
	}
	return client
}

// startUnixServer listens on a fresh unix socket and serves handler. It
// returns the socket path and registers cleanup.
func startUnixServer(t *testing.T, handler http.Handler) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "unix-server-")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	socket := filepath.Join(dir, "u.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}

	done := make(chan error, 1)
	go func() { done <- server.Serve(ln) }()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		<-done
	})

	return socket
}

func writeJSON(t *testing.T, w http.ResponseWriter, code int, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("write json: %v", err)
	}
}

func assertAgentCalls(t *testing.T, calls <-chan string, want []string) {
	t.Helper()
	for i, wantPath := range want {
		select {
		case got := <-calls:
			if got != wantPath {
				t.Fatalf("call %d: got %q, want %q", i, got, wantPath)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("call %d (%s) not seen within 2s", i, wantPath)
		}
	}
	select {
	case extra := <-calls:
		t.Fatalf("unexpected extra agent call: %s", extra)
	case <-time.After(150 * time.Millisecond):
	}
}

func mustURL(t *testing.T, path string) *url.URL {
	t.Helper()
	u, err := url.Parse("http://docker" + path)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dockerd-")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func assertPositivePeerPIDOnLinux(t *testing.T, pid int32) {
	t.Helper()
	if runtime.GOOS != "linux" {
		return
	}
	if pid <= 0 {
		t.Fatalf("peer_pid: got %d, want positive peer pid", pid)
	}
}

func waitForSocketOrRunExit(t *testing.T, path string, errCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case err := <-errCh:
			t.Fatalf("Run returned before socket creation: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %q was not created", path)
}
