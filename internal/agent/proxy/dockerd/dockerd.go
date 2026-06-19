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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

const (
	listenerShutdownTimeout = 5 * time.Second
	headerReadTimeout       = 30 * time.Second
	driverCheckTimeout      = 5 * time.Second
	// GitHub staging is on the docker create response path, so keep the
	// agent wait bounded and fail open if the agent is wedged.
	agentPostTimeout = 1 * time.Second
	// GitLab staging may create a missing Job behind the listener route, so it
	// needs a larger bounded fail-open budget than GitHub's staging-only path.
	agentGitLabStagingTimeout = 5 * time.Second
)

// Options carries the proxy runtime configuration.
type Options struct {
	DockerDaemonSocket string
	DockerProxySocket  string
	AgentSocket        string
	Provider           jobcontext.Provider
}

// Run starts the proxy and blocks until ctx is cancelled or the listener fails.
func Run(ctx context.Context, logger *slog.Logger, opts Options) error {
	if opts.DockerDaemonSocket == "" || opts.DockerProxySocket == "" || opts.AgentSocket == "" {
		return fmt.Errorf("upstream-socket, listen-socket, and agent-socket are required")
	}
	if sameUnixSocketPath(opts.DockerDaemonSocket, opts.DockerProxySocket) {
		return fmt.Errorf("upstream-socket and listen-socket must be different: %q", opts.DockerProxySocket)
	}
	var handler http.Handler
	switch opts.Provider {
	case jobcontext.ProviderGitHub:
		handler = proxyHandlerGitHub(logger, opts.DockerDaemonSocket, opts.AgentSocket)
	case jobcontext.ProviderGitLab:
		handler = proxyHandlerGitLab(logger, opts.DockerDaemonSocket, opts.AgentSocket)
	default:
		return fmt.Errorf("provider must be github or gitlab, got %q", opts.Provider)
	}

	if err := checkDriver(ctx, opts.DockerDaemonSocket); err != nil {
		return fmt.Errorf("driver check: %w", err)
	}
	logger.InfoContext(ctx, "driver_check_ok", "driver", "systemd")

	if err := os.Remove(opts.DockerProxySocket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove existing docker proxy socket %q: %w", opts.DockerProxySocket, err)
	}
	listener, err := net.Listen("unix", opts.DockerProxySocket)
	if err != nil {
		return fmt.Errorf("listen on %q: %w", opts.DockerProxySocket, err)
	}
	defer func() { _ = os.Remove(opts.DockerProxySocket) }()

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: headerReadTimeout,
		ConnContext:       connContext,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	logger.InfoContext(ctx, "proxy_started",
		"docker_proxy_socket", opts.DockerProxySocket,
		"docker_daemon_socket", opts.DockerDaemonSocket,
		"agent_socket", opts.AgentSocket,
		"provider", string(opts.Provider),
	)

	select {
	case <-ctx.Done():
		logger.InfoContext(ctx, "proxy_stopping")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), listenerShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	}
}

func sameUnixSocketPath(a, b string) bool {
	return canonicalUnixSocketPath(a) == canonicalUnixSocketPath(b)
}

func canonicalUnixSocketPath(path string) string {
	if path == "" {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return filepath.Clean(resolved)
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	if resolvedDir, err := filepath.EvalSymlinks(dir); err == nil {
		return filepath.Join(resolvedDir, base)
	}
	return filepath.Clean(path)
}

// driverInfo is the slice of GET /info this proxy needs.
type driverInfo struct {
	CgroupDriver string `json:"CgroupDriver"`
}

// containerCreateResponse is the slice of the response the proxy peeks to
// extract the assigned container id.
type containerCreateResponse struct {
	ID string `json:"Id"`
}

// peerPIDCtxKey carries SO_PEERCRED.PID from net.Conn into the http handler.
type peerPIDCtxKey struct{}

// unixDialClient returns an HTTP client that always dials the given unix socket.
func unixDialClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// checkDriver requires systemd cgroups because staging keys are docker-<cid>.scope basenames.
func checkDriver(ctx context.Context, upstreamSocket string) error {
	client := unixDialClient(upstreamSocket)
	client.Timeout = driverCheckTimeout

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/info", nil)
	if err != nil {
		return fmt.Errorf("build /info request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("dockerd /info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dockerd /info returned status %d", resp.StatusCode)
	}

	var info driverInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return fmt.Errorf("decode /info: %w", err)
	}
	if info.CgroupDriver != "systemd" {
		return fmt.Errorf("dockerd cgroup driver %q is not supported (systemd cgroup driver is required)", info.CgroupDriver)
	}
	return nil
}

// isContainerCreate matches both versioned (/v1.43/containers/create) and
// unversioned paths the docker CLI emits.
func isContainerCreate(req *http.Request) bool {
	if req == nil || req.Method != http.MethodPost {
		return false
	}
	path := req.URL.Path
	return path == "/containers/create" || strings.HasSuffix(path, "/containers/create")
}

// postAgent does the unix-dial POST and returns the response status code
// and body. Callers branch on status to map to specific errors.
func postAgent(ctx context.Context, agentSocket, path string, body []byte) (int, string, error) {
	client := unixDialClient(agentSocket)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://cicd-sensor"+path, bytes.NewReader(body))
	if err != nil {
		return 0, "", fmt.Errorf("build %s request: %w", path, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, "", fmt.Errorf("post %s: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(respBody)), nil
}
