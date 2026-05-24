// Package listener serves the agent's Unix control socket and maps provider
// routes onto JobRegistry.
package listener

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// ErrAlreadyRunning reports that another agent already owns the socket.
var ErrAlreadyRunning = errors.New("agent already running")

const (
	// project/start may carry project-local rules expanded into JSON.
	controlRequestBodyMaxBytes = 16 << 20
	// project/result returns renderer input, so allow richer payloads than
	// normal control responses while staying below the request body cap.
	projectResultMaxBytes = 10 << 20

	listenerReadHeaderTimeout = 5 * time.Second
	listenerReadTimeout       = 30 * time.Second
	listenerWriteTimeout      = 30 * time.Second
	listenerIdleTimeout       = 60 * time.Second
	listenerShutdownTimeout   = 5 * time.Second
	controlSocketMode         = 0o777
)

// Listener serves the control socket API over a unix domain socket.
type Listener struct {
	logger            *slog.Logger
	jobRegistry       *jobregistry.JobRegistry
	socketPath        string
	hostManagerConn   managerclient.Connection
	hostManagerClient jobregistry.ManagerConfigFetcher
	runnerType        string
	provider          jobcontext.Provider
	server            *http.Server
}

// Config is the process-wide listener configuration. Project manager inputs
// remain request-local in project/start.
type Config struct {
	Logger                *slog.Logger
	JobRegistry           *jobregistry.JobRegistry
	SocketPath            string
	HostManagerConnection managerclient.Connection
	HostManagerClient     jobregistry.ManagerConfigFetcher
	RunnerType            string
	Provider              jobcontext.Provider
}

// New creates a listener bound to cfg.SocketPath.
func New(cfg Config) *Listener {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	l := &Listener{
		logger:            logger.With("component", "listener"),
		jobRegistry:       cfg.JobRegistry,
		socketPath:        cfg.SocketPath,
		hostManagerConn:   cfg.HostManagerConnection,
		hostManagerClient: cfg.HostManagerClient,
		runnerType:        cfg.RunnerType,
		provider:          cfg.Provider,
	}
	mux := http.NewServeMux()
	switch cfg.Provider {
	case jobcontext.ProviderGitHub:
		mux.HandleFunc("POST /v1/github/job/health", l.handleGitHubJobHealth)
		mux.HandleFunc("POST /v1/github/host/start", l.handleGitHubHostStart)
		mux.HandleFunc("POST /v1/github/host/end", l.handleGitHubHostEnd)
		mux.HandleFunc("POST /v1/github/project/start", l.handleGitHubProjectStart)
		mux.HandleFunc("POST /v1/github/project/result", l.handleGitHubProjectResult)
		mux.HandleFunc("POST /v1/github/staging/put", l.handleGitHubStagingPut)
	case jobcontext.ProviderGitLab:
		mux.HandleFunc("POST /v1/gitlab/host/start", l.handleGitLabHostStart)
		mux.HandleFunc("POST /v1/gitlab/staging/put", l.handleGitLabStagingPut)
	}
	l.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: listenerReadHeaderTimeout,
		ReadTimeout:       listenerReadTimeout,
		WriteTimeout:      listenerWriteTimeout,
		IdleTimeout:       listenerIdleTimeout,
		ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			return context.WithValue(ctx, unixConnKey{}, connection)
		},
	}
	return l
}

// Serve starts the Unix socket listener.
func (l *Listener) Serve(ctx context.Context) error {
	// /run is tmpfs on many hosts; create only the parent directory here.
	if dir := filepath.Dir(l.socketPath); dir != "" && dir != "." && dir != "/" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create socket directory %s: %w", dir, err)
		}
	}

	// A live socket means another daemon owns the path; a dead one is stale.
	if fi, err := os.Stat(l.socketPath); err == nil && fi.Mode().Type() == os.ModeSocket {
		conn, dialErr := net.DialTimeout("unix", l.socketPath, 200*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			l.logger.InfoContext(ctx, "listener_existing_daemon_detected", "socket", l.socketPath)
			return ErrAlreadyRunning
		}
		if err := os.Remove(l.socketPath); err != nil {
			return fmt.Errorf("remove stale socket %s: %w", l.socketPath, err)
		}
	}

	ln, err := net.Listen("unix", l.socketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", l.socketPath, err)
	}
	if err := os.Chmod(l.socketPath, controlSocketMode); err != nil {
		_ = ln.Close()
		return fmt.Errorf("chmod socket %s: %w", l.socketPath, err)
	}
	l.logger.InfoContext(ctx, "listener_started", "socket", l.socketPath)

	errCh := make(chan error, 1)
	go func() {
		err := l.server.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		l.logger.InfoContext(ctx, "listener_stopping")
		// Control-plane requests are small; keep shutdown tight.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), listenerShutdownTimeout)
		defer cancel()
		if err := l.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown: %w", err)
		}
		if err := os.Remove(l.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			l.logger.WarnContext(ctx, "listener_socket_cleanup_failed",
				"socket", l.socketPath,
				"error", err,
			)
		}
		return nil
	case err := <-errCh:
		return err
	}
}
