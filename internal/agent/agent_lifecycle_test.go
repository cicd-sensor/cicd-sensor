package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

var lifecycleTestLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestNewAgentDefaultsNilLogger(t *testing.T) {
	t.Parallel()

	a := NewAgent(nil, "/tmp/cicd-sensor-test.sock", jobcontext.ProviderGitHub, "machine", managerclient.Connection{}, nil)
	if a.logger == nil {
		t.Fatal("logger is nil")
	}
	if a.provider != jobcontext.ProviderGitHub {
		t.Fatalf("provider: got %q, want %q", a.provider, jobcontext.ProviderGitHub)
	}
	if a.runnerType != "machine" {
		t.Fatalf("runner type: got %q, want machine", a.runnerType)
	}
}

func TestSetShutdownGrace(t *testing.T) {
	t.Parallel()

	a := NewAgent(lifecycleTestLogger, "/tmp/cicd-sensor-test.sock", jobcontext.ProviderGitHub, "machine", managerclient.Connection{}, nil)
	a.SetShutdownGrace(0)
	if a.shutdownGrace != 0 {
		t.Fatalf("zero grace changed shutdownGrace to %s", a.shutdownGrace)
	}
	a.SetShutdownGrace(-time.Second)
	if a.shutdownGrace != 0 {
		t.Fatalf("negative grace changed shutdownGrace to %s", a.shutdownGrace)
	}
	a.SetShutdownGrace(123 * time.Millisecond)
	if a.shutdownGrace != 123*time.Millisecond {
		t.Fatalf("shutdownGrace: got %s, want 123ms", a.shutdownGrace)
	}
}

func TestAgentRunStopsOnContextCancel(t *testing.T) {
	socketPath := filepath.Join(newAgentTestSocketDir(t), "agent.sock")
	a := NewAgent(lifecycleTestLogger, socketPath, jobcontext.ProviderGitHub, "machine", managerclient.Connection{}, nil)
	a.SetShutdownGrace(time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- a.Run(ctx)
	}()

	waitForAgentSocketOrExit(t, socketPath, errCh)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error after cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop after context cancel")
	}
}

func TestAgentRunReturnsListenerError(t *testing.T) {
	dir := newAgentTestSocketDir(t)
	socketPath := filepath.Join(dir, "agent.sock")
	if err := os.WriteFile(socketPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}

	a := NewAgent(lifecycleTestLogger, socketPath, jobcontext.ProviderGitHub, "machine", managerclient.Connection{}, nil)
	err := a.Run(context.Background())
	if err == nil {
		t.Fatal("Run returned nil, want listener error")
	}
	skipIfKernelTrackerUnavailable(t, err)
	if !strings.Contains(err.Error(), "agent:") {
		t.Fatalf("error %q does not contain agent prefix", err)
	}
}

func TestShutdownCancelsAndDrainsKernelTrackerLoop(t *testing.T) {
	t.Parallel()

	cancelled := make(chan struct{})
	done := make(chan error, 1)
	a := &Agent{
		logger:        lifecycleTestLogger,
		shutdownGrace: time.Second,
		cancelEngine: func() {
			close(cancelled)
			done <- nil
		},
		engineDone: done,
	}

	a.shutdown(context.Background())

	select {
	case <-cancelled:
	default:
		t.Fatal("shutdown did not cancel engine")
	}
}

func newAgentTestSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(agentTestSocketBaseDir(), "cicd-sensor-agent-")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func agentTestSocketBaseDir() string {
	if base := os.Getenv("CICD_SENSOR_TEST_SOCKET_DIR"); base != "" {
		return base
	}
	if runtime.GOOS == "darwin" {
		return "/private/tmp"
	}
	return ""
}

func waitForAgentSocketOrExit(t *testing.T, socketPath string, errCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			return
		}
		select {
		case err := <-errCh:
			skipIfAgentSocketPermissionDenied(t, err)
			skipIfKernelTrackerUnavailable(t, err)
			t.Fatalf("Run returned before socket creation: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %q was not created", socketPath)
}

func skipIfAgentSocketPermissionDenied(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "operation not permitted") {
		t.Skipf("socket listen is not permitted in this test environment: %v", err)
	}
}

func skipIfKernelTrackerUnavailable(t *testing.T, err error) {
	t.Helper()
	if runtime.GOOS == "linux" && strings.Contains(err.Error(), "new kernel tracker") {
		t.Skipf("kernel tracker is unavailable in this test environment: %v", err)
	}
}
