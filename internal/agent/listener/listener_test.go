package listener_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/listener"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestListener_SecondServeReturnsAlreadyRunning(t *testing.T) {
	dir := newTestSocketDir(t, "cicd-sensor-test-")
	defer os.RemoveAll(dir)

	sock := filepath.Join(dir, "t.sock")

	ctx1, cancel1 := context.WithCancel(context.Background())
	jr1 := jobregistry.New(testLogger)
	l1 := listener.New(listener.Config{
		Logger:                testLogger,
		JobRegistry:           jr1,
		SocketPath:            sock,
		HostManagerConnection: managerclient.Connection{},
		RunnerType:            "machine",
		Provider:              jobcontext.ProviderGitHub,
	})
	errCh1 := make(chan error, 1)
	go func() { errCh1 <- l1.Serve(ctx1) }()

	deadline := time.After(3 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		select {
		case err := <-errCh1:
			skipIfListenPermissionDenied(t, err)
			t.Fatalf("first listener failed to start: %v", err)
		case <-deadline:
			t.Fatal("socket did not appear within timeout")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	jr2 := jobregistry.New(testLogger)
	l2 := listener.New(listener.Config{
		Logger:                testLogger,
		JobRegistry:           jr2,
		SocketPath:            sock,
		HostManagerConnection: managerclient.Connection{},
		RunnerType:            "machine",
		Provider:              jobcontext.ProviderGitHub,
	})
	if err := l2.Serve(ctx2); !errors.Is(err, listener.ErrAlreadyRunning) {
		t.Fatalf("second listener error: got %v, want %v", err, listener.ErrAlreadyRunning)
	}

	cancel1()
	if err := <-errCh1; err != nil {
		t.Fatalf("first listener shutdown: %v", err)
	}
}

func TestListener_RemovesStaleSocketBeforeServe(t *testing.T) {
	dir := newTestSocketDir(t, "cicd-sensor-stale-socket-test-")
	defer os.RemoveAll(dir)

	sock := filepath.Join(dir, "t.sock")
	staleListener, err := net.Listen("unix", sock)
	if err != nil {
		skipIfListenPermissionDenied(t, err)
		t.Fatalf("create stale socket: %v", err)
	}
	if err := staleListener.Close(); err != nil {
		t.Fatalf("close stale socket: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	registry := jobregistry.New(testLogger)
	l := listener.New(listener.Config{
		Logger:                testLogger,
		JobRegistry:           registry,
		SocketPath:            sock,
		HostManagerConnection: managerclient.Connection{},
		RunnerType:            "machine",
		Provider:              jobcontext.ProviderGitHub,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- l.Serve(ctx) }()

	deadline := time.After(3 * time.Second)
	for {
		if conn, err := net.DialTimeout("unix", sock, 100*time.Millisecond); err == nil {
			conn.Close()
			break
		}
		select {
		case err := <-errCh:
			skipIfListenPermissionDenied(t, err)
			t.Fatalf("listener failed to start: %v", err)
		case <-deadline:
			t.Fatal("listener did not replace stale socket within timeout")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("listener shutdown: %v", err)
	}
}

func TestListener_CreatesWorldConnectableSocket(t *testing.T) {
	dir := newTestSocketDir(t, "cicd-sensor-socket-mode-test-")
	defer os.RemoveAll(dir)

	sock := filepath.Join(dir, "t.sock")
	ctx, cancel := context.WithCancel(context.Background())
	registry := jobregistry.New(testLogger)
	l := listener.New(listener.Config{
		Logger:                testLogger,
		JobRegistry:           registry,
		SocketPath:            sock,
		HostManagerConnection: managerclient.Connection{},
		RunnerType:            "machine",
		Provider:              jobcontext.ProviderGitHub,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- l.Serve(ctx) }()

	deadline := time.After(3 * time.Second)
	for {
		fi, err := os.Stat(sock)
		if err == nil {
			if got, want := fi.Mode().Perm(), os.FileMode(0o777); got != want {
				t.Fatalf("socket mode: got %v, want %v", got, want)
			}
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

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("listener shutdown: %v", err)
	}
}

func TestListener_RegularFileSocketPathReturnsError(t *testing.T) {
	dir := newTestSocketDir(t, "cicd-sensor-regular-file-test-")
	defer os.RemoveAll(dir)

	sock := filepath.Join(dir, "t.sock")
	if err := os.WriteFile(sock, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := jobregistry.New(testLogger)
	l := listener.New(listener.Config{
		Logger:                testLogger,
		JobRegistry:           registry,
		SocketPath:            sock,
		HostManagerConnection: managerclient.Connection{},
		RunnerType:            "machine",
		Provider:              jobcontext.ProviderGitHub,
	})
	if err := l.Serve(ctx); err == nil {
		t.Fatal("Serve returned nil, want listen error")
	}
}
