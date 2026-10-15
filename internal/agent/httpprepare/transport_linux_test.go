//go:build linux

package httpprepare

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestPreparationRequest(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, url      string
		allowed, fails bool
		status         int
	}{
		{name: "authorized PID", url: "/prepare?pid=123&daemon_pid=0", allowed: true, status: 204},
		{name: "unauthorized peer", url: "/prepare?pid=123&daemon_pid=0", status: 403},
		{name: "negative PID", url: "/prepare?pid=-1&daemon_pid=0", allowed: true, status: 400},
		{name: "overflow PID", url: "/prepare?pid=2147483648&daemon_pid=0", allowed: true, status: 400},
		{name: "malformed daemon PID", url: "/prepare?pid=123&daemon_pid=x", allowed: true, status: 400},
		{name: "missing PID", url: "/prepare", allowed: true, status: 400},
		{name: "unknown route", url: "/stage?pid=123&daemon_pid=0", allowed: true, status: 404},
		{name: "worker rejection", url: "/prepare?pid=123&daemon_pid=0", allowed: true, fails: true, status: 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			handler := preparationHandler(func(ctx context.Context, p Process) error {
				calls++
				if p != (Process{PID: 123}) {
					t.Errorf("process=%+v", p)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Error("missing deadline")
				}
				if tc.fails {
					return errors.New("queue full")
				}
				return nil
			}, nil)
			r := httptest.NewRequest(http.MethodPost, tc.url, nil)
			r = r.WithContext(context.WithValue(r.Context(), peerAllowedKey{}, tc.allowed))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, r)
			if response.Code != tc.status {
				t.Fatalf("status=%d want=%d", response.Code, tc.status)
			}
			if tc.status != 204 && tc.status != 503 && calls != 0 {
				t.Fatal("invalid request reached worker")
			}
		})
	}
}

func servePreparationTest(t *testing.T, handler Handler) string {
	t.Helper()
	// Keep the Unix path under Linux's 108-byte limit even with long test names.
	root, err := os.MkdirTemp("", "prep-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	agentSocket := filepath.Join(root, "agent.sock")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, SocketPath(agentSocket), handler, nil) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	for {
		if info, err := os.Stat(SocketPath(agentSocket)); err == nil && info.Mode().Perm() == 0o600 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server not ready")
		}
		time.Sleep(time.Millisecond)
	}
	return agentSocket
}

func TestPreparationUnixHTTP(t *testing.T) {
	for _, tc := range []struct {
		name           string
		blocked, fails bool
	}{
		{name: "PID delivered over same-UID socket"},
		{name: "worker error returned", fails: true},
		{name: "blocked work cannot hold caller", blocked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered := make(chan Process, 1)
			release := make(chan struct{})
			completed := make(chan struct{})
			socket := servePreparationTest(t, func(ctx context.Context, p Process) error {
				defer close(completed)
				entered <- p
				if tc.blocked {
					<-release
				}
				if tc.fails {
					return errors.New("worker rejected")
				}
				return nil
			})
			defer func() { close(release); <-completed }()
			start := time.Now()
			err := NewRemote(socket).Prepare(t.Context(), Process{PID: os.Getpid(), DaemonPID: os.Getpid()})
			if (err != nil) != (tc.blocked || tc.fails) {
				t.Fatalf("error=%v", err)
			}
			if time.Since(start) > 2*Budget {
				t.Fatal("caller exceeded timeout tolerance")
			}
			if p := <-entered; p.PID != os.Getpid() || p.DaemonPID != os.Getpid() {
				t.Fatal(p)
			}
			if err := Serve(t.Context(), SocketPath(socket), func(context.Context, Process) error { return nil }, nil); err == nil {
				t.Fatal("active socket replaced")
			}
		})
	}
}

func TestPreparationSocketDoesNotReplaceFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Serve(t.Context(), path, func(context.Context, Process) error { return nil }, nil); err == nil {
		t.Fatal("regular file replaced")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "keep" {
		t.Fatalf("file changed: %q %v", data, err)
	}
}

func TestProcessOpenProc(t *testing.T) {
	// The daemon path checks PID 1's namespace, which may require privileges.
	// Ordinary tests verify permission failure; privileged runs verify success.
	var daemonErr error
	if _, err := os.Stat("/proc/1/ns/pid"); err != nil {
		if !errors.Is(err, os.ErrPermission) {
			t.Fatal(err)
		}
		daemonErr = os.ErrPermission
	}
	for _, tc := range []struct {
		name    string
		process Process
		wantErr error
	}{
		{name: "host PID resolves its process root", process: Process{PID: os.Getpid()}},
		{name: "daemon PID view requires namespace access", process: Process{PID: os.Getpid(), DaemonPID: os.Getpid()}, wantErr: daemonErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proc, err := tc.process.OpenProc()
			if proc != nil {
				defer proc.Close()
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			actual, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d/root", proc.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			expected, err := os.Stat("/")
			if err != nil || !os.SameFile(actual, expected) {
				t.Fatal("wrong process root")
			}
		})
	}
}

func TestPreparationUnavailable(t *testing.T) {
	// No filesystem resolution is attempted by the producer, even for a valid PID.
	socket := filepath.Join(t.TempDir(), "absent")
	if err := NewRemote(socket).Prepare(t.Context(), Process{PID: os.Getpid()}); err == nil {
		t.Fatal("missing socket accepted")
	}
}

// This subprocess drops every capability before sending another process's PID.
// Notification must not require SYS_PTRACE or any target filesystem access.
func TestPreparationClientWithoutCapabilities(t *testing.T) {
	if socket := os.Getenv("CICD_PID_CLIENT_SOCKET"); socket != "" {
		header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		data := [2]unix.CapUserData{}
		if err := unix.Capset(&header, &data[0]); err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(os.Getenv("CICD_PID_CLIENT_TARGET"))
		if err != nil {
			t.Fatal(err)
		}
		if err := NewRemote(socket).Prepare(t.Context(), Process{PID: pid}); err != nil {
			t.Fatal(err)
		}
		return
	}
	target := Process{PID: os.Getpid()}
	socket := servePreparationTest(t, func(_ context.Context, p Process) error {
		if p != target {
			return fmt.Errorf("unexpected PID %d", p.PID)
		}
		return nil
	})
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestPreparationClientWithoutCapabilities$")
	cmd.Env = append(os.Environ(), "CICD_PID_CLIENT_SOCKET="+socket, "CICD_PID_CLIENT_TARGET="+strconv.Itoa(target.PID))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("capability-free client: %v %s", err, output)
	}
}

func TestOpenProcDoesNotKeepExitedProcessAlive(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	proc, err := (Process{PID: cmd.Process.Pid}).OpenProc()
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	_, err = os.Stat(fmt.Sprintf("/proc/self/fd/%d/root", proc.Fd()))
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ESRCH) {
		t.Fatalf("exited proc root remains accessible: %v", err)
	}
}

func TestProcessValidationBounds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		process Process
		valid   bool
	}{
		{name: "zero PID is not a process"},
		{name: "negative daemon PID is rejected", process: Process{PID: 1, DaemonPID: -1}},
		{name: "largest signed PID is representable", process: Process{PID: 2147483647, DaemonPID: 2147483647}, valid: true},
		{name: "daemon PID overflow is rejected", process: Process{PID: 1, DaemonPID: 2147483648}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.process.Validate(); (err == nil) != tc.valid {
				t.Fatalf("validation=%v valid=%t", err, tc.valid)
			}
		})
	}
}

func TestPreparationNilHandler(t *testing.T) {
	if err := Serve(t.Context(), filepath.Join(t.TempDir(), "absent.sock"), nil, nil); err == nil {
		t.Fatal("nil handler accepted")
	}
}

func TestPreparationIncompleteBodyDoesNotRetainConnection(t *testing.T) {
	socket := servePreparationTest(t, func(context.Context, Process) error { return nil })
	conn, err := net.Dial("unix", SocketPath(socket))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * Budget)); err != nil {
		t.Fatal(err)
	}
	// A malformed sender announces a body and never sends it. Even though the
	// handler reads no body, net/http may drain it before finishing the response.
	if _, err := io.WriteString(conn, "POST /prepare?pid=1&daemon_pid=0 HTTP/1.1\r\nHost: agent\r\nContent-Length: 1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("server retained an incomplete request: %v", err)
	}
}
