package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPostSocket(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		handler     http.Handler
		socketPath  string
		wantErrText string
	}{
		{
			name: "success returns nil",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/project/start" {
					t.Fatalf("path: got %q, want /v1/project/start", r.URL.Path)
				}
				w.WriteHeader(http.StatusOK)
			}),
		},
		{
			name:        "connection failure is returned",
			socketPath:  filepath.Join(t.TempDir(), "missing.sock"),
			wantErrText: "post /v1/project/start:",
		},
		{
			name: "server error returns response body",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			}),
			wantErrText: "agent returned status 500: boom",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			socketPath := tc.socketPath
			if socketPath == "" {
				socketPath = newShortSocketPath(t)
			}

			var server *httptest.Server
			if tc.handler != nil {
				server = newUnixSocketTestServer(t, socketPath, tc.handler)
				defer server.Close()
			}

			err := postSocket(context.Background(), socketPath, "/v1/project/start", map[string]string{"status": "ok"})
			if tc.wantErrText == "" {
				if err != nil {
					t.Fatalf("postSocket: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected postSocket error")
			}
			if !strings.Contains(err.Error(), tc.wantErrText) {
				t.Fatalf("error: got %q, want substring %q", err.Error(), tc.wantErrText)
			}
		})
	}
}

func TestPostSocketForResponseReturnsBody(t *testing.T) {
	t.Parallel()

	socketPath := newShortSocketPath(t)
	server := newUnixSocketTestServer(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/project/result" {
			t.Fatalf("path: got %q, want /v1/project/result", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content-type: got %q, want application/json", r.Header.Get("Content-Type"))
		}
		if _, err := w.Write([]byte(`{"result":"ok"}`)); err != nil {
			t.Fatalf("write response: %v", err)
		}
	}))
	defer server.Close()

	got, err := postSocketForResponse(context.Background(), socketPath, "/v1/project/result", map[string]string{"status": "ok"}, 1<<10)
	if err != nil {
		t.Fatalf("postSocketForResponse: %v", err)
	}
	if string(got) != `{"result":"ok"}` {
		t.Fatalf("body: got %q", got)
	}
}

func newShortSocketPath(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp(testSocketBaseDir(), "cicd-sensor-cmd-test-")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "cicd-sensor.sock")
}

func testSocketBaseDir() string {
	if base := os.Getenv("CICD_SENSOR_TEST_SOCKET_DIR"); base != "" {
		return base
	}
	if runtime.GOOS == "darwin" {
		return "/private/tmp"
	}
	return ""
}

func newUnixSocketTestServer(t *testing.T, socketPath string, handler http.Handler) *httptest.Server {
	t.Helper()

	if err := os.RemoveAll(socketPath); err != nil {
		t.Fatalf("remove old socket: %v", err)
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("unix socket listen is not permitted in this test environment: %v", err)
		}
		t.Fatalf("listen unix socket: %v", err)
	}

	server := httptest.NewUnstartedServer(handler)
	server.Listener = ln
	server.Start()
	return server
}
