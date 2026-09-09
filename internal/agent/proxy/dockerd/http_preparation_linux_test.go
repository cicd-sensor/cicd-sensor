//go:build linux && bpf_integration

package dockerd

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

func TestStartResponsePreparation(t *testing.T) {
	for _, tc := range []struct {
		name             string
		status           int
		timeout, prepare bool
	}{
		{"successful start waits for exact file preparation", 204, false, true},
		{"timeout returns successful start while cleanup continues", 204, true, true},
		{"already running is not a new start", 304, false, false},
		{"failed start preserves daemon failure", 500, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, err := os.MkdirTemp("", "http-prep-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			id := strings.Repeat("a", 64)
			if err := os.WriteFile(filepath.Join(root, "gh"), []byte("fixture target"), 0o755); err != nil {
				t.Fatal(err)
			}
			upstreamSocket := filepath.Join(root, "docker.sock")
			agentSocket := filepath.Join(root, "agent.sock")
			listener, err := net.Listen("unix", upstreamSocket)
			if err != nil {
				t.Fatal(err)
			}
			daemon := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/containers/" + id + "/start":
					w.WriteHeader(tc.status)
				case "/containers/" + id + "/json":
					_ = json.NewEncoder(w).Encode(map[string]any{"Id": id, "State": map[string]any{"Running": true, "Pid": os.Getpid()}, "Config": map[string]any{"Env": []string{"PATH=" + root}}})
				default:
					t.Errorf("unexpected daemon request %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}), ReadHeaderTimeout: time.Second}
			go func() { _ = daemon.Serve(listener) }()
			defer daemon.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			entered := make(chan string, 1)
			release := make(chan struct{})
			served := make(chan error, 1)
			go func() {
				served <- httpprepare.Serve(ctx, httpprepare.SocketPath(agentSocket), func(_ context.Context, files []*os.File, options kernelio.HTTPPreparationOptions) (kernelio.HTTPPreparationResult, error) {
					defer httpprepare.CloseFiles(files)
					entered <- options.Source
					<-release
					return kernelio.HTTPPreparationResult{Prepared: len(files)}, nil
				}, nil)
			}()
			defer func() {
				cancel()
				if err := <-served; err != nil {
					t.Error(err)
				}
			}()
			deadline := time.Now().Add(time.Second)
			for {
				connection, dialErr := net.Dial("unixpacket", httpprepare.SocketPath(agentSocket))
				if dialErr == nil {
					_ = connection.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("receiver not ready")
				}
				time.Sleep(time.Millisecond)
			}
			handler := proxyHandlerGitHub(slog.Default(), upstreamSocket, agentSocket)
			response := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/containers/"+id+"/start", nil))
				close(done)
			}()
			if tc.prepare {
				select {
				case source := <-entered:
					if source != "docker-start" {
						t.Error(source)
					}
				case <-time.After(2 * time.Second):
					close(release)
					t.Fatal("start did not prepare")
				}
				if !tc.timeout {
					select {
					case <-done:
						t.Error("start response escaped before preparation")
					default:
					}
					close(release)
				}
			} else {
				close(release)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				if tc.timeout {
					close(release)
				}
				t.Fatal("start response did not fail open")
			}
			if tc.timeout {
				close(release)
			}
			if response.Code != tc.status {
				t.Fatalf("status changed: %d", response.Code)
			}
			if !tc.prepare && len(entered) != 0 {
				t.Fatal("non-start prepared files")
			}
		})
	}
}
