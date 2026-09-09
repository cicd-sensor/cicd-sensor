//go:build linux && bpf_integration

package dockerd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
	"golang.org/x/sys/unix"
)

// Requires a preloaded test image with curl, /usr/local/bin/gh and /usr/local/bin/glab. It uses only
// its own disposable container, node sockets and a local TLS endpoint.
func TestDockerExecHTTPPreparation(t *testing.T) {
	image := os.Getenv("CICD_DOCKER_PREPARATION_IMAGE")
	if image == "" {
		t.Skip("set CICD_DOCKER_PREPARATION_IMAGE for the privileged Docker fixture")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	dockerCommand := func(t *testing.T, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(t.Context(), docker, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker: %v %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	root := t.TempDir()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":1,"login":"local","username":"local"}`))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	if err := os.WriteFile(filepath.Join(root, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.yml"), []byte("check_update: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := dockerCommand(t, "run", "-d", "--network=host", "--mount", "type=bind,src="+root+",dst=/cicd-test,readonly", "-e", "SSL_CERT_FILE=/cicd-test/cert.pem", "-e", "GH_TOKEN=local-fixture-token", "-e", "GITLAB_TOKEN=local-fixture-token", "-e", "GITLAB_HOST="+srv.URL, "-e", "GLAB_CONFIG_DIR=/cicd-test", "-e", "GH_NO_UPDATE_NOTIFIER=1", "-e", "GLAB_SEND_TELEMETRY=false", image, "sleep", "120")
	t.Cleanup(func() {
		out, err := exec.Command(docker, "rm", "-f", id).CombinedOutput()
		if err != nil {
			t.Errorf("remove test container: %v %s", err, out)
		}
	})
	pid, err := strconv.Atoi(dockerCommand(t, "inspect", "-f", "{{.State.Pid}}", id))
	if err != nil {
		t.Fatal(err)
	}
	cgroups, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		t.Fatal(err)
	}
	var cgroup string
	for _, line := range strings.Split(string(cgroups), "\n") {
		if value, ok := strings.CutPrefix(line, "0::"); ok {
			cgroup = value
		}
	}
	if cgroup == "" {
		t.Fatal("container cgroup v2 unavailable")
	}
	var stat unix.Stat_t
	if err := unix.Stat(filepath.Join("/sys/fs/cgroup", cgroup), &stat); err != nil {
		t.Fatal(err)
	}
	ki, err := kernelio.NewLinux(nil, kernelio.Config{CgroupV2RootPath: "/sys/fs/cgroup", EnableHTTPRequest: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ki.Close()
	if err := ki.PutCgroupIDInTrackedCgroupsMap(t.Context(), stat.Ino); err != nil {
		t.Fatal(err)
	}
	events := make(chan bpfprog.BPFProgramHttpRequestSample, 128)
	if err := ki.StartKernelSampleLoop(t.Context(), func(_ context.Context, s kernelio.KernelSample) error {
		if len(s) >= 4 && binary.LittleEndian.Uint32(s[:4]) == 15 {
			var e bpfprog.BPFProgramHttpRequestSample
			if err := binary.Read(bytes.NewReader(s), binary.LittleEndian, &e); err != nil {
				return err
			}
			select {
			case events <- e:
			default:
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Keep node-owned sockets outside the directory mounted into the test container.
	agentSocket := filepath.Join(t.TempDir(), "agent.sock")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	served := make(chan error, 1)
	prepared := make(chan error, 8)
	go func() {
		served <- httpprepare.Serve(ctx, httpprepare.SocketPath(agentSocket), func(ctx context.Context, files []*os.File, source string) error {
			err := ki.PrepareHTTPFiles(ctx, files, source)
			prepared <- err
			return err
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
			t.Fatal("preparation socket not ready")
		}
		time.Sleep(time.Millisecond)
	}
	proxySocket := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", proxySocket)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &http.Server{Handler: proxyHandlerGitHub(slog.Default(), "/var/run/docker.sock", agentSocket), ReadHeaderTimeout: time.Second}
	go func() { _ = proxy.Serve(listener) }()
	defer proxy.Close()
	for _, tc := range []struct {
		name    string
		command []string
		source  uint8
	}{
		{"openssl", []string{"curl", "--http1.1", "--cacert", "/cicd-test/cert.pem", "-sS", srv.URL + "/docker-ssl"}, 1},
		{"nghttp2", []string{"curl", "--http2", "--cacert", "/cicd-test/cert.pem", "-sS", srv.URL + "/docker-h2"}, 2},
		{"gh", []string{"/usr/local/bin/gh", "api", srv.URL + "/docker-gh"}, 3},
		{"glab", []string{"/usr/local/bin/glab", "api", "user"}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for len(events) > 0 {
				<-events
			}
			args := append([]string{"--host", "unix://" + proxySocket, "exec", id}, tc.command...)
			out := dockerCommand(t, args...)
			if !strings.Contains(out, "local") {
				t.Fatalf("streamed Docker exec response lost: %s", out)
			}
			select {
			case err := <-prepared:
				if err != nil {
					t.Fatalf("preparation failed: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("proxy did not request preparation")
			}
			timer := time.NewTimer(time.Second)
			defer timer.Stop()
			for {
				select {
				case event := <-events:
					if event.CgroupId == stat.Ino && event.Source == tc.source {
						return
					}
				case <-timer.C:
					t.Fatal("no HTTP event from prepared Docker exec")
				}
			}
		})
	}
}
