//go:build linux && bpf_integration && http_client_integration

package kerneltracker

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

func TestLinuxGoNetHTTPUprobeCapturesHTTPS(t *testing.T) {
	clientPath := goHTTPTestClient(t)
	tests := []struct {
		name       string
		clientMode string
		http2      bool
		path       string
	}{
		{name: "Client.Do reaches the shared hook over HTTP/1.1", clientMode: "client", path: "/client-http1"},
		{name: "Client.Do reaches the shared hook over HTTP/2", clientMode: "client", http2: true, path: "/client-http2"},
		{name: "Transport.RoundTrip reaches the selected implementation over HTTP/1.1", clientMode: "transport", path: "/transport-http1"},
		{name: "Transport.RoundTrip reaches the selected implementation over HTTP/2", clientMode: "transport", http2: true, path: "/transport-http2"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kernelTracker, cgroupID := startGoHTTPIntegrationRuntime(t)

			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			if test.http2 {
				server.EnableHTTP2 = true
			} else {
				server.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
			}
			server.StartTLS()
			t.Cleanup(server.Close)

			runGoHTTPClientBurst(t, clientPath, test.clientMode, server.URL+test.path+"?token=must-not-leave-kernel")
			waitForEngineInput(t, kernelTracker.inputCh, 20*time.Second, "Go net/http request for "+test.path,
				func(in engineInput) bool {
					sample, ok := in.(httpRequestSample)
					if !ok || sample.CgroupID != cgroupID || sample.Source != HTTPSourceGoNetHTTP || sample.Path != test.path {
						return false
					}
					if sample.Method != "GET" || sample.Host != server.Listener.Addr().String() {
						t.Fatalf("sample = method %q path %q host %q", sample.Method, sample.Path, sample.Host)
					}
					return true
				})
		})
	}
}

func TestLinuxGoNetHTTPUprobeCapturesExternallyLinkedHTTPS(t *testing.T) {
	clientPath := goHTTPExternalTestClient(t)
	for _, clientMode := range []string{"client", "transport"} {
		t.Run(clientMode, func(t *testing.T) {
			kernelTracker, cgroupID := startGoHTTPIntegrationRuntime(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(server.Close)

			path := "/go-http-cgo-" + clientMode
			runGoHTTPClientBurst(t, clientPath, clientMode, server.URL+path)
			waitForEngineInput(t, kernelTracker.inputCh, 20*time.Second, "externally linked Go net/http request",
				func(in engineInput) bool {
					sample, ok := in.(httpRequestSample)
					return ok && sample.CgroupID == cgroupID && sample.Source == HTTPSourceGoNetHTTP &&
						sample.Method == "GET" && sample.Path == path && sample.Host == server.Listener.Addr().String()
				})
		})
	}
}

func TestLinuxGoNetHTTPUprobeCoversSupportedGoVersions(t *testing.T) {
	clients := os.Getenv("GO_HTTP_VERSIONED_TEST_CLIENTS")
	if clients == "" {
		t.Skip("GO_HTTP_VERSIONED_TEST_CLIENTS is not set")
	}
	kernelTracker, cgroupID := startGoHTTPIntegrationRuntime(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	for _, specification := range strings.Split(clients, ",") {
		version, clientPath, found := strings.Cut(specification, "=")
		if !found || version == "" || clientPath == "" {
			t.Fatalf("invalid GO_HTTP_VERSIONED_TEST_CLIENTS entry %q", specification)
		}
		t.Run(version, func(t *testing.T) {
			path := "/go-version-" + version
			host := "go-" + version + ".example"
			runGoHTTPClientBurst(t, clientPath, "client", server.URL+path, host)
			waitForEngineInput(t, kernelTracker.inputCh, 20*time.Second, "Go net/http request from "+version,
				func(in engineInput) bool {
					sample, ok := in.(httpRequestSample)
					return ok && sample.CgroupID == cgroupID && sample.Source == HTTPSourceGoNetHTTP &&
						sample.Method == "GET" && sample.Path == path && sample.Host == host
				})
		})
	}
}

func TestLinuxGoNetHTTPUprobeCoversGH(t *testing.T) {
	gh, err := exec.LookPath("gh")
	if err != nil {
		t.Skipf("gh is required: %v", err)
	}
	kernelTracker, cgroupID := startGoHTTPIntegrationRuntime(t)

	freshPath := filepath.Join(t.TempDir(), "gh")
	copyExecutable(t, freshPath, gh)
	for range 10 {
		command := exec.Command(freshPath, "api", "/meta")
		command.Env = append(os.Environ(),
			"GH_TOKEN=cicd-sensor-intentionally-invalid-token",
			"GH_NO_UPDATE_NOTIFIER=1",
		)
		if err := command.Start(); err != nil {
			t.Fatalf("start gh: %v", err)
		}
		pid := int32(command.Process.Pid)
		_ = command.Wait() // The intentionally invalid token returns HTTP 401.

		if _, ok := findEngineInput(kernelTracker.inputCh, 2*time.Second,
			func(in engineInput) bool {
				sample, ok := in.(httpRequestSample)
				if !ok || sample.CgroupID != cgroupID || sample.Identity.PID != pid || sample.Source != HTTPSourceGoNetHTTP {
					return false
				}
				if sample.Method != "GET" || sample.Host != "api.github.com" || sample.Path != "/meta" {
					t.Fatalf("gh sample = method %q path %q host %q", sample.Method, sample.Path, sample.Host)
				}
				return true
			}); ok {
			return
		}
	}
	t.Fatal("timed out waiting for Go net/http request from gh")
}

func startGoHTTPIntegrationRuntime(t *testing.T) (*KernelTracker, uint64) {
	t.Helper()
	cgroupRoot, err := getCgroupV2Root()
	if err != nil {
		t.Fatalf("getCgroupV2Root: %v", err)
	}
	kernelIO, err := kernelio.NewLinux(nil, kernelio.Config{
		CgroupV2RootPath:  cgroupRoot,
		EnableHTTPRequest: true,
	})
	if err != nil {
		t.Fatalf("kernelio.NewLinux: %v", err)
	}
	t.Cleanup(func() { _ = kernelIO.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	kernelTracker := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)
	cgroupID := trackTestProcessCgroup(t, ctx, kernelIO, cgroupRoot)
	return kernelTracker, cgroupID
}

func goHTTPTestClient(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("GO_HTTP_TEST_CLIENT"); path != "" {
		return path
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go is required to build the HTTP fixture: %v", err)
	}
	output := filepath.Join(t.TempDir(), "go-http-client")
	command := exec.Command(goBinary, "build", "-buildvcs=false", "-trimpath", "-ldflags=-s -w", "-o", output, "./testdata/go_http_client")
	if buildOutput, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Go HTTP fixture: %v: %s", err, buildOutput)
	}
	return output
}

func goHTTPExternalTestClient(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("GO_HTTP_CGO_TEST_CLIENT"); path != "" {
		return path
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go is required to build the HTTP fixture: %v", err)
	}
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skipf("C compiler is required for an externally linked Go fixture: %v", err)
	}
	output := filepath.Join(t.TempDir(), "go-http-cgo-client")
	command := exec.Command(goBinary, "build", "-buildvcs=false", "-trimpath", "-buildmode=pie", "-ldflags=-s -w -linkmode=external", "-o", output, "./testdata/go_http_client")
	command.Env = append(os.Environ(), "CGO_ENABLED=1", "CC="+compiler)
	if buildOutput, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build externally linked Go HTTP fixture: %v: %s", err, buildOutput)
	}
	return output
}

func runGoHTTPClientBurst(t *testing.T, clientPath, mode, target string, args ...string) {
	t.Helper()
	commandArgs := append([]string{mode, target}, args...)
	command := exec.Command(clientPath, commandArgs...)
	command.Env = append(os.Environ(), "GO_HTTP_TEST_BURST=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Go HTTP client: %v: %s", err, output)
	}
}

func copyExecutable(t *testing.T, destination, source string) {
	t.Helper()
	src, err := os.Open(source)
	if err != nil {
		t.Fatalf("open Go HTTP fixture: %v", err)
	}
	defer src.Close()
	dst, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatalf("create fresh Go HTTP fixture: %v", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		t.Fatalf("copy fresh Go HTTP fixture: %v", err)
	}
	if err := dst.Close(); err != nil {
		t.Fatalf("close fresh Go HTTP fixture: %v", err)
	}
}
