//go:build linux && bpf_integration

package kerneltracker

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
	"github.com/cilium/ebpf/link"
)

// findLibsslPath returns a libssl shared object on the host, or skips.
func findLibsslPath(t *testing.T) string {
	t.Helper()
	for _, pattern := range []string{
		"/usr/lib/*/libssl.so.3", "/lib/*/libssl.so.3",
		"/usr/lib64/libssl.so.3", "/usr/lib/libssl.so.3",
	} {
		if m, _ := filepath.Glob(pattern); len(m) > 0 {
			return m[0]
		}
	}
	t.Skip("no libssl on host")
	return ""
}

// h1TLSServer starts an HTTP/1.1-only TLS server (so SSL_write carries a
// plaintext request line, not HPACK) and returns its base URL.
func h1TLSServer(t *testing.T) string {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

// TestLinuxOpenSSLUprobeDoubleAttachDuplicatesEvents proves the design's
// duplicate-attach claim: the same program attached twice to one inode/offset
// registers two uprobe consumers, the kernel runs both, and a single SSL_write
// yields two events. This is why the identity key must not over-split (mnt_id
// excluded) and why same-image overlay containers are a known duplicate-event
// gap. Discovery is off here; the program is attached manually.
func TestLinuxOpenSSLUprobeDoubleAttachDuplicatesEvents(t *testing.T) {
	curl := requireBinary(t, "curl")
	libssl := findLibsslPath(t)

	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	t.Cleanup(func() { _ = kernelIO.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)
	cgroupID := trackTestProcessCgroup(t, ctx, kernelIO, cgroupRoot)

	base := h1TLSServer(t)
	ex, err := link.OpenExecutable(libssl)
	if err != nil {
		t.Fatalf("OpenExecutable(%s): %v", libssl, err)
	}

	// countFor drives curl to a unique path a few times, then drains events for
	// a quiet window, counting the openssl http_request samples for that path.
	countFor := func(path string) int {
		url := base + path
		for range 4 {
			_ = exec.Command(curl, "-sk", "--http1.1", "--max-time", "3", url).Run()
			time.Sleep(150 * time.Millisecond)
		}
		count := 0
		deadline := time.After(3 * time.Second)
		for {
			select {
			case in := <-kernelTracker.inputCh:
				if s, ok := in.(httpRequestSample); ok &&
					s.CgroupID == cgroupID && s.Source == HTTPSourceOpenSSL && s.Path == path {
					count++
				}
			case <-deadline:
				return count
			}
		}
	}

	single, err := ex.Uprobe("SSL_write", kernelIO.TestOnlyOpenSSLProgram(), nil)
	if err != nil {
		t.Fatalf("first Uprobe(SSL_write): %v", err)
	}
	defer single.Close()
	singleCount := countFor("/single-attach")

	double, err := ex.Uprobe("SSL_write", kernelIO.TestOnlyOpenSSLProgram(), nil)
	if err != nil {
		t.Fatalf("second Uprobe(SSL_write): %v", err)
	}
	defer double.Close()
	doubleCount := countFor("/double-attach")

	t.Logf("single-attach events=%d, double-attach events=%d", singleCount, doubleCount)
	if singleCount < 1 {
		t.Fatalf("single attach captured no events (want >=1)")
	}
	if doubleCount < singleCount+1 {
		t.Fatalf("double attach did not add events: single=%d double=%d (a second consumer must fire too)",
			singleCount, doubleCount)
	}
}

// TestLinuxOpenSSLUprobeCapturesHTTPS drives mapping-triggered discovery and
// steady-state capture end to end for clients that use SSL_write and
// SSL_write_ex. First-request timing is measured separately because attach is
// asynchronous and is not part of this deterministic integration contract.
func TestLinuxOpenSSLUprobeCapturesHTTPS(t *testing.T) {
	tests := []struct {
		name       string
		binary     string
		path       string
		clientArgs func(string) []string
	}{
		{
			name:   "curl exercises SSL_write",
			binary: "curl",
			path:   "/curl-ssl-write",
			clientArgs: func(url string) []string {
				return []string{"-sk", "--http1.1", "--max-time", "10", url}
			},
		},
		{
			name:   "python exercises SSL_write_ex",
			binary: "python3",
			path:   "/python-ssl-write-ex",
			clientArgs: func(url string) []string {
				const script = `
import ssl
import sys
import urllib.request

context = ssl._create_unverified_context()
with urllib.request.urlopen(sys.argv[1], context=context, timeout=10) as response:
    response.read()
`
				return []string{"-c", script, url}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := requireBinary(t, test.binary)
			testOpenSSLUprobeCapturesHTTPS(t, client, test.path, test.clientArgs)
		})
	}
}

func TestLinuxOpenSSLUprobeDisabled(t *testing.T) {
	curl := requireBinary(t, "curl")
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	t.Cleanup(func() { _ = kernelIO.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)
	cgroupID := trackTestProcessCgroup(t, ctx, kernelIO, cgroupRoot)

	const path = "/disabled-openssl"
	url := h1TLSServer(t) + path
	for range 3 {
		if output, err := exec.Command(curl, "-sk", "--http1.1", "--max-time", "3", url).CombinedOutput(); err != nil {
			t.Fatalf("curl: %v: %s", err, output)
		}
	}

	if _, found := findEngineInput(kernelTracker.inputCh, 500*time.Millisecond, func(in engineInput) bool {
		sample, ok := in.(httpRequestSample)
		return ok && sample.CgroupID == cgroupID && sample.Path == path
	}); found {
		t.Fatal("OpenSSL http_request sample emitted while capture is disabled")
	}
}

// testOpenSSLUprobeCapturesHTTPS verifies mapping-triggered attach and capture
// for real OpenSSL clients.
func testOpenSSLUprobeCapturesHTTPS(t *testing.T, client, path string, clientArgs func(string) []string) {
	t.Helper()

	// HTTP/1.1-only TLS server so the request line is plaintext to SSL_write
	// (an h2 client would hand SSL_write HPACK, which the tap rejects by design).
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	url := server.URL + path + "?token=secret"

	clients := make([]*deferredHTTPUprobeExec, 0, 4)
	for range 4 {
		clients = append(clients, prepareHTTPUprobeExec(t, exec.Command(client, clientArgs(url)...)))
	}

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

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Use the real KernelIO so uprobe_mmap notifications exercise runtime
	// discovery before the client enters SSL_write.
	kernelTracker := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)
	cgroupID := trackTestProcessCgroup(t, ctx, kernelIO, cgroupRoot)

	// The first short-lived process can finish before asynchronous attach. Each
	// later process maps the same file again and retries discovery; once attached,
	// the file-scoped link covers subsequent processes without an artificial wait.
	for _, prepared := range clients {
		if output, err := prepared.run(); err != nil {
			t.Fatalf("HTTPS client %s: %v: %s", client, err, output)
		}
	}

	waitForEngineInput(t, kernelTracker.inputCh, 20*time.Second, "openssl http_request for "+path,
		func(in engineInput) bool {
			sample, ok := in.(httpRequestSample)
			if !ok || sample.CgroupID != cgroupID || sample.Source != HTTPSourceOpenSSL {
				return false
			}
			if sample.Path != path {
				t.Fatalf("path = %q, want %s (query must be stripped in-kernel)", sample.Path, path)
			}
			return true
		})
}
