//go:build linux && bpf_integration

package kerneltracker

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"sync"
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

// TestLinuxOpenSSLUprobeCapturesHTTPS drives Stage 1b-1 end to end: with the
// OpenSSL tap enabled, a tracked job's HTTPS request is captured as an
// http_request event with source=openssl, and the attach happens by discovery
// (the connecting process's connect is tee'd, its libssl is found and attached)
// — no manual attach.
//
// One curl process sends several requests to a local HTTP/1.1 TLS server. The
// first connect triggers discovery and the attach to its mapped libssl inode;
// later requests from the same live process are captured. This proves the
// steady-state mechanism without depending on discovery winning a race against
// a short-lived one-request process. First-call capture is a separate M1 gate.
func TestLinuxOpenSSLUprobeCapturesHTTPS(t *testing.T) {
	curl := requireBinary(t, "curl")

	cgroupRoot, err := getCgroupV2Root()
	if err != nil {
		t.Fatalf("getCgroupV2Root: %v", err)
	}
	kernelIO, err := kernelio.NewLinux(nil, kernelio.Config{
		CgroupV2RootPath:  cgroupRoot,
		EnableOpenSSLHTTP: true,
	})
	if err != nil {
		t.Fatalf("kernelio.NewLinux: %v", err)
	}
	t.Cleanup(func() { _ = kernelIO.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)
	cgroupID := trackTestProcessCgroup(t, ctx, kernelIO, cgroupRoot)

	// HTTP/1.1-only TLS server so the request line is plaintext to SSL_write
	// (an h2 client would hand SSL_write HPACK, which the tap rejects by design).
	var firstRequest sync.Once
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Keep the first client process alive long enough for connect-triggered
		// discovery to inspect its maps and attach before its later requests.
		firstRequest.Do(func() { time.Sleep(2 * time.Second) })
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	url := server.URL + "/openssl-probe?token=secret"

	// curl must link OpenSSL for SSL_write to fire. Repeating the URL in one
	// invocation keeps one mapped libssl target alive across discovery and the
	// requests that follow it.
	args := []string{"-sk", "--http1.1", "--max-time", "10", url, url, url, url}
	if output, err := exec.Command(curl, args...).CombinedOutput(); err != nil {
		t.Fatalf("curl HTTPS requests: %v: %s", err, output)
	}

	waitForEngineInput(t, kernelTracker.inputCh, 20*time.Second, "openssl http_request for /openssl-probe",
		func(in engineInput) bool {
			sample, ok := in.(httpRequestSample)
			if !ok || sample.CgroupID != cgroupID || sample.Source != HTTPSourceOpenSSL {
				return false
			}
			if sample.Path != "/openssl-probe" {
				t.Fatalf("path = %q, want /openssl-probe (query must be stripped in-kernel)", sample.Path)
			}
			return true
		})
}
