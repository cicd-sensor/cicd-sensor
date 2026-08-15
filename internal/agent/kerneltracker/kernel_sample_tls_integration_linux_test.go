//go:build linux && bpf_integration

package kerneltracker

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

// TestLinuxOpenSSLUprobeCapturesHTTPS drives Stage 1b-1 end to end: with the
// OpenSSL tap enabled, a tracked job's HTTPS request is captured as an
// http_request event with source=openssl, and the attach happens by discovery
// (the connecting process's connect is tee'd, its libssl is found and attached)
// — no manual attach.
//
// curl is run repeatedly against a local HTTP/1.1 TLS server. The first
// connect triggers discovery and the attach to the shared libssl inode; later
// requests over the now-attached inode are captured. This proves the mechanism;
// it is a steady-state check, not a first-call-rate measurement (that needs
// fresh inodes and a real remote — see the design's M1 gate).
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
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	url := server.URL + "/openssl-probe?token=secret"

	// Drive curl until the sample arrives or the wait times out.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			// curl on this host must link OpenSSL for SSL_write to fire; if it
			// links GnuTLS/NSS the wait below fails, which is the correct signal.
			_ = exec.Command(curl, "-sk", "--http1.1", "--max-time", "3", url).Run()
			time.Sleep(300 * time.Millisecond)
		}
	}()

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
