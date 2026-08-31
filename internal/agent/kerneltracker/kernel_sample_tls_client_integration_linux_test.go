//go:build linux && bpf_integration && http_client_integration

package kerneltracker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

// TestLinuxOpenSSLUprobeCoversCommonClients verifies actual client binaries on
// CI runner images. A unique path identifies which client produced the OpenSSL
// http_request event.
func TestLinuxOpenSSLUprobeCoversCommonClients(t *testing.T) {
	expected := expectedHTTPClientCoverage(t)
	tests := []struct {
		id        string
		name      string
		binary    string
		urlPath   string
		eventPath string
		command   func(string) *exec.Cmd
	}{
		{
			id:        "curl",
			name:      "curl",
			binary:    "curl",
			urlPath:   "/curl",
			eventPath: "/curl",
			command: func(url string) *exec.Cmd {
				// Reuse one mapped libssl for several requests so this coverage
				// test measures eventual shared-library attachment, not first-call timing.
				return exec.Command("curl", "-sk", "--http1.1", "--max-time", "10", url, url, url, url)
			},
		},
		{
			id:        "python_urllib",
			name:      "python urllib",
			binary:    "python3",
			urlPath:   "/python-urllib",
			eventPath: "/python-urllib",
			command: func(url string) *exec.Cmd {
				const script = `import ssl,sys,urllib.request
context=ssl._create_unverified_context()
urllib.request.urlopen(sys.argv[1], context=context, timeout=10).read()`
				return exec.Command("python3", "-c", script, url)
			},
		},
		{
			id:        "python_requests",
			name:      "python requests",
			binary:    "python3",
			urlPath:   "/python-requests",
			eventPath: "/python-requests",
			command: func(url string) *exec.Cmd {
				const script = `import requests,sys
requests.get(sys.argv[1], timeout=10, verify=False)`
				return exec.Command("python3", "-c", script, url)
			},
		},
		{
			id:        "pip",
			name:      "pip",
			binary:    "python3",
			urlPath:   "/pip",
			eventPath: "/pip/simple/cicd-sensor-http-uprobe-missing/",
			command: func(url string) *exec.Cmd {
				command := fmt.Sprintf(
					"python3 -m pip --disable-pip-version-check index versions --trusted-host 127.0.0.1 --index-url %q/simple cicd-sensor-http-uprobe-missing || true",
					url,
				)
				return exec.Command("sh", "-c", command)
			},
		},
		{
			id:        "node",
			name:      "node https",
			binary:    "node",
			urlPath:   "/node",
			eventPath: "/node",
			command: func(url string) *exec.Cmd {
				const script = `const https=require('https'),url=process.argv[1];
https.get(url,{rejectUnauthorized:false,agent:false},r=>{r.resume()}).on('error',e=>{console.error(e);process.exit(1)});`
				return exec.Command("node", "-e", script, url)
			},
		},
		{
			id:        "npm",
			name:      "npm ping",
			binary:    "npm",
			urlPath:   "/npm",
			eventPath: "/npm/-/ping",
			command: func(url string) *exec.Cmd {
				command := fmt.Sprintf("npm ping --registry=%q/ --strict-ssl=false", url)
				return exec.Command("sh", "-c", command)
			},
		},
		{
			id:        "wget",
			name:      "wget",
			binary:    "wget",
			urlPath:   "/wget",
			eventPath: "/wget",
			command: func(url string) *exec.Cmd {
				return exec.Command("wget", "--no-check-certificate", "--quiet", "--output-document=/dev/null", url)
			},
		},
		{
			id:        "git",
			name:      "git ls-remote",
			binary:    "git",
			urlPath:   "/git",
			eventPath: "/git/info/refs",
			command: func(url string) *exec.Cmd {
				command := fmt.Sprintf("git -c http.sslVerify=false ls-remote %q || true", url)
				return exec.Command("sh", "-c", command)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requireBinary(t, test.binary)
			captured := testOpenSSLClientCoverage(
				t,
				test.urlPath,
				test.eventPath,
				test.command,
				expected[test.id],
			)
			if captured != expected[test.id] {
				t.Fatalf("captured = %t, want %t for %s", captured, expected[test.id], test.id)
			}
		})
	}
}

// TestLinuxNghttp2UprobeCoversHTTP2Clients verifies real HTTP/2 request paths
// through the selected nghttp2 submission APIs.
func TestLinuxNghttp2UprobeCoversHTTP2Clients(t *testing.T) {
	tests := []struct {
		name    string
		binary  string
		path    string
		command func(string) *exec.Cmd
	}{
		{
			name:   "curl HTTP/2",
			binary: "curl",
			path:   "/h2-curl",
			command: func(target string) *exec.Cmd {
				return exec.Command("curl", "-sk", "--http2", "--max-time", "10", target)
			},
		},
		{
			name:   "Node HTTP/2",
			binary: "node",
			path:   "/h2-node",
			command: func(target string) *exec.Cmd {
				const script = `const http2=require('http2'),u=new URL(process.argv[1]);
const client=http2.connect(u.origin,{rejectUnauthorized:false});
const r=client.request({':path':u.pathname+u.search});
r.on('response',()=>{});r.on('data',()=>{});r.on('end',()=>client.close());r.on('error',e=>{console.error(e);process.exit(1)});r.end();`
				return exec.Command("node", "-e", script, target)
			},
		},
		{
			name:   "Git default HTTP version",
			binary: "git",
			path:   "/h2-git-default",
			command: func(target string) *exec.Cmd {
				command := fmt.Sprintf("git -c http.sslVerify=false ls-remote %q || true", target)
				return exec.Command("sh", "-c", command)
			},
		},
		{
			name:   "Git forced HTTP/2",
			binary: "git",
			path:   "/h2-git-forced",
			command: func(target string) *exec.Cmd {
				command := fmt.Sprintf("git -c http.version=HTTP/2 -c http.sslVerify=false ls-remote %q || true", target)
				return exec.Command("sh", "-c", command)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requireBinary(t, test.binary)
			testNghttp2ClientCoverage(t, test.path, test.command)
		})
	}
}

func testNghttp2ClientCoverage(
	t *testing.T,
	urlPath string,
	command func(string) *exec.Cmd,
) {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("protocol = %s, want HTTP/2", r.Proto)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	target := server.URL + urlPath + "?token=secret"

	clients := make([]*deferredHTTPUprobeExec, 0, 4)
	for range 4 {
		clients = append(clients, prepareHTTPUprobeExec(t, command(target)))
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

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	kernelTracker := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)
	cgroupID := trackTestProcessCgroup(t, ctx, kernelIO, cgroupRoot)

	// Use separate processes so a mapping missed during asynchronous attach is
	// retried naturally and the resulting file-scoped link covers a later client.
	for _, prepared := range clients {
		if output, err := prepared.run(); err != nil {
			t.Fatalf("HTTP/2 client: %v: %s", err, output)
		}
	}

	waitForEngineInput(t, kernelTracker.inputCh, 20*time.Second, "nghttp2 http_request for "+urlPath,
		func(in engineInput) bool {
			sample, ok := in.(httpRequestSample)
			if !ok || sample.CgroupID != cgroupID || sample.Source != HTTPSourceNghttp2 {
				return false
			}
			if sample.Method != "GET" || sample.Path != urlPath || sample.Host != server.Listener.Addr().String() {
				t.Fatalf("sample = method %q path %q host %q, want GET %q %q",
					sample.Method, sample.Path, sample.Host, urlPath, server.Listener.Addr().String())
			}
			return true
		})
}

func expectedHTTPClientCoverage(t *testing.T) map[string]bool {
	t.Helper()
	raw, ok := os.LookupEnv("HTTP_UPROBE_EXPECTED_CLIENTS")
	if !ok {
		t.Fatal("HTTP_UPROBE_EXPECTED_CLIENTS is required")
	}
	expected := make(map[string]bool)
	for client := range strings.SplitSeq(raw, ",") {
		expected[strings.TrimSpace(client)] = true
	}
	return expected
}

func testOpenSSLClientCoverage(
	t *testing.T,
	urlPath string,
	eventPath string,
	command func(string) *exec.Cmd,
	expectCapture bool,
) bool {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/-/ping"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{}"))
		case strings.HasSuffix(r.URL.Path, "/info/refs"):
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			_, _ = w.Write([]byte("001e# service=git-upload-pack\n0000"))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<!doctype html><html></html>"))
		}
	}))
	server.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)

	clients := make([]*deferredHTTPUprobeExec, 0, 8)
	for range 8 {
		clients = append(clients, prepareHTTPUprobeExec(t, command(server.URL+urlPath)))
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

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	kernelTracker := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)
	cgroupID := trackTestProcessCgroup(t, ctx, kernelIO, cgroupRoot)

	waitForPath := func(path string) bool {
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case in := <-kernelTracker.inputCh:
				sample, ok := in.(httpRequestSample)
				if ok && sample.CgroupID == cgroupID && sample.Source == HTTPSourceOpenSSL &&
					strings.HasPrefix(sample.Path, path) {
					return true
				}
			case <-deadline.C:
				return false
			}
		}
	}

	runClients := func(prepared []*deferredHTTPUprobeExec) {
		// Use separate processes for the same mapping/attach contract as the
		// HTTP/2 test above; do not hide first-request timing behind a sleep.
		for _, client := range prepared {
			if output, err := client.run(); err != nil {
				t.Fatalf("HTTPS client: %v: %s", err, output)
			}
		}
	}

	runClients(clients[:4])
	if captured := waitForPath(eventPath); captured || !expectCapture {
		return captured
	}

	// A very short-lived client can finish the first burst while the worker is
	// still classifying its executable. A second process burst verifies eventual
	// file-scoped attachment without turning this coverage test into a first-call
	// delivery guarantee.
	runClients(clients[4:])
	return waitForPath(eventPath)
}
