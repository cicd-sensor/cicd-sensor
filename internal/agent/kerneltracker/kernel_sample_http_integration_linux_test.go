//go:build linux && bpf_integration

package kerneltracker

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLinuxKernelSampleHTTPRequestEmitsEvent drives the cleartext tap
// end-to-end: fentry/tcp_sendmsg_http fires on a loopback HTTP write from a
// tracked cgroup, the in-eBPF parse strips the query and extracts Host, and
// the sample completes the loop into engine.inputCh.
func TestLinuxKernelSampleHTTPRequestEmitsEvent(t *testing.T) {
	f := newHTTPCaptureFixture(t)

	// Query string present so the assertion proves the in-kernel '?' strip,
	// not just the copy path. Authorization present so a leak would be
	// visible if it ever reached the sample fields.
	request := "GET /search/results?q=topsecret HTTP/1.1\r\n" +
		"Host: http-it.example\r\n" +
		"Authorization: Bearer sk_secret\r\n" +
		"\r\n"
	if _, err := f.conn.Write([]byte(request)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	waitForEngineInput(t, f.inputCh, 5*time.Second, "http_request for http-it.example",
		func(in engineInput) bool {
			sample, ok := in.(httpRequestSample)
			if !ok {
				return false
			}
			if sample.CgroupID != f.cgroupID {
				return false
			}
			if sample.Source != HTTPSourceCleartext {
				return false
			}
			if sample.Method != "GET" {
				t.Fatalf("method = %q, want GET", sample.Method)
			}
			if sample.Path != "/search/results" {
				t.Fatalf("path = %q, want /search/results (query must be stripped in-kernel)", sample.Path)
			}
			if strings.TrimSpace(sample.Host) != "http-it.example" {
				t.Fatalf("host = %q, want http-it.example", sample.Host)
			}
			return true
		})
}

// TestLinuxKernelSampleHTTPRequestIgnoresNonHTTP asserts the content
// pre-check: a TLS-record-like first byte on the same tracked socket path
// must not produce an http_request sample. A subsequent valid request acts
// as the ordering barrier — ringbuf preserves submission order, so if the
// binary write had produced a sample it would arrive first.
func TestLinuxKernelSampleHTTPRequestIgnoresNonHTTP(t *testing.T) {
	f := newHTTPCaptureFixture(t)

	// TLS ClientHello-style record header followed by padding: rejected by
	// the 8-byte method-token pre-check before any prefix copy.
	tlsLike := append([]byte{0x16, 0x03, 0x01, 0x02, 0x00}, make([]byte, 32)...)
	if _, err := f.conn.Write(tlsLike); err != nil {
		t.Fatalf("Write tls-like: %v", err)
	}
	marker := "GET /marker HTTP/1.1\r\nHost: after-binary.example\r\n\r\n"
	if _, err := f.conn.Write([]byte(marker)); err != nil {
		t.Fatalf("Write marker: %v", err)
	}

	waitForEngineInput(t, f.inputCh, 5*time.Second, "only the marker request",
		func(in engineInput) bool {
			sample, ok := in.(httpRequestSample)
			if !ok || sample.CgroupID != f.cgroupID {
				return false
			}
			// First http sample from this cgroup must be the marker; a
			// sample for the binary write would have arrived before it.
			if sample.Path != "/marker" || strings.TrimSpace(sample.Host) != "after-binary.example" {
				t.Fatalf("unexpected first http sample: %+v", sample)
			}
			return true
		})
}

// httpCaptureFixture wires a tracked-cgroup HTTP tap with a loopback listener
// and returns a live connection plus the tracker's input channel. Shared by
// every HTTP capture test so each stays focused on one behaviour.
type httpCaptureFixture struct {
	cgroupID uint64
	inputCh  chan engineInput
	conn     net.Conn
}

func newHTTPCaptureFixture(t *testing.T) *httpCaptureFixture {
	t.Helper()
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	t.Cleanup(func() { kernelIO.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)

	cgroupID, err := lookupProcessCgroupID(int32(os.Getpid()), cgroupRoot)
	if err != nil {
		t.Fatalf("lookupProcessCgroupID: %v", err)
	}
	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, cgroupID); err != nil {
		t.Fatalf("put tracked cgroup: %v", err)
	}
	t.Cleanup(func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{cgroupID})
	})

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			_, _ = io.Copy(io.Discard, conn)
			_ = conn.Close()
		}()
	}()

	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return &httpCaptureFixture{cgroupID: cgroupID, inputCh: kernelTracker.inputCh, conn: conn}
}

// TestLinuxKernelSampleHTTPRequestNoStaleSuffix asserts a short request after a
// long one does not inherit the previous request's bytes — the per-CPU scratch
// and the sample fields are both zeroed per capture (redaction).
func TestLinuxKernelSampleHTTPRequestNoStaleSuffix(t *testing.T) {
	f := newHTTPCaptureFixture(t)

	long := "GET /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\nHost: long.example\r\n\r\n"
	if _, err := f.conn.Write([]byte(long)); err != nil {
		t.Fatalf("Write long: %v", err)
	}
	waitForEngineInput(t, f.inputCh, 5*time.Second, "long request", func(in engineInput) bool {
		s, ok := in.(httpRequestSample)
		return ok && s.CgroupID == f.cgroupID && strings.TrimSpace(s.Host) == "long.example"
	})

	short := "GET /x HTTP/1.1\r\nHost: s.example\r\n\r\n"
	if _, err := f.conn.Write([]byte(short)); err != nil {
		t.Fatalf("Write short: %v", err)
	}
	waitForEngineInput(t, f.inputCh, 5*time.Second, "short request without stale suffix", func(in engineInput) bool {
		s, ok := in.(httpRequestSample)
		if !ok || s.CgroupID != f.cgroupID || strings.TrimSpace(s.Host) != "s.example" {
			return false
		}
		if s.Path != "/x" {
			t.Fatalf("path = %q, want exactly \"/x\" (stale bytes from the long request leaked)", s.Path)
		}
		return true
	})
}

// TestLinuxKernelSampleHTTPRequestRejectsBadVersion asserts a malformed version
// token ("HTTP/1.Xjunk") is not captured, while a following valid request is —
// so the reject is the version check, not a dead tap.
func TestLinuxKernelSampleHTTPRequestRejectsBadVersion(t *testing.T) {
	f := newHTTPCaptureFixture(t)

	bad := "GET /evil HTTP/1.Xjunk\r\nHost: bad.example\r\n\r\n"
	if _, err := f.conn.Write([]byte(bad)); err != nil {
		t.Fatalf("Write bad: %v", err)
	}
	marker := "GET /ok HTTP/1.1\r\nHost: good.example\r\n\r\n"
	if _, err := f.conn.Write([]byte(marker)); err != nil {
		t.Fatalf("Write marker: %v", err)
	}
	waitForEngineInput(t, f.inputCh, 5*time.Second, "only the valid request", func(in engineInput) bool {
		s, ok := in.(httpRequestSample)
		if !ok || s.CgroupID != f.cgroupID {
			return false
		}
		if strings.TrimSpace(s.Host) == "bad.example" || s.Path == "/evil" {
			t.Fatalf("captured the malformed-version request: %+v", s)
		}
		return strings.TrimSpace(s.Host) == "good.example" && s.Path == "/ok"
	})
}

// TestLinuxKernelSampleHTTPRequestQueryStripNoHost drives an HTTP/1.0 request
// with a query and no Host: the query is stripped and the host is empty.
func TestLinuxKernelSampleHTTPRequestQueryStripNoHost(t *testing.T) {
	f := newHTTPCaptureFixture(t)

	request := "GET /p/q?secret=1 HTTP/1.0\r\nUser-Agent: x\r\n\r\n"
	if _, err := f.conn.Write([]byte(request)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	waitForEngineInput(t, f.inputCh, 5*time.Second, "http/1.0 no-host request", func(in engineInput) bool {
		s, ok := in.(httpRequestSample)
		if !ok || s.CgroupID != f.cgroupID || s.Path != "/p/q" {
			return false
		}
		if strings.TrimSpace(s.Host) != "" {
			t.Fatalf("host = %q, want empty (no Host header)", s.Host)
		}
		return true
	})
}
