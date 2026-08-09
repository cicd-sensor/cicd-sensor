//go:build linux && bpf_integration

package kerneltracker

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
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
	addr     string
}

// dial opens an additional connection from the tracked cgroup. The concurrency
// test gives each worker its own connection so the writes really do race.
func (f *httpCaptureFixture) dial(t *testing.T) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", f.addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
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
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(io.Discard, conn)
				_ = conn.Close()
			}()
		}
	}()

	fixture := &httpCaptureFixture{
		cgroupID: cgroupID,
		inputCh:  kernelTracker.inputCh,
		addr:     listener.Addr().String(),
	}
	fixture.conn = fixture.dial(t)
	return fixture
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

// TestLinuxKernelSampleHTTPRequestConcurrentSendsStayConsistent sends from many
// connections at once and asserts every captured sample is self-consistent:
// method, path, and host all carry the same worker id.
//
// This is the load-bearing test for the parse design. The parse spans two BPF
// programs joined by a tail call, and the intermediate offsets live in a
// per-CPU scratch map. Correctness rests on the assumption that a tail call
// keeps running on the same CPU and cannot be interleaved with another capture
// on that CPU. If that assumption broke, a sample would surface with one
// request's path and another's host — which is exactly what this asserts
// against. Samples may legitimately be dropped under load, so the test checks
// the integrity of what arrives, not an exact count.
func TestLinuxKernelSampleHTTPRequestConcurrentSendsStayConsistent(t *testing.T) {
	f := newHTTPCaptureFixture(t)

	const (
		workers      = 8
		perWorker    = 25
		quietPeriod  = 500 * time.Millisecond
		collectLimit = 15 * time.Second
	)

	// Dial every connection up front: net.DialTimeout failures must be reported
	// from the test goroutine, not from a worker.
	conns := make([]net.Conn, workers)
	for i := range workers {
		conns[i] = f.dial(t)
	}

	type captured struct {
		method string
		path   string
		host   string
	}
	var (
		mu      sync.Mutex
		samples []captured
	)
	stop := make(chan struct{})
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		for {
			select {
			case <-stop:
				return
			case in := <-f.inputCh:
				sample, ok := in.(httpRequestSample)
				if !ok || sample.CgroupID != f.cgroupID {
					continue
				}
				mu.Lock()
				samples = append(samples, captured{
					method: sample.Method,
					path:   sample.Path,
					host:   strings.TrimSpace(sample.Host),
				})
				mu.Unlock()
			}
		}
	}()

	var wg sync.WaitGroup
	for id := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The method also varies by worker: it is copied from the scratch
			// prefix by a different code path than path/host, so a mismatch
			// there would be invisible if every worker sent the same method.
			method := "GET"
			if id%2 == 1 {
				method = "POST"
			}
			for seq := range perWorker {
				request := fmt.Sprintf("%s /w%d/r%d HTTP/1.1\r\nHost: w%d.example\r\n\r\n",
					method, id, seq, id)
				if _, err := conns[id].Write([]byte(request)); err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()

	// Drain until the ring buffer goes quiet: a fixed sleep would either flake
	// or waste time depending on how fast the sampler keeps up.
	deadline := time.Now().Add(collectLimit)
	previous := -1
	for time.Now().Before(deadline) {
		time.Sleep(quietPeriod)
		mu.Lock()
		current := len(samples)
		mu.Unlock()
		if current == previous {
			break
		}
		previous = current
	}
	close(stop)
	<-collectorDone

	mu.Lock()
	collected := append([]captured(nil), samples...)
	mu.Unlock()

	seenWorkers := map[int]int{}
	for _, sample := range collected {
		pathID, ok := workerIDFromPath(sample.path)
		if !ok {
			continue // not one of ours (another test's traffic in the same cgroup)
		}
		hostID, ok := workerIDFromHost(sample.host)
		if !ok {
			t.Fatalf("path %q carries worker %d but host %q is not a worker host: fields came from different requests",
				sample.path, pathID, sample.host)
		}
		if hostID != pathID {
			t.Fatalf("cross-request mix: path %q (worker %d) paired with host %q (worker %d)",
				sample.path, pathID, sample.host, hostID)
		}
		wantMethod := "GET"
		if pathID%2 == 1 {
			wantMethod = "POST"
		}
		if sample.method != wantMethod {
			t.Fatalf("cross-request mix: worker %d sent %s but sample carries method %q (path %q)",
				pathID, wantMethod, sample.method, sample.path)
		}
		seenWorkers[pathID]++
	}

	total := 0
	for _, count := range seenWorkers {
		total += count
	}
	// Drops are acceptable; a silent capture failure is not. Requiring several
	// workers keeps the integrity assertions above from passing vacuously.
	if len(seenWorkers) < 2 || total < workers {
		t.Fatalf("captured %d samples from %d workers, want traffic from at least 2 workers and %d samples overall",
			total, len(seenWorkers), workers)
	}
	t.Logf("concurrent capture: %d samples across %d workers (sent %d)",
		total, len(seenWorkers), workers*perWorker)
}

// workerIDFromPath parses "/w<id>/r<seq>" written by the concurrency test.
func workerIDFromPath(path string) (int, bool) {
	rest, ok := strings.CutPrefix(path, "/w")
	if !ok {
		return 0, false
	}
	digits, _, ok := strings.Cut(rest, "/")
	if !ok {
		return 0, false
	}
	id, err := strconv.Atoi(digits)
	if err != nil {
		return 0, false
	}
	return id, true
}

// workerIDFromHost parses "w<id>.example" written by the concurrency test.
func workerIDFromHost(host string) (int, bool) {
	digits, ok := strings.CutPrefix(host, "w")
	if !ok {
		return 0, false
	}
	digits, ok = strings.CutSuffix(digits, ".example")
	if !ok {
		return 0, false
	}
	id, err := strconv.Atoi(digits)
	if err != nil {
		return 0, false
	}
	return id, true
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
