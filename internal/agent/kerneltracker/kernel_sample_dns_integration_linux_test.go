//go:build linux && integration

package kerneltracker

import (
	"context"
	"encoding/binary"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"
)

func TestLinuxKernelSampleDNSUDPEmitsEvent(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)

	cgroupID, err := lookupProcessCgroupID(int32(os.Getpid()), cgroupRoot)
	if err != nil {
		t.Fatalf("lookupProcessCgroupID: %v", err)
	}
	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, cgroupID); err != nil {
		t.Fatalf("put tracked cgroup: %v", err)
	}
	defer func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{cgroupID})
	}()

	// Hand-build a DNS query so the test does not depend on a real
	// resolver being reachable from the QEMU multikernel runner.
	queryName := "test.example.com."
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0xbeef, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(queryName),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack DNS: %v", err)
	}

	// sendto-style on a fresh UDP socket. The hook fires regardless of
	// whether anything listens on 127.0.0.1:53; we are only asserting
	// the udp_sendmsg fentry path completes the loop into engine.inputCh.
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer sock.Close()

	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
	if _, err := sock.WriteToUDP(payload, target); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}

	waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "dns event for test.example.com",
		func(in engineInput) bool {
			sample, ok := in.(dnsSample)
			if !ok {
				return false
			}
			if sample.CgroupID != cgroupID {
				return false
			}
			if sample.Source != DNSSourceUDP {
				return false
			}
			if sample.Dport != 53 {
				return false
			}
			domain, parsed := parseDNSQuery(sample.Payload)
			return parsed && domain == "test.example.com"
		})
}

func TestLinuxKernelSampleDNSTCPEmitsEvent(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)

	cgroupID, err := lookupProcessCgroupID(int32(os.Getpid()), cgroupRoot)
	if err != nil {
		t.Fatalf("lookupProcessCgroupID: %v", err)
	}
	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, cgroupID); err != nil {
		t.Fatalf("put tracked cgroup: %v", err)
	}
	defer func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{cgroupID})
	}()

	// systemd-resolved binds 127.0.0.53:53 on Ubuntu, so 127.0.0.1:53
	// is free in practice. The integration workflow lowers
	// net.ipv4.ip_unprivileged_port_start=53 because the rung-linux
	// runner drops CAP_NET_BIND_SERVICE from its sudo bounding set;
	// without that sysctl this Listen returns EACCES even as root.
	const tcpListenAddr = "127.0.0.1:53"
	listener, err := net.Listen("tcp4", tcpListenAddr)
	if err != nil {
		t.Fatalf("Listen tcp4 %s: %v", tcpListenAddr, err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Drain the request so the client's Write does not block on a
		// full receive buffer for this tiny payload.
		go func() {
			_, _ = io.Copy(io.Discard, conn)
			_ = conn.Close()
		}()
	}()

	queryName := "tcp.example.com."
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0xcafe, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(queryName),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack DNS: %v", err)
	}

	conn, err := net.DialTimeout("tcp4", tcpListenAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// RFC 1035 §4.2.2: TCP DNS prepends a 2-byte big-endian length to
	// the message. The BPF hook captures the raw bytes including the
	// prefix; userspace strips it before parseDNSQuery.
	framed := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(payload)))
	copy(framed[2:], payload)
	if _, err := conn.Write(framed); err != nil {
		t.Fatalf("Write: %v", err)
	}

	waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "tcp dns event for tcp.example.com",
		func(in engineInput) bool {
			sample, ok := in.(dnsSample)
			if !ok {
				return false
			}
			if sample.CgroupID != cgroupID {
				return false
			}
			if sample.Source != DNSSourceTCP {
				return false
			}
			if sample.Dport != 53 {
				return false
			}
			if len(sample.Payload) < 2 {
				return false
			}
			domain, parsed := parseDNSQuery(sample.Payload[2:])
			return parsed && domain == "tcp.example.com"
		})
}

func waitForDNSQuery(t *testing.T, kernelTracker *KernelTracker, cgroupID uint64, domain string, timeout time.Duration) {
	t.Helper()

	waitForEngineInput(t, kernelTracker.inputCh, timeout, "dns event for "+domain,
		func(in engineInput) bool {
			sample, ok := in.(dnsSample)
			if !ok {
				return false
			}
			if sample.CgroupID != cgroupID {
				return false
			}
			if sample.Source != DNSSourceUDP || sample.Dport != 53 {
				return false
			}
			got, parsed := parseDNSQuery(sample.Payload)
			return parsed && got == domain
		})
}

func TestLinuxKernelSampleDNSSystemdResolvedEmitsEvent(t *testing.T) {
	const varlinkSocket = "/run/systemd/resolve/io.systemd.Resolve"
	if _, err := os.Stat(varlinkSocket); err != nil {
		// The unix_stream_sendmsg hook filters by exact peer-bound
		// path, so this E2E path requires the real systemd-resolved
		// daemon. Fail loudly rather than skip — the integration
		// workflow rejects skipped tests.
		t.Fatalf("stat %q: %v (test requires systemd-resolved running)", varlinkSocket, err)
	}

	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)

	cgroupID, err := lookupProcessCgroupID(int32(os.Getpid()), cgroupRoot)
	if err != nil {
		t.Fatalf("lookupProcessCgroupID: %v", err)
	}
	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, cgroupID); err != nil {
		t.Fatalf("put tracked cgroup: %v", err)
	}
	defer func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{cgroupID})
	}()

	conn, err := net.Dial("unix", varlinkSocket)
	if err != nil {
		t.Fatalf("Dial unix %q: %v", varlinkSocket, err)
	}
	defer conn.Close()

	// .invalid TLD per RFC 6761 will never resolve. systemd-resolved
	// returns NXDOMAIN, but the BPF hook fires on unix_stream_sendmsg
	// before any reply matters. Varlink frames are NUL-terminated.
	const queryName = "tcp.example.invalid"
	request := []byte(`{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"` + queryName + `","family":0,"flags":0}}` + "\x00")
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("Write Varlink request: %v", err)
	}

	waitForEngineInput(t, kernelTracker.inputCh, 5*time.Second, "systemd-resolved dns event for "+queryName,
		func(in engineInput) bool {
			sample, ok := in.(dnsSample)
			if !ok {
				return false
			}
			if sample.CgroupID != cgroupID {
				return false
			}
			if sample.Source != DNSSourceSystemdResolved {
				return false
			}
			domain, parsed := parseSystemdResolvedQuery(sample.Payload)
			return parsed && domain == queryName
		})
}

// The DNS tests above hand-build wire bytes from the test goroutine.
// They lock the BPF struct layout, the parser, and the udp/tcp/unix
// fentry attaches in isolation, but they don't exercise the full
// production path: a child process running a real resolver client,
// glibc / bind9 issuing a real getaddrinfo or send, the kernel routing
// it through sendmsg with whatever iov layout that resolver uses. The
// three tests below cover that path by exec'ing dig and resolvectl
// from inside the tracked cgroup so the BPF hook sees the real bytes.

func TestLinuxKernelSampleDNSUDPViaDigEndToEnd(t *testing.T) {
	digPath := requireBinary(t, "dig")
	cgroupID, kernelTracker, cleanup := startTrackedKernelIO(t)
	defer cleanup()

	const attempts = 3
	for attempt := 1; attempt <= attempts; attempt++ {
		queryName := fmt.Sprintf("e2e-udp-%d.example.invalid", attempt)
		// dig defaults to UDP. +tries=1 +timeout=2 keeps each attempt
		// bounded; retries absorb LVH startup/scheduling jitter.
		cmd := exec.Command(digPath, "@127.0.0.1", "-p", "53", "+tries=1", "+timeout=2", "+short", queryName)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		_ = cmd.Run() // exit code irrelevant; no resolver needs to answer

		if _, ok := findEngineInput(kernelTracker.inputCh, 10*time.Second, func(in engineInput) bool {
			sample, ok := in.(dnsSample)
			if !ok || sample.CgroupID != cgroupID {
				return false
			}
			if sample.Source != DNSSourceUDP || sample.Dport != 53 {
				return false
			}
			domain, parsed := parseDNSQuery(sample.Payload)
			return parsed && domain == queryName
		}); ok {
			return
		}
	}
	t.Fatalf("timed out waiting for udp dns event after %d attempts", attempts)
}

func TestLinuxKernelSampleDNSTCPViaDigEndToEnd(t *testing.T) {
	digPath := requireBinary(t, "dig")
	cgroupID, kernelTracker, cleanup := startTrackedKernelIO(t)
	defer cleanup()

	const tcpListenAddr = "127.0.0.1:53"
	listener, err := net.Listen("tcp4", tcpListenAddr)
	if err != nil {
		t.Fatalf("Listen tcp4 %s: %v", tcpListenAddr, err)
	}
	defer listener.Close()

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

	const attempts = 3
	for attempt := 1; attempt <= attempts; attempt++ {
		queryName := fmt.Sprintf("e2e-tcp-%d.example.invalid", attempt)
		cmd := exec.Command(digPath, "+tcp", "@127.0.0.1", "-p", "53", "+tries=1", "+timeout=2", "+short", queryName)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		_ = cmd.Run()

		if _, ok := findEngineInput(kernelTracker.inputCh, 10*time.Second, func(in engineInput) bool {
			sample, ok := in.(dnsSample)
			if !ok || sample.CgroupID != cgroupID {
				return false
			}
			if sample.Source != DNSSourceTCP || sample.Dport != 53 {
				return false
			}
			if len(sample.Payload) < 2 {
				return false
			}
			domain, parsed := parseDNSQuery(sample.Payload[2:])
			return parsed && domain == queryName
		}); ok {
			return
		}
	}
	t.Fatalf("timed out waiting for tcp dns event after %d attempts", attempts)
}

func TestLinuxKernelSampleDNSSystemdResolvedViaGetentEndToEnd(t *testing.T) {
	const varlinkSocket = "/run/systemd/resolve/io.systemd.Resolve"
	if _, err := os.Stat(varlinkSocket); err != nil {
		t.Fatalf("stat %q: %v (test requires systemd-resolved running)", varlinkSocket, err)
	}
	getentPath := requireBinary(t, "getent")

	// Skip if /etc/nsswitch.conf does not route the hosts database
	// through `resolve` — without it, getent uses the dns backend
	// and never touches the Varlink socket. (resolvectl was tried
	// here first; it talks to systemd-resolved over D-Bus, not
	// Varlink, so the unix_stream_sendmsg hook never sees its
	// requests.)
	nsswitch, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		t.Fatalf("read /etc/nsswitch.conf: %v", err)
	}
	if !regexp.MustCompile(`(?m)^hosts:.*\bresolve\b`).Match(nsswitch) {
		t.Fatalf("nsswitch.conf hosts: line missing `resolve` backend; install libnss-resolve so getent reaches Varlink")
	}

	cgroupID, kernelTracker, cleanup := startTrackedKernelIO(t)
	defer cleanup()

	const queryName = "e2e-getent.example.invalid"
	cmd := exec.Command(getentPath, "hosts", queryName)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	_ = cmd.Run() // .invalid → NXDOMAIN; the Varlink send fires first

	waitForEngineInput(t, kernelTracker.inputCh, 10*time.Second, "systemd-resolved dns event for "+queryName,
		func(in engineInput) bool {
			sample, ok := in.(dnsSample)
			if !ok || sample.CgroupID != cgroupID {
				return false
			}
			if sample.Source != DNSSourceSystemdResolved {
				return false
			}
			domain, parsed := parseSystemdResolvedQuery(sample.Payload)
			return parsed && domain == queryName
		})
}
