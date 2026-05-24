//go:build linux && bpf_integration

package kerneltracker

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

func TestLinuxKernelSampleNetworkConnectV4EndToEnd(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	done := make(chan error, 1)
	go func() {
		done <- engine.Run(ctx)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run error = %v, want nil", err)
		}
	}()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "net-hooks")
	eventCh, err := engine.RegisterJob(ctx, jobID)
	if err != nil {
		t.Fatalf("RegisterJob: %v", err)
	}
	if err := engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid())); err != nil {
		t.Fatalf("BindProcessCgroupToJob: %v", err)
	}
	if eventCh == nil {
		t.Fatal("RegisterJob returned nil event channel")
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("Close listener: %v", err)
	}

	_, _ = net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(closedPort)), 100*time.Millisecond)

	waitForEventRecord(t, eventCh, 5*time.Second, "network_connect", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.NetworkConnect {
			return false
		}

		remoteIP, _ := record.Payload["remote_ip"].(string)
		remotePort, _ := record.Payload["remote_port"].(int)
		protocol, _ := record.Payload["protocol"].(string)
		if remoteIP != "127.0.0.1" || remotePort != closedPort || protocol != "tcp" {
			return false
		}
		return true
	})
}

func TestLinuxKernelSampleNetworkConnectV4UDPEndToEnd(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	done := make(chan error, 1)
	go func() {
		done <- engine.Run(ctx)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run error = %v, want nil", err)
		}
	}()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "net-hooks-udp4")
	eventCh, err := engine.RegisterJob(ctx, jobID)
	if err != nil {
		t.Fatalf("RegisterJob: %v", err)
	}
	if err := engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid())); err != nil {
		t.Fatalf("BindProcessCgroupToJob: %v", err)
	}
	if eventCh == nil {
		t.Fatal("RegisterJob returned nil event channel")
	}

	const remotePort = 9
	conn, _ := net.DialTimeout("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)), 100*time.Millisecond)
	if conn != nil {
		_ = conn.Close()
	}

	waitForEventRecord(t, eventCh, 5*time.Second, "network_connect_udp4", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.NetworkConnect {
			return false
		}

		remoteIP, _ := record.Payload["remote_ip"].(string)
		remotePortPayload, _ := record.Payload["remote_port"].(int)
		protocol, _ := record.Payload["protocol"].(string)
		family, _ := record.Payload["family"].(string)
		if remoteIP != "127.0.0.1" || remotePortPayload != remotePort || protocol != "udp" || family != "ipv4" {
			return false
		}
		return true
	})
}

func TestLinuxKernelSampleNetworkConnectZeroPortIsIgnored(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	done := make(chan error, 1)
	go func() {
		done <- engine.Run(ctx)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run error = %v, want nil", err)
		}
	}()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "net-hooks-zero-port")
	eventCh, err := engine.RegisterJob(ctx, jobID)
	if err != nil {
		t.Fatalf("RegisterJob: %v", err)
	}
	if err := engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid())); err != nil {
		t.Fatalf("BindProcessCgroupToJob: %v", err)
	}
	if eventCh == nil {
		t.Fatal("RegisterJob returned nil event channel")
	}

	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			host := "127.0.0.1"
			if network == "udp6" {
				host = "::1"
			}
			conn, _ := net.DialTimeout(network, net.JoinHostPort(host, "0"), 100*time.Millisecond)
			if conn != nil {
				_ = conn.Close()
			}

			assertNoEventRecord(t, eventCh, 300*time.Millisecond, func(record jobevent.EventRecord) bool {
				if record.EventType != jobevent.NetworkConnect {
					return false
				}
				remotePort, _ := record.Payload["remote_port"].(int)
				protocol, _ := record.Payload["protocol"].(string)
				return remotePort == 0 && protocol == "udp"
			})
		})
	}
}

func TestLinuxKernelSampleNetworkConnectV6EndToEnd(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	done := make(chan error, 1)
	go func() {
		done <- engine.Run(ctx)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run error = %v, want nil", err)
		}
	}()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "net-hooks-v6")
	eventCh, err := engine.RegisterJob(ctx, jobID)
	if err != nil {
		t.Fatalf("RegisterJob: %v", err)
	}
	if err := engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid())); err != nil {
		t.Fatalf("BindProcessCgroupToJob: %v", err)
	}
	if eventCh == nil {
		t.Fatal("RegisterJob returned nil event channel")
	}

	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatalf("Listen tcp6: %v", err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("Close listener: %v", err)
	}

	_, _ = net.DialTimeout("tcp6", net.JoinHostPort("::1", strconv.Itoa(closedPort)), 100*time.Millisecond)

	waitForEventRecord(t, eventCh, 5*time.Second, "network_connect_ipv6", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.NetworkConnect {
			return false
		}

		remoteIP, _ := record.Payload["remote_ip"].(string)
		remotePort, _ := record.Payload["remote_port"].(int)
		protocol, _ := record.Payload["protocol"].(string)
		family, _ := record.Payload["family"].(string)
		if remoteIP != "::1" || remotePort != closedPort || protocol != "tcp" || family != "ipv6" {
			return false
		}
		return true
	})
}

func TestLinuxKernelSampleNetworkConnectV6UDPEndToEnd(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	done := make(chan error, 1)
	go func() {
		done <- engine.Run(ctx)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run error = %v, want nil", err)
		}
	}()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "net-hooks-udp6")
	eventCh, err := engine.RegisterJob(ctx, jobID)
	if err != nil {
		t.Fatalf("RegisterJob: %v", err)
	}
	if err := engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid())); err != nil {
		t.Fatalf("BindProcessCgroupToJob: %v", err)
	}
	if eventCh == nil {
		t.Fatal("RegisterJob returned nil event channel")
	}

	for _, remotePort := range []int{9, 443} {
		t.Run(strconv.Itoa(remotePort), func(t *testing.T) {
			conn, _ := net.DialTimeout("udp6", net.JoinHostPort("::1", strconv.Itoa(remotePort)), 100*time.Millisecond)
			if conn != nil {
				_ = conn.Close()
			}

			waitForEventRecord(t, eventCh, 5*time.Second, "network_connect_udp6", func(record jobevent.EventRecord) bool {
				if record.EventType != jobevent.NetworkConnect {
					return false
				}

				remoteIP, _ := record.Payload["remote_ip"].(string)
				remotePortPayload, _ := record.Payload["remote_port"].(int)
				protocol, _ := record.Payload["protocol"].(string)
				family, _ := record.Payload["family"].(string)
				if remoteIP != "::1" || remotePortPayload != remotePort || protocol != "udp" || family != "ipv6" {
					return false
				}
				return true
			})
		})
	}
}
