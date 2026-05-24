//go:build linux && bpf_integration

package kerneltracker

import (
	"context"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLinuxKernelSampleUnixSocketConnectProxyBypassEndToEnd verifies the agent
// observes a CI workload bypassing the dockerd proxy by connecting directly
// to the renamed real backend. Production layout:
//
//	/var/run/docker.sock       -> cicd-sensor proxy listen
//	/var/run/docker-upstream.sock  -> renamed real dockerd
//
// A bypass attempt = AF_UNIX connect(2) to the renamed real path. The hook
// is pre-namei so `path` carries what the workload wrote, absolutized for
// relative inputs. Sub-cases follow docs/rules/path-semantics.md.
func TestLinuxKernelSampleUnixSocketConnectProxyBypassEndToEnd(t *testing.T) {
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

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "unix-bypass")
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

	t.Run("absolute_path_simulating_renamed_real_backend", func(t *testing.T) {
		tempDir := t.TempDir()
		sockPath := filepath.Join(tempDir, "docker-upstream.sock")
		listener, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatalf("Listen unix %s: %v", sockPath, err)
		}
		defer listener.Close()
		go acceptAndDiscardUnix(listener)

		conn, err := net.Dial("unix", sockPath)
		if err != nil {
			t.Fatalf("Dial unix %s: %v", sockPath, err)
		}
		defer conn.Close()

		waitForEventRecord(t, eventCh, 5*time.Second, "unix_socket_connect absolute",
			func(record jobevent.EventRecord) bool {
				if record.EventType != jobevent.UnixSocketConnect {
					return false
				}
				path, _ := record.Payload["path"].(string)
				socketType, _ := record.Payload["socket_type"].(string)
				isAbstract, _ := record.Payload["is_abstract"].(bool)
				return path == sockPath && socketType == "stream" && !isAbstract
			})
	})

	t.Run("abstract_namespace", func(t *testing.T) {
		// sun_path[0] == 0 marks the abstract namespace. Per-run unique
		// name avoids collision when reruns overlap.
		name := "@cicd-sensor-test-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		addr := &net.UnixAddr{Name: name, Net: "unix"}
		listener, err := net.ListenUnix("unix", addr)
		if err != nil {
			t.Fatalf("ListenUnix abstract: %v", err)
		}
		defer listener.Close()
		go acceptAndDiscardUnix(listener)

		conn, err := net.DialUnix("unix", nil, addr)
		if err != nil {
			t.Fatalf("DialUnix abstract: %v", err)
		}
		defer conn.Close()

		waitForEventRecord(t, eventCh, 5*time.Second, "unix_socket_connect abstract",
			func(record jobevent.EventRecord) bool {
				if record.EventType != jobevent.UnixSocketConnect {
					return false
				}
				path, _ := record.Payload["path"].(string)
				isAbstract, _ := record.Payload["is_abstract"].(bool)
				return path == name && isAbstract
			})
	})

	t.Run("relative_path_resolved_by_cwd", func(t *testing.T) {
		tempDir := t.TempDir()
		sockPath := filepath.Join(tempDir, "docker-upstream.sock")
		listener, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatalf("Listen unix %s: %v", sockPath, err)
		}
		defer listener.Close()
		go acceptAndDiscardUnix(listener)

		// t.Chdir reverts at sub-test exit. Closes the chdir bypass class:
		// `connect("./docker-upstream.sock")` from cwd=tempDir must absolutize
		// to sockPath via the kernel-side cwd walk + path.Clean.
		t.Chdir(tempDir)
		conn, err := net.Dial("unix", "./docker-upstream.sock")
		if err != nil {
			t.Fatalf("Dial unix ./docker-upstream.sock: %v", err)
		}
		defer conn.Close()

		// On container CI rootfs (LVH kind) the kernel-side cwd walk can
		// land on a layer-internal path rather than the visible /tmp/...,
		// so match by basename suffix and log what we actually saw.
		waitForEventRecord(t, eventCh, 5*time.Second, "unix_socket_connect relative",
			func(record jobevent.EventRecord) bool {
				if record.EventType != jobevent.UnixSocketConnect {
					return false
				}
				path, _ := record.Payload["path"].(string)
				t.Logf("unix_socket_connect relative saw path=%q (want suffix %q)", path, "/"+filepath.Base(sockPath))
				return strings.HasSuffix(path, "/"+filepath.Base(sockPath))
			})
	})

	t.Run("real_var_run_docker_upstream_sock_if_proxy_deployed", func(t *testing.T) {
		const realPath = "/var/run/docker-upstream.sock"
		if _, err := os.Stat(realPath); err != nil {
			t.Skipf("%s not present (dockerd proxy not deployed): %v", realPath, err)
		}
		conn, err := net.Dial("unix", realPath)
		if err != nil {
			t.Skipf("Dial %s: %v", realPath, err)
		}
		defer conn.Close()

		waitForEventRecord(t, eventCh, 5*time.Second, "docker-upstream.sock bypass",
			func(record jobevent.EventRecord) bool {
				if record.EventType != jobevent.UnixSocketConnect {
					return false
				}
				path, _ := record.Payload["path"].(string)
				return path == realPath
			})
	})
}

// acceptAndDiscardUnix drains the listener until it is closed. The test
// cares about the connect event, not the byte stream, so accepted
// connections are immediately discarded.
func acceptAndDiscardUnix(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			_, _ = io.Copy(io.Discard, c)
			_ = c.Close()
		}(conn)
	}
}
