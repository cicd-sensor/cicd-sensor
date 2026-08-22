//go:build linux && bpf_integration

package kerneltracker

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

// Stage 1b-2 reclaim E2E. These drive the discovery worker's reconcile directly
// with constructed MappedProcessSnapshots (via ReconcileHTTPUprobeTargets), so
// the tests are deterministic and do not wait on the 60 s ticker. The
// attached-target count is read back from the worker itself.

// startLibsslMapper starts a long-lived process that keeps libssl mapped:
// python3 importing ssl (libssl is dlopen'd and stays mapped while the process
// sleeps). Returns the PID; the process is killed on cleanup.
func startLibsslMapper(t *testing.T) int32 {
	t.Helper()
	python := requireBinary(t, "python3")
	cmd := exec.Command(python, "-c", "import ssl, time\ntime.sleep(600)")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start libssl mapper: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	// Wait until libssl shows up in its maps.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if mapsLibssl(int32(cmd.Process.Pid)) {
			return int32(cmd.Process.Pid)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("python3 never mapped libssl (ssl module missing?)")
	return 0
}

func mapsLibssl(pid int32) bool {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "maps"))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "libssl.so") || strings.Contains(string(data), "libssl3")
}

func newReclaimTestKernelIO(t *testing.T) (*kernelio.LinuxKernelIO, string) {
	t.Helper()
	cgroupRoot, err := getCgroupV2Root()
	if err != nil {
		t.Fatalf("getCgroupV2Root: %v", err)
	}
	kernelIO, err := kernelio.NewLinux(nil, kernelio.Config{CgroupV2RootPath: cgroupRoot, EnableOpenSSLHTTP: true})
	if err != nil {
		t.Fatalf("kernelio.NewLinux: %v", err)
	}
	t.Cleanup(func() { _ = kernelIO.Close() })
	return kernelIO, cgroupRoot
}

// waitTargets polls the worker-owned target count until it equals want.
func waitTargets(t *testing.T, ctx context.Context, kernelIO *kernelio.LinuxKernelIO, want int, why string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if n := kernelIO.TestOnlyHTTPUprobeTargetCount(ctx); n == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s: target count = %d, want %d", why, kernelIO.TestOnlyHTTPUprobeTargetCount(ctx), want)
}

// reconcileAndSettle enqueues one snapshot and returns only after the worker has
// reconciled it, by waiting on the snapshot's own Done channel (closed by the
// worker after reconcile). This is ordered by construction — unlike a query on a
// separate channel, which the worker's select does not serialize after the
// snapshot. Without it the latest-wins buffer (size 1) could replace a queued
// complete miss with the next incomplete one.
func reconcileAndSettle(ctx context.Context, kernelIO *kernelio.LinuxKernelIO, snapshot kernelio.MappedProcessSnapshot) {
	done := make(chan struct{})
	snapshot.Done = done
	kernelIO.ReconcileHTTPUprobeTargets(ctx, snapshot)
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func snapshotOf(complete bool, pids ...int32) kernelio.MappedProcessSnapshot {
	return kernelio.NewMappedProcessSnapshot(time.Now().UTC(), complete, pids, 1, 0, 0)
}

// TestLinuxHTTPUprobeReclaimSharedInode: an inode mapped by two tracked processes
// stays attached while EITHER maps it, and is closed only after two complete
// snapshots see neither — never because one of them left.
func TestLinuxHTTPUprobeReclaimSharedInode(t *testing.T) {
	kernelIO, cgroupRoot := newReclaimTestKernelIO(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)
	_ = trackTestProcessCgroup(t, ctx, kernelIO, cgroupRoot)

	a := startLibsslMapper(t)
	b := startLibsslMapper(t)

	// Discovery attaches via the snapshot scan itself (backstop path).
	reconcileAndSettle(ctx, kernelIO, snapshotOf(true, a, b))
	waitTargets(t, ctx, kernelIO, 1, "shared libssl inode attached once for two mappers")

	// Two complete snapshots that only list b: a left, but b still maps it.
	reconcileAndSettle(ctx, kernelIO, snapshotOf(true, b))
	reconcileAndSettle(ctx, kernelIO, snapshotOf(true, b))
	time.Sleep(500 * time.Millisecond)
	if n := kernelIO.TestOnlyHTTPUprobeTargetCount(ctx); n != 1 {
		t.Fatalf("target closed while still mapped by b: count = %d, want 1", n)
	}

	// Neither maps it: first complete miss keeps it, second closes it.
	reconcileAndSettle(ctx, kernelIO, snapshotOf(true))
	time.Sleep(300 * time.Millisecond)
	if n := kernelIO.TestOnlyHTTPUprobeTargetCount(ctx); n != 1 {
		t.Fatalf("closed after a single miss: count = %d, want 1", n)
	}
	reconcileAndSettle(ctx, kernelIO, snapshotOf(true))
	waitTargets(t, ctx, kernelIO, 0, "closed after two complete misses")
}

// TestLinuxHTTPUprobeReclaimIncompleteIsFailKeep: an incomplete snapshot never
// closes, and does not count toward the two misses.
func TestLinuxHTTPUprobeReclaimIncompleteIsFailKeep(t *testing.T) {
	kernelIO, cgroupRoot := newReclaimTestKernelIO(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)
	_ = trackTestProcessCgroup(t, ctx, kernelIO, cgroupRoot)

	a := startLibsslMapper(t)
	reconcileAndSettle(ctx, kernelIO, snapshotOf(true, a))
	waitTargets(t, ctx, kernelIO, 1, "attached")

	// complete-missing, then several INCOMPLETE empties: must stay attached.
	reconcileAndSettle(ctx, kernelIO, snapshotOf(true))
	for range 3 {
		reconcileAndSettle(ctx, kernelIO, snapshotOf(false))
	}
	time.Sleep(500 * time.Millisecond)
	if n := kernelIO.TestOnlyHTTPUprobeTargetCount(ctx); n != 1 {
		t.Fatalf("incomplete snapshots closed a target: count = %d, want 1", n)
	}
	// A second COMPLETE miss closes it (incomplete ones neither advanced nor reset).
	reconcileAndSettle(ctx, kernelIO, snapshotOf(true))
	waitTargets(t, ctx, kernelIO, 0, "closed by the second complete miss across incomplete scans")
}

// TestLinuxHTTPUprobeReclaimUnlinkedButMappedKept: a mapped libssl whose file
// was unlinked (in-place library upgrade mid-job) is NOT detached — the
// predicate is "still mapped by a tracked process", not file-existence.
func TestLinuxHTTPUprobeReclaimUnlinkedButMappedKept(t *testing.T) {
	kernelIO, cgroupRoot := newReclaimTestKernelIO(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	startKernelSampleLoop(t, ctx, kernelIO, kernelTracker)
	_ = trackTestProcessCgroup(t, ctx, kernelIO, cgroupRoot)

	// Copy libssl to a temp file, map it from a process, then unlink the copy.
	src := findLibsslPath(t)
	dir := t.TempDir()
	dst := filepath.Join(dir, "libssl-copy.so")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
	python := requireBinary(t, "python3")
	cmd := exec.Command(python, "-c", "import ctypes, time\nctypes.CDLL("+strconv.Quote(dst)+")\ntime.sleep(600)")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	pid := int32(cmd.Process.Pid)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if d, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "maps")); err == nil && strings.Contains(string(d), "libssl-copy.so") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	reconcileAndSettle(ctx, kernelIO, snapshotOf(true, pid))
	waitTargets(t, ctx, kernelIO, 1, "attached to the copied libssl")

	if err := os.Remove(dst); err != nil { // unlink while still mapped
		t.Fatal(err)
	}
	// Still mapped by pid: complete snapshots listing pid must keep it.
	reconcileAndSettle(ctx, kernelIO, snapshotOf(true, pid))
	reconcileAndSettle(ctx, kernelIO, snapshotOf(true, pid))
	time.Sleep(500 * time.Millisecond)
	if n := kernelIO.TestOnlyHTTPUprobeTargetCount(ctx); n != 1 {
		t.Fatalf("unlinked-but-mapped inode was detached: count = %d, want 1", n)
	}
}
