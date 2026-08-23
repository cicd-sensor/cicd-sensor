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

// Stage 1b-2 reclaim E2E. These drive the discovery worker with constructed
// tracked cgroup paths, so the tests cover cgroup.procs -> PID -> maps ->
// uprobe lifecycle without waiting on the 60 s ticker.

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

func newReclaimTestKernelIO(t *testing.T) *kernelio.LinuxKernelIO {
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
	return kernelIO
}

func startReclaimWorker(t *testing.T, ctx context.Context, kernelIO *kernelio.LinuxKernelIO) {
	t.Helper()
	if err := kernelIO.StartKernelSampleLoop(ctx, func(context.Context, kernelio.KernelSample) error { return nil }); err != nil {
		t.Fatalf("start kernel sample loop: %v", err)
	}
}

// reconcileAndSettle waits for the worker and returns its target count.
func reconcileAndSettle(t *testing.T, ctx context.Context, kernelIO *kernelio.LinuxKernelIO, cgroupPaths []string) int {
	t.Helper()
	count := kernelIO.TestOnlyReconcileHTTPUprobeTargets(ctx, cgroupPaths)
	if count < 0 {
		t.Fatalf("reconcile did not complete: %v", ctx.Err())
	}
	return count
}

func cgroupPathsForPIDs(t *testing.T, pids ...int32) []string {
	t.Helper()
	if len(pids) == 0 {
		return nil
	}
	cgroupPath := t.TempDir()
	lines := make([]string, 0, len(pids))
	for _, pid := range pids {
		lines = append(lines, strconv.FormatInt(int64(pid), 10))
	}
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write cgroup.procs: %v", err)
	}
	return []string{cgroupPath}
}

func unreadableCgroupPaths(t *testing.T) []string {
	t.Helper()
	notDirectory := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(notDirectory, nil, 0o644); err != nil {
		t.Fatalf("write non-directory cgroup path: %v", err)
	}
	return []string{notDirectory}
}

// TestLinuxHTTPUprobeReclaimSharedInode: an inode mapped by two tracked processes
// stays attached while EITHER maps it, and is closed only after two complete
// scans see neither — never because one of them left.
func TestLinuxHTTPUprobeReclaimSharedInode(t *testing.T) {
	kernelIO := newReclaimTestKernelIO(t)
	ctx := t.Context()
	startReclaimWorker(t, ctx, kernelIO)

	a := startLibsslMapper(t)
	b := startLibsslMapper(t)

	// Discovery attaches via reconciliation itself (backstop path).
	if got := reconcileAndSettle(t, ctx, kernelIO, cgroupPathsForPIDs(t, a, b)); got != 1 {
		t.Fatalf("shared libssl inode target count = %d, want 1", got)
	}

	// One miss followed by seeing b resets the target's missing count.
	if n := reconcileAndSettle(t, ctx, kernelIO, cgroupPathsForPIDs(t)); n != 1 {
		t.Fatalf("closed after a single miss: count = %d, want 1", n)
	}
	if n := reconcileAndSettle(t, ctx, kernelIO, cgroupPathsForPIDs(t, b)); n != 1 {
		t.Fatalf("target closed while still mapped by b: count = %d, want 1", n)
	}

	// Because seeing b reset the count, the next miss still keeps the target.
	if n := reconcileAndSettle(t, ctx, kernelIO, cgroupPathsForPIDs(t)); n != 1 {
		t.Fatalf("closed after a miss following reappearance: count = %d, want 1", n)
	}
	if n := reconcileAndSettle(t, ctx, kernelIO, cgroupPathsForPIDs(t)); n != 0 {
		t.Fatalf("target count after second complete miss = %d, want 0", n)
	}
}

// TestLinuxHTTPUprobeReclaimIncompleteIsFailKeep: an incomplete scan never
// closes, and does not count toward the two misses.
func TestLinuxHTTPUprobeReclaimIncompleteIsFailKeep(t *testing.T) {
	kernelIO := newReclaimTestKernelIO(t)
	ctx := t.Context()
	startReclaimWorker(t, ctx, kernelIO)

	a := startLibsslMapper(t)
	if n := reconcileAndSettle(t, ctx, kernelIO, cgroupPathsForPIDs(t, a)); n != 1 {
		t.Fatalf("target count after attach = %d, want 1", n)
	}

	// complete-missing, then several INCOMPLETE empties: must stay attached.
	reconcileAndSettle(t, ctx, kernelIO, cgroupPathsForPIDs(t))
	if n := reconcileAndSettle(t, ctx, kernelIO, unreadableCgroupPaths(t)); n != 1 {
		t.Fatalf("incomplete scan closed a target: count = %d, want 1", n)
	}
	// A second COMPLETE miss closes it (incomplete ones neither advanced nor reset).
	if n := reconcileAndSettle(t, ctx, kernelIO, cgroupPathsForPIDs(t)); n != 0 {
		t.Fatalf("target count after second complete miss = %d, want 0", n)
	}
}

// TestLinuxHTTPUprobeReclaimUnlinkedButMappedKept: a mapped libssl whose file
// was unlinked (in-place library upgrade mid-job) is NOT detached — the
// predicate is "still mapped by a tracked process", not file-existence.
func TestLinuxHTTPUprobeReclaimUnlinkedButMappedKept(t *testing.T) {
	kernelIO := newReclaimTestKernelIO(t)
	ctx := t.Context()
	startReclaimWorker(t, ctx, kernelIO)

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

	if n := reconcileAndSettle(t, ctx, kernelIO, cgroupPathsForPIDs(t, pid)); n != 1 {
		t.Fatalf("target count after copied libssl attach = %d, want 1", n)
	}

	if err := os.Remove(dst); err != nil { // unlink while still mapped
		t.Fatal(err)
	}
	// Still mapped by pid: complete scans listing pid must keep it.
	reconcileAndSettle(t, ctx, kernelIO, cgroupPathsForPIDs(t, pid))
	if n := reconcileAndSettle(t, ctx, kernelIO, cgroupPathsForPIDs(t, pid)); n != 1 {
		t.Fatalf("unlinked-but-mapped inode was detached: count = %d, want 1", n)
	}
}
