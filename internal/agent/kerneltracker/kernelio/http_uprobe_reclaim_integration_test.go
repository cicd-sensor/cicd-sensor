//go:build linux && bpf_integration

package kernelio

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Stage 1b-2 reclaim E2E. These tests call the worker-owned reconciliation
// synchronously, covering cgroup.procs -> PID -> maps -> uprobe lifecycle
// without exposing test completion channels in production.

func requireTestBinary(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is required: %v", name, err)
	}
	return path
}

func startLibsslMapper(t *testing.T) int32 {
	t.Helper()
	python := requireTestBinary(t, "python3")
	cmd := exec.Command(python, "-c", "import ssl, time\ntime.sleep(600)")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start libssl mapper: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if processMapsLibssl(int32(cmd.Process.Pid)) {
			return int32(cmd.Process.Pid)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("python3 never mapped libssl (ssl module missing?)")
	return 0
}

func processMapsLibssl(pid int32) bool {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "maps"))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "libssl.so") || strings.Contains(string(data), "libssl3")
}

func newReclaimTestDiscovery(t *testing.T) *httpUprobeDiscovery {
	t.Helper()
	config := testLinuxConfig(t)
	config.EnableHTTPUprobes = true
	kernelIO, err := NewLinux(nil, config)
	if err != nil {
		t.Fatalf("NewLinux: %v", err)
	}
	discovery := kernelIO.httpUprobeDiscovery
	discovery.cgroupRootPath = t.TempDir()
	t.Cleanup(func() {
		discovery.closeAll()
		_ = kernelIO.Close()
	})
	return discovery
}

func reconcileAndCount(discovery *httpUprobeDiscovery, activeCgroupIDs []uint64) int {
	discovery.reconcileTargets(activeCgroupIDs)
	return len(discovery.attachedTargets)
}

func discoverAndCount(discovery *httpUprobeDiscovery, pids ...int32) int {
	for _, pid := range pids {
		discovery.discoverAndAttachTargets(pid)
	}
	return len(discovery.attachedTargets)
}

func cgroupIDsForPIDs(t *testing.T, discovery *httpUprobeDiscovery, pids ...int32) []uint64 {
	t.Helper()
	if len(pids) == 0 {
		return nil
	}
	cgroupPath, err := os.MkdirTemp(discovery.cgroupRootPath, "tracked-")
	if err != nil {
		t.Fatalf("create tracked cgroup: %v", err)
	}
	lines := make([]string, 0, len(pids))
	for _, pid := range pids {
		lines = append(lines, strconv.FormatInt(int64(pid), 10))
	}
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write cgroup.procs: %v", err)
	}
	return []uint64{testPathInode(t, cgroupPath)}
}

func unreadableCgroupIDs(t *testing.T, discovery *httpUprobeDiscovery) []uint64 {
	t.Helper()
	cgroupPath, err := os.MkdirTemp(discovery.cgroupRootPath, "unreadable-")
	if err != nil {
		t.Fatalf("create unreadable cgroup: %v", err)
	}
	if err := os.Mkdir(filepath.Join(cgroupPath, "cgroup.procs"), 0o755); err != nil {
		t.Fatalf("create invalid cgroup.procs: %v", err)
	}
	return []uint64{testPathInode(t, cgroupPath)}
}

// TestLinuxHTTPUprobeReclaimSharedInode verifies that an inode mapped by two
// tracked processes remains attached while either process maps it.
func TestLinuxHTTPUprobeReclaimSharedInode(t *testing.T) {
	discovery := newReclaimTestDiscovery(t)
	a := startLibsslMapper(t)
	b := startLibsslMapper(t)

	if got := discoverAndCount(discovery, a, b); got != 1 {
		t.Fatalf("shared libssl inode target count = %d, want 1", got)
	}
	reconcileAndCount(discovery, cgroupIDsForPIDs(t, discovery, a, b))
	if got := reconcileAndCount(discovery, nil); got != 1 {
		t.Fatalf("closed after a single miss: count = %d, want 1", got)
	}
	if got := reconcileAndCount(discovery, cgroupIDsForPIDs(t, discovery, b)); got != 1 {
		t.Fatalf("target closed while still mapped by b: count = %d, want 1", got)
	}
	if got := reconcileAndCount(discovery, nil); got != 1 {
		t.Fatalf("closed after a miss following reappearance: count = %d, want 1", got)
	}
	if got := reconcileAndCount(discovery, nil); got != 0 {
		t.Fatalf("target count after second complete miss = %d, want 0", got)
	}
}

// TestLinuxHTTPUprobeReclaimIncompleteIsFailKeep verifies that an incomplete
// scan neither closes a target nor advances its missing count.
func TestLinuxHTTPUprobeReclaimIncompleteIsFailKeep(t *testing.T) {
	discovery := newReclaimTestDiscovery(t)
	a := startLibsslMapper(t)
	if got := discoverAndCount(discovery, a); got != 1 {
		t.Fatalf("target count after attach = %d, want 1", got)
	}
	reconcileAndCount(discovery, cgroupIDsForPIDs(t, discovery, a))

	reconcileAndCount(discovery, nil)
	if got := reconcileAndCount(discovery, unreadableCgroupIDs(t, discovery)); got != 1 {
		t.Fatalf("incomplete scan closed a target: count = %d, want 1", got)
	}
	if got := reconcileAndCount(discovery, nil); got != 0 {
		t.Fatalf("target count after second complete miss = %d, want 0", got)
	}
}

// TestLinuxHTTPUprobeReclaimUnlinkedButMappedKept verifies that reclaim uses
// maps-liveness rather than pathname existence.
func TestLinuxHTTPUprobeReclaimUnlinkedButMappedKept(t *testing.T) {
	discovery := newReclaimTestDiscovery(t)
	src := findLibssl(t)
	dst := filepath.Join(t.TempDir(), "libssl-copy.so")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}

	python := requireTestBinary(t, "python3")
	cmd := exec.Command(python, "-c", "import ctypes, time\nctypes.CDLL("+strconv.Quote(dst)+")\ntime.sleep(600)")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	pid := int32(cmd.Process.Pid)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "maps")); err == nil && strings.Contains(string(data), "libssl-copy.so") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if got := discoverAndCount(discovery, pid); got != 1 {
		t.Fatalf("target count after copied libssl attach = %d, want 1", got)
	}
	reconcileAndCount(discovery, cgroupIDsForPIDs(t, discovery, pid))
	if err := os.Remove(dst); err != nil {
		t.Fatal(err)
	}
	reconcileAndCount(discovery, cgroupIDsForPIDs(t, discovery, pid))
	if got := reconcileAndCount(discovery, cgroupIDsForPIDs(t, discovery, pid)); got != 1 {
		t.Fatalf("unlinked-but-mapped inode was detached: count = %d, want 1", got)
	}
}
