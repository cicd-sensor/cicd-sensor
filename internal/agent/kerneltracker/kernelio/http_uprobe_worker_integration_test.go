//go:build linux && bpf_integration

package kernelio

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
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

func newReclaimTestWorker(t *testing.T) *httpUprobeWorker {
	t.Helper()
	config := testLinuxConfig(t)
	config.EnableHTTPUprobes = true
	kernelIO, err := NewLinux(nil, config)
	if err != nil {
		t.Fatalf("NewLinux: %v", err)
	}
	worker := kernelIO.httpUprobeWorker
	worker.cgroupRootPath = t.TempDir()
	t.Cleanup(func() {
		worker.closeAll()
		_ = kernelIO.Close()
	})
	return worker
}

func reconcileAndCount(worker *httpUprobeWorker, activeCgroupIDs []uint64) int {
	worker.reconcileTargets(activeCgroupIDs)
	return len(worker.attachedTargets)
}

func discoverAndCount(t *testing.T, worker *httpUprobeWorker, pids ...int32) int {
	t.Helper()
	for _, pid := range pids {
		mappings, _ := worker.scanProcessMappings(pid)
		for _, candidate := range mappings {
			startText, endText, ok := strings.Cut(candidate.addressRange, "-")
			if !ok {
				continue
			}
			start, startErr := strconv.ParseUint(startText, 16, 64)
			end, endErr := strconv.ParseUint(endText, 16, 64)
			if startErr != nil || endErr != nil {
				continue
			}
			f, err := os.Open(mappedFilePath(pid, start, end))
			if err != nil {
				continue
			}
			key, err := classificationKeyFromFile(f)
			_ = f.Close()
			if err != nil {
				continue
			}
			if err := worker.discoveryCache.Put(key, uint8(1)); err != nil {
				t.Fatalf("record discovery file: %v", err)
			}
			worker.classifyAndAttach(httpUprobeAttachCandidate{
				process: httpUprobeProcessGeneration{TGID: pid}, vmStart: start, vmEnd: end, file: key,
			})
		}
	}
	return len(worker.attachedTargets)
}

func cgroupIDsForPIDs(t *testing.T, worker *httpUprobeWorker, pids ...int32) []uint64 {
	t.Helper()
	if len(pids) == 0 {
		return nil
	}
	cgroupPath, err := os.MkdirTemp(worker.cgroupRootPath, "tracked-")
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

func unreadableCgroupIDs(t *testing.T, worker *httpUprobeWorker) []uint64 {
	t.Helper()
	cgroupPath, err := os.MkdirTemp(worker.cgroupRootPath, "unreadable-")
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
	worker := newReclaimTestWorker(t)
	a := startLibsslMapper(t)
	b := startLibsslMapper(t)

	if got := discoverAndCount(t, worker, a, b); got != 1 {
		t.Fatalf("shared libssl inode target count = %d, want 1", got)
	}
	var target *attachedUprobeTarget
	for _, target = range worker.attachedTargets {
		break
	}
	if target == nil || !discoveryCacheContains(t, worker, target.classificationKey) {
		t.Fatal("attached target has no BPF discovery-cache key")
	}
	reconcileAndCount(worker, cgroupIDsForPIDs(t, worker, a, b))
	if got := reconcileAndCount(worker, nil); got != 1 {
		t.Fatalf("closed after a single miss: count = %d, want 1", got)
	}
	if got := reconcileAndCount(worker, cgroupIDsForPIDs(t, worker, b)); got != 1 {
		t.Fatalf("target closed while still mapped by b: count = %d, want 1", got)
	}
	if got := reconcileAndCount(worker, nil); got != 1 {
		t.Fatalf("closed after a miss following reappearance: count = %d, want 1", got)
	}
	if got := reconcileAndCount(worker, nil); got != 0 {
		t.Fatalf("target count after second complete miss = %d, want 0", got)
	}
	if discoveryCacheContains(t, worker, target.classificationKey) {
		t.Fatal("reclaimed target remained in the BPF discovery cache")
	}
}

// TestLinuxHTTPUprobeReclaimIncompleteIsFailKeep verifies that an incomplete
// scan neither closes a target nor advances its missing count.
func TestLinuxHTTPUprobeReclaimIncompleteIsFailKeep(t *testing.T) {
	worker := newReclaimTestWorker(t)
	a := startLibsslMapper(t)
	if got := discoverAndCount(t, worker, a); got != 1 {
		t.Fatalf("target count after attach = %d, want 1", got)
	}
	reconcileAndCount(worker, cgroupIDsForPIDs(t, worker, a))

	reconcileAndCount(worker, nil)
	if got := reconcileAndCount(worker, unreadableCgroupIDs(t, worker)); got != 1 {
		t.Fatalf("incomplete scan closed a target: count = %d, want 1", got)
	}
	if got := reconcileAndCount(worker, nil); got != 0 {
		t.Fatalf("target count after second complete miss = %d, want 0", got)
	}
}

// TestLinuxHTTPUprobeReclaimUnlinkedButMappedKept verifies that reclaim uses
// maps-liveness rather than pathname existence.
func TestLinuxHTTPUprobeReclaimUnlinkedButMappedKept(t *testing.T) {
	worker := newReclaimTestWorker(t)
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

	if got := discoverAndCount(t, worker, pid); got != 1 {
		t.Fatalf("target count after copied libssl attach = %d, want 1", got)
	}
	reconcileAndCount(worker, cgroupIDsForPIDs(t, worker, pid))
	if err := os.Remove(dst); err != nil {
		t.Fatal(err)
	}
	reconcileAndCount(worker, cgroupIDsForPIDs(t, worker, pid))
	if got := reconcileAndCount(worker, cgroupIDsForPIDs(t, worker, pid)); got != 1 {
		t.Fatalf("unlinked-but-mapped inode was detached: count = %d, want 1", got)
	}
}

func TestLinuxHTTPUprobeOpenMappedFileFallsBackToCurrentRange(t *testing.T) {
	worker := newReclaimTestWorker(t)
	mappings, complete := worker.scanProcessMappings(int32(os.Getpid()))
	if !complete || len(mappings) == 0 {
		t.Fatalf("own executable mappings = %d complete = %v", len(mappings), complete)
	}

	candidate := mappings[0]
	f, err := os.Open(fmt.Sprintf("/proc/%d/map_files/%s", os.Getpid(), candidate.addressRange))
	if err != nil {
		t.Fatalf("open current map_files entry: %v", err)
	}
	key, err := classificationKeyFromFile(f)
	_ = f.Close()
	if err != nil {
		t.Fatalf("classify current map_files entry: %v", err)
	}

	opened, err := worker.openMappedFile(httpUprobeAttachCandidate{
		process: httpUprobeProcessGeneration{TGID: int32(os.Getpid())}, vmStart: 1, vmEnd: 2, file: key,
	})
	if err != nil {
		t.Fatalf("openMappedFile stale-range fallback: %v", err)
	}
	defer opened.Close()
	got, err := classificationKeyFromFile(opened)
	if err != nil {
		t.Fatalf("classify fallback result: %v", err)
	}
	if got != key {
		t.Fatalf("fallback identity = %+v, want %+v", got, key)
	}
}

func TestLinuxHTTPUprobeDiscoveryCacheUsesBPFMap(t *testing.T) {
	worker := newReclaimTestWorker(t)
	key := fileClassificationKey{
		mappedFile: mappedFileIdentity{deviceMajor: 8, deviceMinor: 1, inode: 42},
		ctimeSec:   123, ctimeNsec: 456,
	}
	if discoveryCacheContains(t, worker, key) {
		t.Fatal("fresh key is already in discovery cache")
	}
	worker.cacheDiscoveryFile(key)
	if !discoveryCacheContains(t, worker, key) {
		t.Fatal("cached key was not found in discovery cache")
	}
}

func TestLinuxHTTPUprobeQueueManagesDiscoveryCache(t *testing.T) {
	for _, test := range []struct {
		name      string
		fillQueue bool
		wantKey   bool
	}{
		{name: "queued classification remains deduplicated", wantKey: true},
		{name: "dropped classification allows another process retry", fillQueue: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			worker := newReclaimTestWorker(t)
			worker.attachCandidates = make(chan httpUprobeAttachCandidate, 1)
			if test.fillQueue {
				worker.attachCandidates <- httpUprobeAttachCandidate{}
			}
			candidate := httpUprobeAttachCandidate{file: fileClassificationKey{
				mappedFile: mappedFileIdentity{deviceMajor: 8, deviceMinor: 1, inode: 42},
				ctimeSec:   123,
				ctimeNsec:  456,
			}}
			if err := worker.discoveryCache.Put(candidate.file, uint8(1)); err != nil {
				t.Fatalf("record discovery file: %v", err)
			}
			worker.queueAttachCandidate(candidate)
			if got := discoveryCacheContains(t, worker, candidate.file); got != test.wantKey {
				t.Fatalf("discovery-cache key exists = %v, want %v", got, test.wantKey)
			}
		})
	}
}

func discoveryCacheContains(t *testing.T, worker *httpUprobeWorker, key fileClassificationKey) bool {
	t.Helper()
	var value uint8
	err := worker.discoveryCache.Lookup(key, &value)
	if err == nil {
		return true
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return false
	}
	t.Fatalf("lookup discovery cache: %v", err)
	return false
}

func TestLinuxHTTPUprobeIdentityMismatchIsRetryable(t *testing.T) {
	worker := newReclaimTestWorker(t)
	mappings, complete := worker.scanProcessMappings(int32(os.Getpid()))
	if !complete || len(mappings) == 0 {
		t.Fatalf("own executable mappings = %d complete = %v", len(mappings), complete)
	}

	mapping := mappings[0]
	startText, endText, ok := strings.Cut(mapping.addressRange, "-")
	if !ok {
		t.Fatalf("invalid mapping range %q", mapping.addressRange)
	}
	start, startErr := strconv.ParseUint(startText, 16, 64)
	end, endErr := strconv.ParseUint(endText, 16, 64)
	if startErr != nil || endErr != nil {
		t.Fatalf("parse mapping range %q: %v, %v", mapping.addressRange, startErr, endErr)
	}
	f, err := os.Open(mappedFilePath(int32(os.Getpid()), start, end))
	if err != nil {
		t.Fatalf("open current map_files entry: %v", err)
	}
	key, err := classificationKeyFromFile(f)
	_ = f.Close()
	if err != nil {
		t.Fatalf("classify current map_files entry: %v", err)
	}
	key.ctimeNsec++
	if err := worker.discoveryCache.Put(key, uint8(1)); err != nil {
		t.Fatalf("record discovery file: %v", err)
	}

	attachCandidate := httpUprobeAttachCandidate{
		process: httpUprobeProcessGeneration{TGID: int32(os.Getpid())}, vmStart: start, vmEnd: end, file: key,
	}
	worker.queueAttachCandidate(attachCandidate)
	worker.classifyAndAttach(<-worker.attachCandidates)
	if worker.identityMismatch != 1 {
		t.Fatalf("identity mismatch count = %d, want 1", worker.identityMismatch)
	}
	if len(worker.attachedTargets) != 0 {
		t.Fatalf("identity mismatch attached %d targets, want 0", len(worker.attachedTargets))
	}
	if discoveryCacheContains(t, worker, key) {
		t.Fatal("identity mismatch remained in the BPF discovery cache")
	}
}
