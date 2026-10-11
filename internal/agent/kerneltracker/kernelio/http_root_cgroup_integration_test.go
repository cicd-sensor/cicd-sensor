//go:build linux && bpf_integration

package kernelio

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func rootCgroup(t *testing.T) (*os.File, uint64) {
	t.Helper()
	path, err := os.MkdirTemp("/sys/fs/cgroup", "cicd-http-root-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error(err)
		}
	})
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	return f, st.Ino
}

func TestHTTPRootCgroupSharedOverlayLifecycle(t *testing.T) {
	lower := t.TempDir()
	source := filepath.Join(lower, "fixture.c")
	if err := os.WriteFile(source, []byte(`#include <stdlib.h>
#include <unistd.h>
__attribute__((noinline)) int SSL_write(void *ssl,const void *buf,int n){asm volatile("" : : "r"(buf) : "memory"); return n;}
int main(int argc, char **argv) {
    // Initialize writable memory: a cold string-literal page may not be readable
    // by bpf_probe_read_user, which cannot fault it in on the process's behalf.
    char request[] = "GET /root-cgroup HTTP/1.1\r\nHost: example.test\r\n\r\n";
    for (int i = 0; i < atoi(argv[1]); i++)
        SSL_write(0, request, sizeof(request) - 1);
    return 0;
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(lower, "client")
	if out, err := exec.Command(requireTestBinary(t, "cc"), "-O0", "-g", "-o", binaryPath, source).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v %s", err, out)
	}
	roots := []string{mountPreparationOverlay(t, lower), mountPreparationOverlay(t, lower)}
	w := newReclaimTestWorker(t)
	ki := w.tracking.(*LinuxKernelIO)
	a, aid := rootCgroup(t)
	b, bid := rootCgroup(t)
	for _, id := range []uint64{aid, bid} {
		if err := ki.PutCgroupIDInTrackedCgroupsMap(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	ao, bo := ki.httpRootCgroup(aid), ki.httpRootCgroup(bid)
	if ao != aid || bo != bid || ao == bo {
		t.Fatal("root IDs do not match their cgroups")
	}
	prepare := func(t *testing.T, root string, id, rootCgroupID uint64) fileClassificationKey {
		t.Helper()
		f, err := os.Open(filepath.Join(root, "client"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		data, key, err := w.mapFile(f)
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Munmap(data)
		if ok, err := w.prepareFile(t.Context(), f, nil, id, rootCgroupID); err != nil || !ok {
			t.Fatalf("prepare: %v %v", ok, err)
		}
		return key
	}
	ak := prepare(t, roots[0], aid, ao)
	bk := prepare(t, roots[1], bid, bo)
	if ak != bk {
		t.Fatal("overlay roots did not share backing")
	}
	prepare(t, roots[0], aid, ao)
	if len(w.attachedTargets) != 2 {
		t.Fatalf("same-root duplicate: %d", len(w.attachedTargets))
	}
	w.classifyAndAttach(httpUprobeAttachCandidate{cgroupID: aid, rootCgroupID: ao, file: ak, tgid: -1})
	if len(w.attachedTargets) != 2 {
		t.Fatal("mapping duplicated prepared target")
	}
	run := func(t *testing.T, root string, cgroup *os.File, n, want int) {
		t.Helper()
		cmd := exec.Command(filepath.Join(root, "client"), fmt.Sprint(n))
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		count := 0
		ki.reader.SetDeadline(time.Now().Add(100 * time.Millisecond))
		for {
			record, err := ki.reader.Read()
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(record.RawSample) < 4 || binary.LittleEndian.Uint32(record.RawSample[:4]) != SampleKindHTTPRequest {
				continue
			}
			var sample bpfprog.BPFProgramHttpRequestSample
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &sample); err != nil {
				t.Fatal(err)
			}
			if sample.Tgid == int32(cmd.Process.Pid) {
				count++
			}
		}
		if count != want {
			t.Fatalf("HTTP events=%d want=%d", count, want)
		}
	}
	t.Run("each root receives every real call exactly once", func(t *testing.T) { run(t, roots[0], a, 20, 20); run(t, roots[1], b, 20, 20) })
	// Copy-up gets a new backing and therefore a separate target in the same root.
	t.Run("copy up leaves other container on lower", func(t *testing.T) {
		if err := os.Chmod(filepath.Join(roots[0], "client"), 0o700); err != nil {
			t.Fatal(err)
		}
		upper := prepare(t, roots[0], aid, ao)
		if upper.mappedFile == ak.mappedFile {
			t.Fatal("copy-up did not change backing")
		}
		run(t, roots[0], a, 20, 20)
		run(t, roots[1], b, 20, 20)
	})
	t.Run("ending A closes only A and clears its positive cache", func(t *testing.T) {
		destination, _ := rootCgroup(t)
		sleeper := exec.Command(requireTestBinary(t, "sleep"), "60")
		sleeper.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(a.Fd())}
		if err := sleeper.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() }()
		if err := os.WriteFile(filepath.Join(destination.Name(), "cgroup.procs"), []byte(fmt.Sprint(sleeper.Process.Pid)), 0o600); err != nil {
			t.Fatal(err)
		}
		run(t, roots[0], destination, 20, 20)
		if err := ki.DeleteCgroupIDsFromTrackedCgroupsMap(t.Context(), []uint64{aid}); err != nil {
			t.Fatal(err)
		}
		// Keep the real links installed: the BPF root gate must already stop
		// captures, even though the destination still stores A's root ID.
		run(t, roots[0], destination, 20, 0)
		w.reconcileTargets(t.Context())
		if len(w.attachedTargets) != 1 {
			t.Fatalf("targets=%d", len(w.attachedTargets))
		}
		var cached uint8
		if err := w.discoveryCache.Lookup(httpDiscoveryKey{ao, ak}, &cached); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("ended root retained positive cache entry: %v", err)
		}
		run(t, roots[1], b, 20, 20)
		if _, err := w.prepareFile(t.Context(), nil, nil, aid, ao); !errors.Is(err, errHTTPTrackingEnded) {
			t.Fatal("late root accepted")
		}
	})

	if err := ki.DeleteCgroupIDsFromTrackedCgroupsMap(t.Context(), []uint64{aid, bid}); err != nil {
		t.Fatal(err)
	}
	w.reconcileTargets(t.Context())
	if len(w.attachedTargets) != 0 {
		t.Fatal("last root leaked links")
	}
}

func TestHTTPRootCgroupInheritance(t *testing.T) {
	w := newReclaimTestWorker(t)
	ki := w.tracking.(*LinuxKernelIO)
	parent, pid := rootCgroup(t)
	if err := ki.PutCgroupIDInTrackedCgroupsMap(t.Context(), pid); err != nil {
		t.Fatal(err)
	}
	rootCgroupID := ki.httpRootCgroup(pid)
	childPath := filepath.Join(parent.Name(), "child")
	if err := os.Mkdir(childPath, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(childPath) })
	var st unix.Stat_t
	if err := unix.Stat(childPath, &st); err != nil {
		t.Fatal(err)
	}
	if ki.httpRootCgroup(st.Ino) != rootCgroupID {
		t.Fatal("child did not inherit before userspace notification")
	}
	if err := ki.PutCgroupIDInTrackedCgroupsMap(t.Context(), st.Ino); err != nil {
		t.Fatal(err)
	}
	if ki.httpRootCgroup(st.Ino) != rootCgroupID {
		t.Fatal("userspace mirror replaced inherited root")
	}
	key := httpTargetKey{rootCgroupID: rootCgroupID, file: mappedFileIdentity{inode: 42}}
	w.attachedTargets[key] = &attachedUprobeTarget{}
	if err := os.Remove(childPath); err != nil {
		t.Fatal(err)
	}
	if ki.httpRootCgroup(st.Ino) != 0 {
		t.Fatal("rmdir did not end child before sample intake")
	}
	w.reconcileTargets(t.Context())
	if len(w.attachedTargets) != 1 {
		t.Fatal("child removal closed parent target")
	}
	if err := os.Remove(parent.Name()); err != nil {
		t.Fatal(err)
	}
	w.reconcileTargets(t.Context())
	if len(w.attachedTargets) != 0 {
		t.Fatal("last removed member retained target")
	}
}

func TestHTTPDiscoveryRootCache(t *testing.T) {
	w := newReclaimTestWorker(t)
	ki := w.tracking.(*LinuxKernelIO)
	_, aid := rootCgroup(t)
	_, bid := rootCgroup(t)
	for _, id := range []uint64{aid, bid} {
		if err := ki.PutCgroupIDInTrackedCgroupsMap(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	file := fileClassificationKey{mappedFile: mappedFileIdentity{inode: 42}}
	a := httpDiscoveryKey{ki.httpRootCgroup(aid), file}
	b := httpDiscoveryKey{ki.httpRootCgroup(bid), file}
	for _, key := range []httpDiscoveryKey{a, b} {
		if err := w.discoveryCache.Put(key, httpDiscoveryNegative); err != nil {
			t.Fatal(err)
		}
	}
	for range cap(w.attachCandidates) {
		w.attachCandidates <- httpUprobeAttachCandidate{}
	}
	w.queueAttachCandidate(httpUprobeAttachCandidate{cgroupID: aid, rootCgroupID: a.rootCgroupID, file: file})
	var value uint8
	if err := w.discoveryCache.Lookup(a, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatal("dropped candidate retained its cache")
	}
	if err := w.discoveryCache.Lookup(b, &value); err != nil || value != httpDiscoveryNegative {
		t.Fatal("A drop affected B cache")
	}
	for len(w.attachCandidates) > 0 {
		<-w.attachCandidates
	}
	if err := ki.DeleteCgroupIDsFromTrackedCgroupsMap(t.Context(), []uint64{bid}); err != nil {
		t.Fatal(err)
	}
	w.reconcileTargets(t.Context())
	if err := w.discoveryCache.Lookup(b, &value); err != nil || value != httpDiscoveryNegative {
		t.Fatal("reclaim removed the bounded negative cache entry")
	}

}

func TestHTTPRootCgroupMigrationEndsWithRoot(t *testing.T) {
	w := newReclaimTestWorker(t)
	ki := w.tracking.(*LinuxKernelIO)
	source, sid := rootCgroup(t)
	destination, did := rootCgroup(t)
	if err := ki.PutCgroupIDInTrackedCgroupsMap(t.Context(), sid); err != nil {
		t.Fatal(err)
	}
	rootCgroupID := ki.httpRootCgroup(sid)
	cmd := exec.Command(requireTestBinary(t, "sleep"), "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(source.Fd())}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if err := os.WriteFile(filepath.Join(destination.Name(), "cgroup.procs"), []byte(fmt.Sprint(cmd.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	if ki.httpRootCgroup(did) != rootCgroupID {
		t.Fatal("migration did not inherit source root")
	}
	key := httpTargetKey{rootCgroupID: rootCgroupID, file: mappedFileIdentity{inode: 42}}
	w.attachedTargets[key] = &attachedUprobeTarget{}
	if err := os.Remove(source.Name()); err != nil {
		t.Fatal(err)
	}
	w.reconcileTargets(t.Context())
	if len(w.attachedTargets) != 0 {
		t.Fatal("migration destination retained ended root links")
	}
	if w.rootActive(did, rootCgroupID) {
		t.Fatal("destination extended root lifetime")
	}
	if _, err := w.prepareFile(t.Context(), nil, nil, did, rootCgroupID); !errors.Is(err, errHTTPTrackingEnded) {
		t.Fatalf("late destination preparation: %v", err)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if err := os.Remove(destination.Name()); err != nil {
		t.Fatal(err)
	}
	w.reconcileTargets(t.Context())
	if len(w.attachedTargets) != 0 {
		t.Fatal("last migration destination retained links")
	}
}

// End the real tracking entry at prepareFile's final check, after real attach.
// This forces the rollback window without sleeps or production test hooks.
type endAtCommitTracking struct {
	*LinuxKernelIO
	t      *testing.T
	checks int
}

func (s *endAtCommitTracking) httpRootCgroup(id uint64) uint64 {
	s.checks++
	if s.checks == 2 {
		if err := s.DeleteCgroupIDsFromTrackedCgroupsMap(s.t.Context(), []uint64{id}); err != nil {
			s.t.Fatal(err)
		}
	}
	return s.LinuxKernelIO.httpRootCgroup(id)
}

func TestHTTPRootCgroupEndDuringPreparationRollsBack(t *testing.T) {
	w := newReclaimTestWorker(t)
	ki := w.tracking.(*LinuxKernelIO)
	_, id := rootCgroup(t)
	if err := ki.PutCgroupIDInTrackedCgroupsMap(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	rootCgroupID := ki.httpRootCgroup(id)
	f, err := os.Open(findLibssl(t))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, key, err := w.mapFile(f)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Munmap(data)
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	w.tracking = &endAtCommitTracking{LinuxKernelIO: ki, t: t}
	if ok, err := w.prepareFile(t.Context(), f, nil, id, rootCgroupID); ok || !errors.Is(err, errHTTPTrackingEnded) {
		t.Fatalf("prepare=%v err=%v", ok, err)
	}
	if len(w.attachedTargets) != 0 {
		t.Fatal("ended root published a target")
	}
	var value uint8
	if err := w.discoveryCache.Lookup(httpDiscoveryKey{rootCgroupID, key}, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatal("ended root published a cache result")
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatalf("rollback leaked descriptors: before=%d after=%d", len(before), len(after))
	}
}

func TestHTTPRootCgroupRecreatedPath(t *testing.T) {
	w := newReclaimTestWorker(t)
	ki := w.tracking.(*LinuxKernelIO)
	first, firstID := rootCgroup(t)
	if err := ki.PutCgroupIDInTrackedCgroupsMap(t.Context(), firstID); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(first.Name()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(first.Name(), 0o755); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(first.Name(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Ino == firstID {
		t.Fatal("recreated cgroup reused the old ID")
	}
	if err := ki.PutCgroupIDInTrackedCgroupsMap(t.Context(), st.Ino); err != nil {
		t.Fatal(err)
	}
	if w.rootActive(firstID, firstID) || !w.rootActive(st.Ino, st.Ino) {
		t.Fatal("old and recreated roots were confused")
	}
	w.classifyAndAttach(httpUprobeAttachCandidate{cgroupID: firstID, rootCgroupID: firstID, tgid: -1})
	if len(w.attachedTargets) != 0 {
		t.Fatal("old notification reactivated a target")
	}
}
