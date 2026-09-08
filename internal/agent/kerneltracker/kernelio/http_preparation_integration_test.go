//go:build linux && bpf_integration

package kernelio

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func copyPreparationFixture(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mountPreparationOverlay(t *testing.T, lower string) string {
	t.Helper()
	base := t.TempDir()
	for _, name := range []string{"upper", "work", "merged"} {
		if err := os.Mkdir(filepath.Join(base, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	merged := filepath.Join(base, "merged")
	options := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, filepath.Join(base, "upper"), filepath.Join(base, "work"))
	if err := unix.Mount("overlay", merged, "overlay", 0, options); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(merged, 0); err != nil {
			t.Errorf("unmount test overlay: %v", err)
		}
	})
	return merged
}

func TestHTTPPreparationBackingAndDedup(t *testing.T) {
	w := newReclaimTestWorker(t)
	if w.control == nil {
		t.Fatal("optional backing control unavailable on validation kernel")
	}
	f, err := os.Open(findLibssl(t))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	data, key, err := w.control.mapFile(f, int(info.Size()))
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Munmap(data)
	for i := range 2 {
		ok, err := w.prepareFile(t.Context(), f, nil, false)
		if err != nil || !ok {
			t.Fatalf("prepare %d: %v %v", i, ok, err)
		}
	}
	if len(w.attachedTargets) != 1 {
		t.Fatalf("duplicate registry: %d", len(w.attachedTargets))
	}
	entry := w.attachedTargets[key.mappedFile]
	if entry == nil || len(entry.links) == 0 {
		t.Fatal("no verified links for backing")
	}
	// An arriving mapping must hit the same registry without needing a valid PID.
	w.classifyAndAttach(httpUprobeAttachCandidate{file: key, tgid: -1})
	if len(w.attachedTargets) != 1 || w.attachedTargets[key.mappedFile] != entry {
		t.Fatal("mapping failed to deduplicate")
	}
	var cached uint8
	if err := w.discoveryCache.Lookup(key, &cached); err != nil {
		t.Fatal(err)
	}
	pid := startLibsslMapper(t)
	mappings, complete := w.scanProcessMappings(pid)
	if !complete {
		t.Fatal("backing maps scan incomplete")
	}
	found := false
	for _, m := range mappings {
		if m.mappedFile == key.mappedFile {
			found = true
		}
	}
	if !found {
		t.Fatal("original VMA backing missing")
	}
}

func TestHTTPPreparationOverlayOriginalVMA(t *testing.T) {
	lower := t.TempDir()
	copyPreparationFixture(t, findLibssl(t), filepath.Join(lower, "libssl.so.3"))
	roots := []string{mountPreparationOverlay(t, lower), mountPreparationOverlay(t, lower)}
	w := newReclaimTestWorker(t)
	if w.control == nil {
		t.Fatal("backing control unavailable")
	}
	prepare := func(root string) fileClassificationKey {
		t.Helper()
		f, err := os.Open(filepath.Join(root, "libssl.so.3"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		info, _ := f.Stat()
		data, key, err := w.control.mapFile(f, int(info.Size()))
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Munmap(data)
		if ok, err := w.prepareFile(t.Context(), f, nil, false); err != nil || !ok {
			t.Fatalf("prepare: %v %v", ok, err)
		}
		return key
	}
	old := prepare(roots[0])
	shared := prepare(roots[1])
	if old != shared || len(w.attachedTargets) != 1 {
		t.Fatal("shared lower attached twice")
	}
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(requireTestBinary(t, "python3"), "-c", "import ctypes,pathlib,sys,time; h=ctypes.CDLL(sys.argv[1]); pathlib.Path(sys.argv[2]).touch(); time.sleep(60)", filepath.Join(roots[0], "libssl.so.3"), ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mapper not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Opening for write forces a data copy-up even though contents stay identical.
	f, err := os.OpenFile(filepath.Join(roots[0], "libssl.so.3"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	newKey := prepare(roots[0])
	if newKey.mappedFile == old.mappedFile {
		t.Fatal("copy-up failed to create another backing")
	}
	if len(w.attachedTargets) != 2 {
		t.Fatal("copy-up target not independently attached")
	}
	if err := os.Remove(filepath.Join(roots[0], "libssl.so.3")); err != nil {
		t.Fatal(err)
	}
	mappings, complete := w.scanProcessMappings(int32(cmd.Process.Pid))
	if !complete {
		t.Fatal("original VMA scan incomplete")
	}
	found := false
	for _, m := range mappings {
		if m.mappedFile == old.mappedFile {
			found = true
		}
	}
	if !found {
		t.Fatal("copy-up/unlink hid the original lower VMA")
	}
	for _, a := range w.attachedTargets {
		a.protectedUntil = time.Time{}
	}
	ids := cgroupIDsForPIDs(t, w, int32(cmd.Process.Pid))
	w.reconcileTargets(t.Context(), ids)
	w.reconcileTargets(t.Context(), ids)
	if w.attachedTargets[old.mappedFile] == nil || w.attachedTargets[newKey.mappedFile] != nil {
		t.Fatal("reclaim confused original lower and copied-up upper")
	}
}

// The path is a disposable dind threaded cgroup, supplied by the live harness.
func TestDindThreadedReclaimPIDs(t *testing.T) {
	path := os.Getenv("CICD_DIND_THREADED_CGROUP")
	if path == "" {
		t.Skip("set CICD_DIND_THREADED_CGROUP for live dind")
	}
	w := newHTTPUprobeWorker(nil, nil, "/sys/fs/cgroup", nil, goUprobeTarget{})
	pids := make(map[int32]struct{})
	if !w.collectCgroupPIDs(path, pids) {
		t.Fatal("threaded subtree left reclaim incomplete")
	}
	if len(pids) == 0 {
		t.Fatal("live dind domain returned no PIDs")
	}
	t.Logf("collected %d live process IDs", len(pids))
}
