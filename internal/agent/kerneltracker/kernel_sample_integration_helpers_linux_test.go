//go:build linux && integration

package kerneltracker

import (
	"bytes"
	"context"
	"fmt"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireBinary(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("LookPath %q: %v (install required for this test)", name, err)
	}
	return path
}

// startTrackedKernelIO boots a LinuxKernelIO, starts the kernel event
// loop into a fresh KernelTracker, and registers the test process's
// cgroup as tracked. Cleanup unregisters the cgroup and closes the
// kernelIO. Lets the dig / resolvectl tests stay focused on the
// command they exercise.
func startTrackedKernelIO(t *testing.T) (uint64, *KernelTracker, func()) {
	t.Helper()
	kernelIO, cgroupRoot := newLinuxKernelIO(t)

	ctx, cancel := context.WithCancel(context.Background())

	kernelTracker := newTestKernelTracker(nil, nil, noopKernelIO{}, cgroupRoot)
	engine := kernelTracker
	if err := kernelIO.StartKernelSampleLoop(ctx, engine.enqueueKernelSample); err != nil {
		kernelIO.Close()
		cancel()
		t.Fatalf("StartKernelSampleLoop: %v", err)
	}

	cgroupID, err := lookupProcessCgroupID(int32(os.Getpid()), cgroupRoot)
	if err != nil {
		cancel()
		kernelIO.Close()
		t.Fatalf("lookupProcessCgroupID: %v", err)
	}
	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, cgroupID); err != nil {
		cancel()
		kernelIO.Close()
		t.Fatalf("put tracked cgroup: %v", err)
	}

	cleanup := func() {
		_ = kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), []uint64{cgroupID})
		cancel()
		kernelIO.Close()
	}
	return cgroupID, kernelTracker, cleanup
}

func newLinuxKernelIO(t *testing.T) (*kernelio.LinuxKernelIO, string) {
	t.Helper()
	cgroupRoot, err := getCgroupV2Root()
	if err != nil {
		t.Fatalf("getCgroupV2Root: %v", err)
	}
	kernelIO, err := kernelio.NewLinux(nil, kernelio.Config{
		CgroupV2RootPath: cgroupRoot,
	})
	if err != nil {
		t.Fatalf("kernelio.NewLinux: %v", err)
	}
	return kernelIO, cgroupRoot
}

func startKernelSampleLoop(t *testing.T, ctx context.Context, kernelIO *kernelio.LinuxKernelIO, engine *KernelTracker) {
	t.Helper()
	if err := kernelIO.StartKernelSampleLoop(ctx, engine.enqueueKernelSample); err != nil {
		t.Fatalf("StartKernelSampleLoop: %v", err)
	}
}

func waitForEngineInput(t *testing.T, inputCh <-chan engineInput, timeout time.Duration, name string, match func(engineInput) bool) engineInput {
	t.Helper()

	if message, ok := findEngineInput(inputCh, timeout, match); ok {
		return message
	}
	t.Fatalf("timed out waiting for %s event", name)
	return nil
}

func findEngineInput(inputCh <-chan engineInput, timeout time.Duration, match func(engineInput) bool) (engineInput, bool) {
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			return nil, false
		case message := <-inputCh:
			if match(message) {
				return message, true
			}
		}
	}
}

func requireTrackedCgroupEntry(t *testing.T, ctx context.Context, kernelIO *kernelio.LinuxKernelIO, cgroupID uint64, name string) {
	t.Helper()
	ok, err := kernelIO.TestOnlyLookupCgroupIDInTrackedCgroupsMap(ctx, cgroupID)
	if err != nil {
		t.Fatalf("lookup %s cgroup in tracked_cgroups: %v", name, err)
	}
	if !ok {
		t.Fatalf("%s cgroup was not present in tracked_cgroups", name)
	}
}

func requireAndDeleteTrackedCgroupEntry(t *testing.T, ctx context.Context, kernelIO *kernelio.LinuxKernelIO, cgroupID uint64, name string) {
	t.Helper()
	requireTrackedCgroupEntry(t, ctx, kernelIO, cgroupID, name)
	if err := kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(ctx, []uint64{cgroupID}); err != nil {
		t.Fatalf("delete %s cgroup from tracked_cgroups: %v", name, err)
	}
}

func waitForEventRecord(t *testing.T, eventCh <-chan jobevent.EventRecord, timeout time.Duration, name string, match func(jobevent.EventRecord) bool) jobevent.EventRecord {
	t.Helper()

	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %s event record", name)
		case record := <-eventCh:
			if match(record) {
				return record
			}
		}
	}
}

func assertNoEventRecord(t *testing.T, eventCh <-chan jobevent.EventRecord, timeout time.Duration, match func(jobevent.EventRecord) bool) {
	t.Helper()

	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			return
		case record := <-eventCh:
			if match(record) {
				t.Fatalf("unexpected event record: %#v", record)
			}
		}
	}
}

func currentCgroupPath(pid int32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", fmt.Errorf("read /proc/%d/cgroup: %w", pid, err)
	}

	for len(data) > 0 {
		var line []byte
		line, data, _ = bytes.Cut(data, []byte{'\n'})
		if cgroupPath, ok := bytes.CutPrefix(line, []byte("0::")); ok {
			return string(cgroupPath), nil
		}
	}

	return "", fmt.Errorf("no cgroup v2 entry for pid %d", pid)
}

func cgroupIDForPath(cgroupRoot string, path string) (uint64, error) {
	fullPath, err := cgroupFSPath(cgroupRoot, path)
	if err != nil {
		return 0, err
	}
	var stat unix.Stat_t
	if err := unix.Stat(fullPath, &stat); err != nil {
		return 0, fmt.Errorf("stat %q: %w", fullPath, err)
	}
	return stat.Ino, nil
}

func mustCgroupFSPath(t *testing.T, cgroupRoot string, parts ...string) string {
	t.Helper()
	fullPath, err := cgroupFSPath(cgroupRoot, parts...)
	if err != nil {
		t.Fatalf("cgroup fs path: %v", err)
	}
	return fullPath
}

func cgroupFSPath(cgroupRoot string, parts ...string) (string, error) {
	pathParts := []string{cgroupRoot}
	for _, part := range parts {
		pathParts = append(pathParts, strings.TrimPrefix(part, "/"))
	}
	return filepath.Join(pathParts...), nil
}
