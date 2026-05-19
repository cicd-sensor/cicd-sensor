//go:build linux && integration

package kernelio

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cilium/ebpf"
	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

func TestLinuxKernelIOLoadAndClose(t *testing.T) {
	kernelIO, err := NewLinux(nil, testLinuxConfig(t))
	if err != nil {
		t.Fatalf("NewLinux: %v", err)
	}
	if kernelIO.objs.Events == nil {
		t.Fatalf("events ringbuf map is nil")
	}
	if kernelIO.objs.TrackedCgroups == nil {
		t.Fatalf("tracked_cgroups map is nil")
	}
	if kernelIO.objs.StagingMap == nil {
		t.Fatalf("staging_map is nil")
	}
	if kernelIO.reader == nil {
		t.Fatalf("ringbuf reader is nil")
	}
	if len(kernelIO.links) == 0 {
		t.Fatalf("expected attached BPF links")
	}
	if err := kernelIO.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestLinuxKernelIOTrackedCgroupsMapOperations(t *testing.T) {
	kernelIO, err := NewLinux(nil, testLinuxConfig(t))
	if err != nil {
		t.Fatalf("NewLinux: %v", err)
	}
	defer kernelIO.Close()

	ctx := context.Background()
	const cgroupID = uint64(0x123456789)

	if err := kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, cgroupID); err != nil {
		t.Fatalf("PutCgroupIDInTrackedCgroupsMap: %v", err)
	}
	found, err := kernelIO.TestOnlyLookupCgroupIDInTrackedCgroupsMap(ctx, cgroupID)
	if err != nil {
		t.Fatalf("TestOnlyLookupCgroupIDInTrackedCgroupsMap: %v", err)
	}
	if !found {
		t.Fatalf("tracked cgroup lookup after put: got false, want true")
	}
	var got uint8
	if err := kernelIO.objs.TrackedCgroups.Lookup(cgroupID, &got); err != nil {
		t.Fatalf("lookup tracked cgroup: %v", err)
	}
	if got != 1 {
		t.Fatalf("tracked cgroup value: got %d, want 1", got)
	}

	if err := kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(ctx, []uint64{cgroupID}); err != nil {
		t.Fatalf("DeleteCgroupIDsFromTrackedCgroupsMap: %v", err)
	}
	found, err = kernelIO.TestOnlyLookupCgroupIDInTrackedCgroupsMap(ctx, cgroupID)
	if err != nil {
		t.Fatalf("TestOnlyLookupCgroupIDInTrackedCgroupsMap after delete: %v", err)
	}
	if found {
		t.Fatalf("tracked cgroup lookup after delete: got true, want false")
	}
	if err := kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(ctx, []uint64{cgroupID}); err != nil {
		t.Fatalf("DeleteCgroupIDsFromTrackedCgroupsMap missing key: %v", err)
	}
	if err := kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(ctx, nil); err != nil {
		t.Fatalf("DeleteCgroupIDsFromTrackedCgroupsMap empty input: %v", err)
	}
	if err := kernelIO.objs.TrackedCgroups.Lookup(cgroupID, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("lookup deleted tracked cgroup: got %v, want ErrKeyNotExist", err)
	}
}

func TestLinuxKernelIOStagingMapOperations(t *testing.T) {
	kernelIO, err := NewLinux(nil, testLinuxConfig(t))
	if err != nil {
		t.Fatalf("NewLinux: %v", err)
	}
	defer kernelIO.Close()

	ctx := context.Background()
	basename := "docker-integration.scope"
	fixedKey, err := fixedStagingMapKey([]byte(basename))
	if err != nil {
		t.Fatalf("fixedStagingMapKey: %v", err)
	}

	if err := kernelIO.PutCgroupBasenameInStagingMap(ctx, basename); err != nil {
		t.Fatalf("PutCgroupBasenameInStagingMap: %v", err)
	}
	found, err := kernelIO.TestOnlyLookupCgroupBasenameInStagingMap(ctx, basename)
	if err != nil {
		t.Fatalf("TestOnlyLookupCgroupBasenameInStagingMap: %v", err)
	}
	if !found {
		t.Fatalf("staging lookup after put: got false, want true")
	}
	var got bpfprog.BPFProgramStagingValue
	if err := kernelIO.objs.StagingMap.Lookup(fixedKey, &got); err != nil {
		t.Fatalf("lookup staging entry: %v", err)
	}
	if got.JobIdLo != 0 || got.JobIdHi != 0 {
		t.Fatalf("staging value: got %+v, want zero value", got)
	}

	if err := kernelIO.DeleteCgroupBasenamesFromStagingMap(ctx, []string{basename}); err != nil {
		t.Fatalf("DeleteCgroupBasenamesFromStagingMap: %v", err)
	}
	found, err = kernelIO.TestOnlyLookupCgroupBasenameInStagingMap(ctx, basename)
	if err != nil {
		t.Fatalf("TestOnlyLookupCgroupBasenameInStagingMap after delete: %v", err)
	}
	if found {
		t.Fatalf("staging lookup after delete: got true, want false")
	}
	if err := kernelIO.DeleteCgroupBasenamesFromStagingMap(ctx, []string{basename}); err != nil {
		t.Fatalf("DeleteCgroupBasenamesFromStagingMap missing key: %v", err)
	}
	if err := kernelIO.DeleteCgroupBasenamesFromStagingMap(ctx, nil); err != nil {
		t.Fatalf("DeleteCgroupBasenamesFromStagingMap empty input: %v", err)
	}
	if err := kernelIO.objs.StagingMap.Lookup(fixedKey, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("lookup deleted staging entry: got %v, want ErrKeyNotExist", err)
	}
}

func TestLinuxKernelIOStartLoopAndClose(t *testing.T) {
	kernelIO, err := NewLinux(nil, testLinuxConfig(t))
	if err != nil {
		t.Fatalf("NewLinux: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := kernelIO.StartKernelSampleLoop(ctx, func(context.Context, KernelSample) error {
		return nil
	}); err != nil {
		_ = kernelIO.Close()
		t.Fatalf("StartKernelSampleLoop: %v", err)
	}
	if err := kernelIO.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func testLinuxConfig(t *testing.T) Config {
	t.Helper()
	root, err := testCgroupV2RootPath()
	if err != nil {
		t.Fatalf("cgroup v2 root: %v", err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(root, &stat); err != nil {
		t.Fatalf("stat cgroup v2 root %q: %v", root, err)
	}
	return Config{CgroupV2RootPath: root}
}

func testCgroupV2RootPath() (string, error) {
	mounts, err := mountinfo.GetMounts(mountinfo.FSTypeFilter("cgroup2"))
	if err != nil {
		return "", fmt.Errorf("find cgroup v2 root from mountinfo: %w", err)
	}
	for _, mount := range mounts {
		if mount == nil || mount.Mountpoint == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(mount.Mountpoint, "cgroup.controllers")); err == nil {
			return mount.Mountpoint, nil
		}
	}
	return "", os.ErrNotExist
}
