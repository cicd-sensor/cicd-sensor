//go:build linux && bpf_integration

package kernelio

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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

func TestLinuxKernelIOOpensDedicatedHTTPUprobeAttachReader(t *testing.T) {
	config := testLinuxConfig(t)
	config.EnableHTTPRequest = true
	kernelIO, err := NewLinux(nil, config)
	if err != nil {
		t.Fatalf("NewLinux: %v", err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = kernelIO.Close()
		}
	})

	if kernelIO.objs.HttpUprobeAttachCandidates == nil {
		t.Fatal("HTTP uprobe attach-candidate ringbuf map is nil")
	}
	if kernelIO.httpUprobeAttachCandidateReader == nil {
		t.Fatal("HTTP uprobe attach-candidate reader is nil")
	}
	if _, err := os.Stat(filepath.Join(httpUprobeBPFFSPinPath, httpUprobeStopMapName)); err != nil {
		t.Fatalf("stat pinned HTTP uprobe stop leases: %v", err)
	}
	if err := kernelIO.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	closed = true
	if _, err := os.Stat(filepath.Join(httpUprobeBPFFSPinPath, httpUprobeStopMapName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pinned HTTP uprobe stop leases remain after clean close: %v", err)
	}
}

func TestLinuxKernelIOReplacesIncompatibleHTTPUprobeStopLeasePin(t *testing.T) {
	if err := os.MkdirAll(httpUprobeBPFFSPinPath, 0o700); err != nil {
		t.Fatalf("create BPF pin directory: %v", err)
	}
	pinnedPath := filepath.Join(httpUprobeBPFFSPinPath, httpUprobeStopMapName)
	if err := os.Remove(pinnedPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove existing stop lease pin: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pinnedPath) })

	incompatible, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "old_stop_lease",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("create incompatible stop lease map: %v", err)
	}
	if err := incompatible.Put(uint32(1), uint32(1)); err != nil {
		_ = incompatible.Close()
		t.Fatalf("seed incompatible stop lease map: %v", err)
	}
	if err := incompatible.Pin(pinnedPath); err != nil {
		_ = incompatible.Close()
		t.Fatalf("pin incompatible stop lease map: %v", err)
	}
	if err := incompatible.Close(); err != nil {
		t.Fatalf("close incompatible stop lease map: %v", err)
	}

	config := testLinuxConfig(t)
	config.EnableHTTPRequest = true
	kernelIO, err := NewLinux(nil, config)
	if err != nil {
		t.Fatalf("NewLinux with incompatible stop lease pin: %v", err)
	}
	t.Cleanup(func() { _ = kernelIO.Close() })

	info, err := kernelIO.objs.HttpUprobeStopLeases.Info()
	if err != nil {
		t.Fatalf("read replacement stop lease map info: %v", err)
	}
	if got, want := info.KeySize, uint32(binary.Size(httpUprobeProcessGeneration{})); got != want {
		t.Fatalf("replacement stop lease key size = %d, want %d", got, want)
	}
}

// TestLinuxKernelIOOpenSSLUprobeAttaches proves the OpenSSL HTTP uprobe entry
// program is attachable to a real libssl inode for both symbols it targets —
// the load-and-attach half of Stage 1b-1 M0. A single program is attached to
// SSL_write and SSL_write_ex, as the design intends. Discovery (choosing which
// inode, and when) is later; here we attach a known libssl directly. Skips if
// no libssl is present on the host.
func TestLinuxKernelIOOpenSSLUprobeAttaches(t *testing.T) {
	libssl := findLibssl(t)

	kernelIO, err := NewLinux(nil, testLinuxConfig(t))
	if err != nil {
		t.Fatalf("NewLinux: %v", err)
	}
	defer kernelIO.Close()

	ex, err := link.OpenExecutable(libssl)
	if err != nil {
		t.Fatalf("OpenExecutable(%s): %v", libssl, err)
	}
	for _, symbol := range []string{"SSL_write", "SSL_write_ex"} {
		uprobe, err := ex.Uprobe(symbol, kernelIO.objs.HandleSslWrite, nil)
		if err != nil {
			t.Fatalf("Uprobe(%s) on %s: %v", symbol, libssl, err)
		}
		if err := uprobe.Close(); err != nil {
			t.Fatalf("close uprobe(%s): %v", symbol, err)
		}
	}
}

func TestLinuxKernelIONghttp2UprobeAttaches(t *testing.T) {
	libnghttp2 := findLibnghttp2(t)

	kernelIO, err := NewLinux(nil, testLinuxConfig(t))
	if err != nil {
		t.Fatalf("NewLinux: %v", err)
	}
	defer kernelIO.Close()

	ex, err := link.OpenExecutable(libnghttp2)
	if err != nil {
		t.Fatalf("OpenExecutable(%s): %v", libnghttp2, err)
	}
	attached := 0
	for _, symbol := range []string{"nghttp2_submit_request", "nghttp2_submit_request2"} {
		uprobe, err := ex.Uprobe(symbol, kernelIO.objs.HandleNghttp2SubmitRequest, nil)
		if errors.Is(err, link.ErrNoSymbol) {
			continue
		}
		if err != nil {
			t.Fatalf("Uprobe(%s) on %s: %v", symbol, libnghttp2, err)
		}
		attached++
		if err := uprobe.Close(); err != nil {
			t.Fatalf("close uprobe(%s): %v", symbol, err)
		}
	}
	if attached == 0 {
		t.Fatalf("no selected nghttp2 request symbol found in %s", libnghttp2)
	}
}

// findLibssl returns a libssl shared object path on the host, or skips.
func findLibssl(t *testing.T) string {
	t.Helper()
	for _, pattern := range []string{
		"/usr/lib/*/libssl.so.3",
		"/lib/*/libssl.so.3",
		"/usr/lib64/libssl.so.3",
		"/usr/lib/libssl.so.3",
		"/usr/lib/*/libssl.so.1.1",
	} {
		if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
			return matches[0]
		}
	}
	t.Skip("no libssl found on host; skipping OpenSSL uprobe attach test")
	return ""
}

func findLibnghttp2(t *testing.T) string {
	t.Helper()
	for _, pattern := range []string{
		"/usr/lib/*/libnghttp2.so.*",
		"/lib/*/libnghttp2.so.*",
		"/usr/lib64/libnghttp2.so.*",
		"/usr/lib/libnghttp2.so.*",
	} {
		if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
			return matches[0]
		}
	}
	t.Skip("no libnghttp2 found on host")
	return ""
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
