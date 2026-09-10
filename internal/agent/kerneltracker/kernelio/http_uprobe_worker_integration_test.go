//go:build linux && bpf_integration

package kernelio

import (
	"os"
	"os/exec"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestOpenMappedFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "mapped-client")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(int64(2 * os.Getpagesize())); err != nil {
		t.Fatal(err)
	}
	data, err := unix.Mmap(int(f.Fd()), 0, 2*os.Getpagesize(), unix.PROT_READ|unix.PROT_EXEC, unix.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(data)
	start := uint64(uintptr(unsafe.Pointer(&data[0])))
	want, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		size int
	}{
		{name: "current range opens the mapped file", size: len(data)},
		{name: "stale smaller range finds the containing VMA", size: os.Getpagesize()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			worker := &httpUprobeWorker{}
			got, err := worker.openMappedFile(httpUprobeAttachCandidate{
				tgid: int32(os.Getpid()), vmStart: start, vmEnd: start + uint64(tc.size),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer got.Close()
			info, err := got.Stat()
			if err != nil || !os.SameFile(want, info) {
				t.Fatalf("opened another file: %v", err)
			}
		})
	}
}

func requireTestBinary(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is required: %v", name, err)
	}
	return path
}

func newReclaimTestWorker(t *testing.T) *httpUprobeWorker {
	t.Helper()
	config := testLinuxConfig(t)
	config.EnableHTTPRequest = true
	ki, err := NewLinux(nil, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ki.httpUprobeWorker.closeAll(); _ = ki.Close() })
	return ki.httpUprobeWorker
}
