//go:build linux && bpf_integration

package kernelio

import (
	"errors"
	"os"
	"runtime"
	"testing"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func mmapIdentityFixture(t *testing.T) (*os.File, mappedFileIdentity) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "identity")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := f.Truncate(int64(os.Getpagesize())); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	return f, mappedFileIdentity{deviceMajor: unix.Major(uint64(stat.Dev)), deviceMinor: unix.Minor(uint64(stat.Dev)), inode: stat.Ino}
}

func TestHTTPMmapIdentity(t *testing.T) {
	w := newReclaimTestWorker(t)
	f, want := mmapIdentityFixture(t)
	closed, _ := mmapIdentityFixture(t)
	_ = closed.Close()
	for _, tc := range []struct {
		name    string
		file    *os.File
		stale   bool
		wantErr error
	}{
		{name: "read only mapping returns backing identity", file: f},
		{name: "new query replaces an unread old result", file: f, stale: true},
		{name: "failed mmap removes its request", file: closed, wantErr: unix.EBADF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			tid := uint64(os.Getpid())<<32 | uint64(uint32(unix.Gettid()))
			if tc.stale {
				if err := w.mmapRequests.Put(tid, fileClassificationKey{mappedFile: mappedFileIdentity{inode: 1}}); err != nil {
					t.Fatal(err)
				}
			}
			data, got, err := w.mapFile(tc.file)
			if data != nil {
				defer unix.Munmap(data)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error=%v want=%v", err, tc.wantErr)
			}
			if err == nil && got.mappedFile != want {
				t.Fatalf("identity=%+v want=%+v", got.mappedFile, want)
			}
			var remaining bpfprog.BPFProgramFileClassificationKey
			if err := w.mmapRequests.Lookup(tid, &remaining); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("request remains: %v %+v", err, remaining)
			}
		})
	}
}

func TestHTTPMmapIdentityWithoutHook(t *testing.T) {
	// This private map has no BPF writer. An old nonzero value must not make a
	// successful mmap look like a completed identity query.
	requests, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 32, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer requests.Close()
	w := &httpUprobeWorker{mmapRequests: requests}
	f, _ := mmapIdentityFixture(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid := uint64(os.Getpid())<<32 | uint64(uint32(unix.Gettid()))
	if err := requests.Put(tid, fileClassificationKey{mappedFile: mappedFileIdentity{inode: 1}}); err != nil {
		t.Fatal(err)
	}
	data, _, err := w.mapFile(f)
	if err == nil || data != nil {
		t.Fatalf("absent hook accepted: mapping=%v error=%v", data != nil, err)
	}
	var remaining bpfprog.BPFProgramFileClassificationKey
	if err := requests.Lookup(tid, &remaining); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("request remains: %v", err)
	}
}

func TestHTTPMmapIdentityOtherThread(t *testing.T) {
	w := newReclaimTestWorker(t)
	f, want := mmapIdentityFixture(t)
	other, _ := mmapIdentityFixture(t)
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		for range 200 {
			data, err := unix.Mmap(int(other.Fd()), 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_PRIVATE)
			if err != nil {
				done <- err
				return
			}
			if err := unix.Munmap(data); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	t.Cleanup(func() {
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	<-started
	for range 100 {
		data, got, err := w.mapFile(f)
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Munmap(data)
		if got.mappedFile != want {
			t.Fatalf("other thread supplied result: %+v", got.mappedFile)
		}
	}
}

func TestHTTPMmapRequestKeepsFirstResult(t *testing.T) {
	w := newReclaimTestWorker(t)
	first, want := mmapIdentityFixture(t)
	second, _ := mmapIdentityFixture(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid := uint64(os.Getpid())<<32 | uint64(uint32(unix.Gettid()))
	if err := w.mmapRequests.Put(tid, fileClassificationKey{}); err != nil {
		t.Fatal(err)
	}
	defer w.mmapRequests.Delete(tid)
	for _, f := range []*os.File{first, second} {
		data, err := unix.Mmap(int(f.Fd()), 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_PRIVATE)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Munmap(data)
	}
	var got bpfprog.BPFProgramFileClassificationKey
	if err := w.mmapRequests.Lookup(tid, &got); err != nil {
		t.Fatal(err)
	}
	if fileKeyFromBPF(got).mappedFile != want {
		t.Fatalf("completed result overwritten: %+v want=%+v", got, want)
	}
	// This also documents the contract: the first file mapping on this marked
	// thread must be the intended query. TID alone does not identify a file.
}
