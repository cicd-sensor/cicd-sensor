//go:build linux

package kernelio

import (
	"errors"
	"os"
	"runtime"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"

	"golang.org/x/sys/unix"
)

// mapFile queries the backing identity through the existing mmap hook. Only the
// serial worker calls it. LockOSThread keeps the map key valid across the syscall;
// no unrelated file mapping may run on this thread before the requested mmap.
// The caller keeps the returned mapping until it finishes inspecting the file.
func (w *httpUprobeWorker) mapFile(f *os.File) ([]byte, fileClassificationKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tid := uint64(os.Getpid())<<32 | uint64(uint32(unix.Gettid()))
	// Reset the result for every query, including after a failed cleanup.
	if err := w.mmapRequests.Put(tid, bpfprog.BPFProgramFileClassificationKey{}); err != nil {
		return nil, fileClassificationKey{}, err
	}
	defer w.mmapRequests.Delete(tid)
	data, err := unix.Mmap(int(f.Fd()), 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		return nil, fileClassificationKey{}, err
	}
	var id bpfprog.BPFProgramFileClassificationKey
	err = w.mmapRequests.Lookup(tid, &id)
	if err == nil && id.MappedFile.Inode == 0 {
		err = errors.New("HTTP mmap identity missing")
	}
	if err != nil {
		_ = unix.Munmap(data)
		return nil, fileClassificationKey{}, err
	}
	return data, fileKeyFromBPF(id), nil
}
