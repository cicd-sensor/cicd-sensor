//go:build linux

package kernelio

import (
	"errors"
	"os"
	"runtime"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type uprobeControlResult struct {
	Nonce                    uint64
	DeviceMajor, DeviceMinor uint32
	Inode                    uint64
	CTimeSec                 int64
	CTimeNsec, Pad           uint32
}

func (r uprobeControlResult) key() fileClassificationKey {
	return fileClassificationKey{
		mappedFile: mappedFileIdentity{
			deviceMajor: r.DeviceMajor,
			deviceMinor: r.DeviceMinor,
			inode:       r.Inode,
		},
		ctimeSec: r.CTimeSec, ctimeNsec: r.CTimeNsec,
	}
}

// uprobeControl shares temporary maps with the primary mmap hook. Only the HTTP
// worker operates it, while LinuxKernelIO owns program/link teardown after join.
type uprobeControl struct {
	requests, results *ebpf.Map
	nonce             uint64
}

// mapFile returns a read-only mapping that pins the inspected backing until
// the caller unmaps it. Only the serial worker uses the nonce and these maps.
func (c *uprobeControl) mapFile(f *os.File) ([]byte, fileClassificationKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	c.nonce++
	tid := uint64(os.Getpid())<<32 | uint64(uint32(unix.Gettid()))
	if err := c.requests.Put(tid, c.nonce); err != nil {
		return nil, fileClassificationKey{}, err
	}
	defer c.requests.Delete(tid)
	data, err := unix.Mmap(int(f.Fd()), 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		return nil, fileClassificationKey{}, err
	}
	var result uprobeControlResult
	err = c.results.Lookup(uint64(0), &result)
	if err == nil && (result.Nonce != c.nonce || result.Inode == 0) {
		err = errors.New("HTTP uprobe control identity missing or stale")
	}
	if err != nil {
		_ = unix.Munmap(data)
		return nil, fileClassificationKey{}, err
	}
	return data, result.key(), nil
}
