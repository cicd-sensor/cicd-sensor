//go:build linux

package kernelio

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	controlNormalize    = 1
	controlRegister     = 2
	controlScan         = 3
	maxControlMappings  = 256
	maxProcessMapsBytes = 2 << 20
)

// Exported fields are required for cilium's binary map decoding. These private
// types mirror http_uprobe_control_maps.bpf.h; no pointer/address identities.
type uprobeControlRequest struct {
	Nonce                           uint64
	Operation, PID, Count, Overflow uint32
}

type uprobeControlResult struct {
	Nonce, Start, End        uint64
	DeviceMajor, DeviceMinor uint32
	Inode                    uint64
	CTimeSec                 int64
	CTimeNsec, Pad           uint32
}

func (r uprobeControlResult) key() fileClassificationKey {
	return fileClassificationKey{mappedFile: mappedFileIdentity{deviceMajor: r.DeviceMajor, deviceMinor: r.DeviceMinor, inode: r.Inode}, ctimeSec: r.CTimeSec, ctimeNsec: r.CTimeNsec}
}

// uprobeControl shares temporary maps with the primary mmap hook. Only the HTTP
// worker operates it, while LinuxKernelIO owns program/link teardown after join.
type uprobeControl struct {
	objects           *ebpf.Collection
	links             []link.Link
	requests, results *ebpf.Map
	nonce             uint64
}

func newUprobeControl(requests, results *ebpf.Map) (*uprobeControl, error) {
	spec, err := bpfprog.LoadHTTPUprobeControl()
	if err != nil {
		return nil, err
	}
	objects, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{
		"http_uprobe_control_requests": requests, "http_uprobe_control_results": results,
	}})
	if err != nil {
		return nil, err
	}
	c := &uprobeControl{objects: objects, requests: requests, results: results}
	for _, name := range []string{"handle_http_uprobe_register", "handle_http_uprobe_map_vma"} {
		l, err := link.AttachTracing(link.TracingOptions{Program: objects.Programs[name]})
		if err != nil {
			c.close()
			return nil, fmt.Errorf("attach %s: %w", name, err)
		}
		c.links = append(c.links, l)
	}
	return c, nil
}

func (c *uprobeControl) close() {
	if c != nil {
		closeLinks(c.links)
		c.objects.Close()
	}
}

// begin/end are paired while the worker is locked to one OS thread. Requests
// cannot follow goroutine migration or be consumed by unrelated sensor I/O.
func (c *uprobeControl) begin(operation uint32, pid int32) (tid, nonce uint64, err error) {
	if err = c.clearResults(); err != nil {
		return
	}
	c.nonce++
	nonce = c.nonce
	tid = uint64(os.Getpid())<<32 | uint64(uint32(unix.Gettid()))
	err = c.requests.Put(tid, uprobeControlRequest{Nonce: nonce, Operation: operation, PID: uint32(pid)})
	return
}

// Results are bounded and nonce-checked. Clear them once, before the next
// request, rather than walking the same map again after every operation.
func (c *uprobeControl) end(tid uint64) { _ = c.requests.Delete(tid) }

func (c *uprobeControl) clearResults() error {
	for range maxControlMappings {
		var key uint64
		err := c.results.NextKey(nil, &key)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if err = c.results.Delete(key); err != nil {
			return err
		}
	}
	var key uint64
	if err := c.results.NextKey(nil, &key); errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return errors.New("HTTP uprobe control result overflow")
}

func (c *uprobeControl) result(nonce uint64) (uprobeControlResult, error) {
	var r uprobeControlResult
	if err := c.results.Lookup(uint64(0), &r); err != nil {
		return r, err
	}
	if r.Nonce != nonce || r.Inode == 0 {
		return r, errors.New("HTTP uprobe control identity missing or stale")
	}
	return r, nil
}

func (c *uprobeControl) mapFile(f *os.File, size int) ([]byte, fileClassificationKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid, nonce, err := c.begin(controlNormalize, 0)
	if err != nil {
		return nil, fileClassificationKey{}, err
	}
	defer c.end(tid)
	data, err := unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		return nil, fileClassificationKey{}, err
	}
	r, err := c.result(nonce)
	if err == nil && (r.End <= r.Start || r.End-r.Start < uint64(size)) {
		err = errors.New("HTTP uprobe control mapping range mismatch")
	}
	if err != nil {
		_ = unix.Munmap(data)
		return nil, fileClassificationKey{}, err
	}
	return data, r.key(), nil
}

func (c *uprobeControl) attach(ex *link.Executable, program *ebpf.Program, offset uint64, expected fileClassificationKey) (link.Link, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid, nonce, err := c.begin(controlRegister, 0)
	if err != nil {
		return nil, err
	}
	defer c.end(tid)
	l, err := ex.Uprobe("", program, &link.UprobeOptions{Address: offset})
	if err != nil {
		return nil, err
	}
	r, err := c.result(nonce)
	if err == nil && (r.key() != expected || r.Start != offset) {
		err = errors.New("HTTP uprobe registered backing or offset changed")
	}
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// scan decorates the existing /proc/maps read with the original VMA's backing.
// Reopening map_files and remapping it is not equivalent after overlay copy-up.
func (c *uprobeControl) scan(pid int32) ([]processMapping, bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid, nonce, err := c.begin(controlScan, pid)
	if err != nil {
		return nil, false
	}
	defer c.end(tid)
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, processIsGone(err)
	}
	defer f.Close()
	data, readErr := io.ReadAll(io.LimitReader(f, maxProcessMapsBytes+1))
	var q uprobeControlRequest
	complete := readErr == nil && len(data) <= maxProcessMapsBytes
	if err = c.requests.Lookup(tid, &q); err != nil || q.Nonce != nonce || q.Overflow != 0 {
		complete = false
	}
	var mappings []processMapping
	for _, line := range strings.Split(string(data), "\n") {
		rng, _, ok := parseExecMapping(line)
		if !ok {
			continue
		}
		startText, endText, _ := strings.Cut(rng, "-")
		start, _ := strconv.ParseUint(startText, 16, 64)
		end, _ := strconv.ParseUint(endText, 16, 64)
		var r uprobeControlResult
		if err = c.results.Lookup(start, &r); err != nil || r.Nonce != nonce || r.Start != start || r.End != end || r.Inode == 0 {
			complete = false
			continue
		}
		mappings = append(mappings, processMapping{addressRange: rng, mappedFile: r.key().mappedFile})
		if len(mappings) > maxControlMappings {
			return mappings, false
		}
	}
	// seq_file can visit a VMA more than once while growing its buffer. Count
	// may exceed unique mappings, but cannot be smaller than confirmed results.
	if uint64(q.Count) < uint64(len(mappings)) {
		complete = false
	}
	return mappings, complete
}
