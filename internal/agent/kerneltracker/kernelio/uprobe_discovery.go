//go:build linux

package kernelio

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// uprobe_discovery.go — attach discovery for the OpenSSL HTTP uprobe tap.
//
// The BPF side is passive: the existing cgroup/connect4/6 hooks already emit a
// tracked-cgroup-only NetworkConnect sample. The ringbuf reader tees each TCP
// connect to this component, and a single worker scans the connecting process's
// maps, finds the file that defines SSL_write / SSL_write_ex (a shared libssl or
// a statically-linked binary), and attaches the uprobe entry program to it. One
// attach on an inode covers every process mapping it; the cgroup gate keeps
// emission scoped to tracked jobs.
//
// Ownership: this is KernelIO's. All mutable state (the attached-target registry
// and the negative cache) is touched only by the single worker goroutine, so no
// locking is needed. The reader only sends on the hints channel.
//
// Stage 1b-1 scope: no reclaim (attaches live until Close), no strict pid/cgroup
// recheck. Those are Stage 1b-2 / M2.

// opensslSymbols are the write entry points attached with the same program.
// SSL_write covers curl/wget/node; SSL_write_ex is what Python (pip/requests)
// calls. Both are mandatory.
var opensslSymbols = []string{"SSL_write", "SSL_write_ex"}

// maxUprobeTargets bounds attached targets. On cap the worker refuses new
// targets and never evicts a live one. Without reclaim (Stage 1b-2) this is the
// only bound, so it is generous but finite.
const maxUprobeTargets = 4096

// negativeCacheSize bounds the fixed FIFO of "no target symbol" identities so a
// connect burst does not re-parse libc / the loader every time.
const negativeCacheSize = 8192

// fileIdentity identifies a mapped file by content, not by path or mount. dev+ino
// is the file; ctime+size catches inode reuse. mnt_id is deliberately excluded:
// it is mount identity, and including it would over-split (the same file via two
// mounts) into a double attach, which the kernel runs as two consumers = two
// events.
type fileIdentity struct {
	dev       uint64
	ino       uint64
	size      int64
	ctimeNano int64
}

// processHint is a tee'd TCP connect: scan this pid, which belongs to this
// tracked cgroup.
type processHint struct {
	pid      int32
	cgroupID uint64
}

type uprobeDiscovery struct {
	prog   *ebpf.Program
	logger *slog.Logger
	hints  chan processHint

	// Worker-owned state (single goroutine, no locking).
	targets   map[fileIdentity][]link.Link
	negatives *fifoSet

	// Reader-owned counter.
	queueDropped uint64
}

func newUprobeDiscovery(prog *ebpf.Program, logger *slog.Logger) *uprobeDiscovery {
	return &uprobeDiscovery{
		prog:      prog,
		logger:    logger,
		hints:     make(chan processHint, 256),
		targets:   make(map[fileIdentity][]link.Link),
		negatives: newFIFOSet(negativeCacheSize),
	}
}

// teeConnect enqueues a discovery hint for a TCP NetworkConnect sample. It reads
// only the fixed header fields (kind/protocol/cgroup_id/tgid, identical in the
// v4 and v6 layouts), never blocks, and is called from the reader goroutine
// before the sample is forwarded normally.
func (d *uprobeDiscovery) teeConnect(raw []byte) {
	// Header: kind@0 (u32), protocol@4 (u8), cgroup_id@16 (u64), tgid@32 (s32).
	if len(raw) < 36 {
		return
	}
	kind := binary.LittleEndian.Uint32(raw[0:4])
	if kind != SampleKindNetworkConnectV4 && kind != SampleKindNetworkConnectV6 {
		return
	}
	if raw[4] != unix.IPPROTO_TCP {
		return
	}
	cgroupID := binary.LittleEndian.Uint64(raw[16:24])
	tgid := int32(binary.LittleEndian.Uint32(raw[32:36]))

	select {
	case d.hints <- processHint{pid: tgid, cgroupID: cgroupID}:
	default:
		// Never block the reader: a full queue drops the hint. The next connect
		// from the same process is a natural retry.
		d.queueDropped++
	}
}

// run drains hints and scans the connecting processes until ctx is cancelled,
// then closes every attached link. It is the sole owner of targets/negatives.
func (d *uprobeDiscovery) run(ctx context.Context) {
	defer d.closeAll()
	for {
		select {
		case <-ctx.Done():
			return
		case first := <-d.hints:
			// Coalesce whatever is already queued and dedupe by pid so a burst
			// scans each process once.
			pids := map[int32]struct{}{first.pid: {}}
			for draining := true; draining; {
				select {
				case h := <-d.hints:
					pids[h.pid] = struct{}{}
				default:
					draining = false
				}
			}
			for pid := range pids {
				if ctx.Err() != nil {
					return
				}
				d.scanProcess(pid)
			}
		}
	}
}

// scanProcess reads the process's executable, file-backed mappings and attaches
// to any that define a target symbol. A dead pid or unreadable maps is skipped
// (inconclusive; a later connect retries).
func (d *uprobeDiscovery) scanProcess(pid int32) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return
	}
	defer f.Close()

	seen := make(map[string]struct{}) // dedupe by dev:inode within this scan
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		rng, devIno, ok := parseExecMapping(scanner.Text())
		if !ok {
			continue
		}
		if _, dup := seen[devIno]; dup {
			continue
		}
		seen[devIno] = struct{}{}
		if len(d.targets) >= maxUprobeTargets {
			d.warn("uprobe_target_cap_reached", "targets", len(d.targets))
			break
		}
		d.classifyAndAttach(pid, rng)
	}
	// A read error means a partial scan (e.g. the process exited mid-read); the
	// next connect from a still-live process retries.
	_ = scanner.Err()
}

// classifyAndAttach opens the mapped file by FD (surviving unlink / mount-ns /
// path replacement), computes its identity, and attaches the uprobe program to
// each target symbol it defines. The FD is held until every attach completes.
func (d *uprobeDiscovery) classifyAndAttach(pid int32, rng string) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/map_files/%s", pid, rng))
	if err != nil {
		return // pid gone / EPERM: inconclusive, do not cache
	}
	defer f.Close()

	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return
	}
	id := fileIdentity{dev: st.Dev, ino: st.Ino, size: st.Size, ctimeNano: st.Ctim.Nano()}
	if _, have := d.targets[id]; have {
		return
	}
	if d.negatives.has(id) {
		return
	}

	ex, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	if err != nil {
		return
	}
	d.attachTarget(id, ex)
}

// attachTarget attaches the program to the file's target symbols and records the
// outcome. Classification is conservative: only a definitive "no symbol" caches
// a negative; anything else (ErrNotSupported, I/O, permission) is inconclusive
// and retried on a later connect.
func (d *uprobeDiscovery) attachTarget(id fileIdentity, ex *link.Executable) {
	var got []link.Link
	for _, symbol := range opensslSymbols {
		l, err := ex.Uprobe(symbol, d.prog, nil)
		switch {
		case err == nil:
			got = append(got, l)
		case errors.Is(err, link.ErrNoSymbol):
			// Symbol not defined in this file (a UND reference or absent).
		default:
			// Inconclusive: do not cache. Undo partial attaches and retry later.
			closeLinks(got)
			return
		}
	}
	if len(got) > 0 {
		d.targets[id] = got
		d.warn("uprobe_attached", "symbols", len(got))
		return
	}
	// Every target symbol was definitively absent: safe to cache negative.
	d.negatives.add(id)
}

func (d *uprobeDiscovery) closeAll() {
	for _, links := range d.targets {
		closeLinks(links)
	}
}

func (d *uprobeDiscovery) warn(msg string, args ...any) {
	if d.logger != nil {
		d.logger.Warn(msg, args...)
	}
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}

// parseExecMapping returns the address range and a "dev:inode" key for an
// executable, file-backed mapping with a non-zero inode. Lines for anonymous or
// special ([vdso], [heap], ...) mappings return ok=false.
//
// /proc/<pid>/maps line: "start-end perms offset dev inode pathname".
func parseExecMapping(line string) (rng, devIno string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 { // needs a pathname field
		return "", "", false
	}
	perms := fields[1]
	if len(perms) < 3 || perms[2] != 'x' {
		return "", "", false
	}
	if fields[4] == "0" { // inode 0 = anonymous
		return "", "", false
	}
	if strings.HasPrefix(fields[5], "[") { // [vdso] etc.
		return "", "", false
	}
	return fields[0], fields[3] + ":" + fields[4], true
}

// fifoSet is a fixed-size set with FIFO eviction. It is a cache: eviction only
// costs a re-classify, never correctness.
type fifoSet struct {
	set   map[fileIdentity]struct{}
	order []fileIdentity
	next  int
}

func newFIFOSet(size int) *fifoSet {
	return &fifoSet{set: make(map[fileIdentity]struct{}, size), order: make([]fileIdentity, 0, size)}
}

func (s *fifoSet) has(id fileIdentity) bool {
	_, ok := s.set[id]
	return ok
}

func (s *fifoSet) add(id fileIdentity) {
	if _, ok := s.set[id]; ok {
		return
	}
	if len(s.order) < cap(s.order) {
		s.order = append(s.order, id)
	} else {
		delete(s.set, s.order[s.next])
		s.order[s.next] = id
		s.next = (s.next + 1) % len(s.order)
	}
	s.set[id] = struct{}{}
}
