//go:build linux

package kernelio

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// http_uprobe_discovery.go — attach discovery for HTTP uprobe taps.
//
// The BPF side is passive: the existing cgroup/connect4/6 hooks already emit a
// tracked-cgroup-only NetworkConnect sample. After decoding that sample,
// KernelTracker queues the connecting PID here before normal engine delivery. A
// single worker scans the process's maps, finds the file that defines SSL_write
// / SSL_write_ex (a shared libssl or a statically-linked binary), and attaches
// the uprobe entry program to it. One attach on an inode covers every process
// mapping it; the cgroup gate keeps emission scoped to tracked jobs.
//
// Ownership: this is KernelIO's. All mutable state (the attached-target registry
// and the negative cache) is touched only by the single worker goroutine, so no
// locking is needed. KernelTracker only sends on the hints channel.
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

type httpUprobeDiscovery struct {
	openSSLProgram *ebpf.Program
	logger         *slog.Logger
	hints          chan int32 // pid of a tracked process that just did a TCP connect

	// Worker-owned state (single goroutine, no locking).
	targets   map[fileIdentity][]link.Link
	negatives *fifoSet

	// Throttled-warning counters. queueDropped is sample-reader-owned (enqueuePID);
	// permDenied / opErrors / capReached are worker-owned (the scan path). Each
	// counter is touched by a single goroutine, so no atomics are needed.
	queueDropped uint64
	permDenied   uint64
	opErrors     uint64
	capReached   uint64
}

func newHTTPUprobeDiscovery(openSSLProgram *ebpf.Program, logger *slog.Logger) *httpUprobeDiscovery {
	return &httpUprobeDiscovery{
		openSSLProgram: openSSLProgram,
		logger:         logger,
		hints:          make(chan int32, 256),
		targets:        make(map[fileIdentity][]link.Link),
		negatives:      newFIFOSet(negativeCacheSize),
	}
}

// enqueuePID schedules one process mapping scan without blocking kernel sample
// intake. A later TCP connect is a natural retry when the bounded queue is full.
func (d *httpUprobeDiscovery) enqueuePID(tgid int32) {
	select {
	case d.hints <- tgid:
	default:
		d.warnThrottled(&d.queueDropped, "http_uprobe_discovery_hint_dropped")
	}
}

// QueueHTTPUprobeDiscovery schedules discovery for a decoded TCP connect.
func (kernelIO *LinuxKernelIO) QueueHTTPUprobeDiscovery(pid int32) {
	if kernelIO.httpUprobeDiscovery == nil {
		return
	}
	kernelIO.httpUprobeDiscovery.enqueuePID(pid)
}

// run drains hints and scans the connecting processes until ctx is cancelled,
// then closes every attached link. It is the sole owner of targets/negatives.
func (d *httpUprobeDiscovery) run(ctx context.Context) {
	defer d.closeAll()
	for {
		select {
		case <-ctx.Done():
			return
		case first := <-d.hints:
			// Coalesce whatever is already queued and dedupe by pid so a burst
			// scans each process once.
			pids := map[int32]struct{}{first: {}}
			for draining := true; draining; {
				select {
				case h := <-d.hints:
					pids[h] = struct{}{}
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
//
// No strict pid/cgroup recheck is done here in Stage 1b-1, by design. Emission
// is gated on the tracked cgroup inside the uprobe program itself, so an
// untracked process — even one that reuses a hint's pid before this scan —
// never produces an event. The only residual effect is one wasted attach on
// such a process's inode, bounded by the target cap and with no cross-job
// disclosure. A pid-current-cgroup-matches-and-is-tracked recheck belongs with
// reclaim in Stage 1b-2, where the registry lifecycle it protects exists.
func (d *httpUprobeDiscovery) scanProcess(pid int32) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		// A gone pid (ENOENT) is the normal end-of-job case and stays silent. A
		// permission error means discovery is systematically blind, so surface
		// it (throttled) rather than looking healthy while capturing nothing.
		if errors.Is(err, os.ErrPermission) {
			d.warnThrottled(&d.permDenied, "http_uprobe_discovery_permission_denied", "op", "open_maps")
		}
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
			d.warnThrottled(&d.capReached, "http_uprobe_target_cap_reached", "targets", len(d.targets))
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
func (d *httpUprobeDiscovery) classifyAndAttach(pid int32, rng string) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/map_files/%s", pid, rng))
	if err != nil {
		// map_files needs CAP_SYS_PTRACE/root: a systematic EPERM here blocks
		// every attach, so surface it (throttled). ENOENT is a raced-away
		// mapping and stays silent. Either way it is inconclusive, not cached.
		if errors.Is(err, os.ErrPermission) {
			d.warnThrottled(&d.permDenied, "http_uprobe_discovery_permission_denied", "op", "open_map_files")
		}
		return
	}
	defer f.Close()

	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "fstat", "error", err)
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
		d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "open_executable", "error", err)
		return
	}
	d.attachTarget(id, ex)
}

// attachTarget attaches the program to the file's target symbols and records the
// outcome. Classification is conservative: only a definitive "no symbol" caches
// a negative; anything else (ErrNotSupported, I/O, permission) is inconclusive
// and retried on a later connect.
func (d *httpUprobeDiscovery) attachTarget(id fileIdentity, ex *link.Executable) {
	var got []link.Link
	for _, symbol := range opensslSymbols {
		l, err := ex.Uprobe(symbol, d.openSSLProgram, nil)
		switch {
		case err == nil:
			got = append(got, l)
		case errors.Is(err, link.ErrNoSymbol):
			// Symbol not defined in this file (a UND reference or absent).
		default:
			// Inconclusive: do not cache. Undo partial attaches and retry later.
			// Unlike a plain "symbol absent", an unexpected attach failure is a
			// real signal, so surface it (throttled).
			d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "uprobe_attach", "symbol", symbol, "error", err)
			closeLinks(got)
			return
		}
	}
	if len(got) > 0 {
		d.targets[id] = got
		return
	}
	// Every target symbol was definitively absent: safe to cache negative.
	d.negatives.add(id)
}

func (d *httpUprobeDiscovery) closeAll() {
	for _, links := range d.targets {
		closeLinks(links)
	}
}

func (d *httpUprobeDiscovery) warn(msg string, args ...any) {
	if d.logger != nil {
		d.logger.Warn(msg, args...)
	}
}

// warnThrottled logs at a power-of-two cadence (1st, 2nd, 4th, 8th, ... event)
// so a systematic failure — a permission error that leaves discovery blind, a
// saturated hint queue — is visible without emitting one line per connect. The
// counter must be owned by the calling goroutine.
func (d *httpUprobeDiscovery) warnThrottled(counter *uint64, msg string, args ...any) {
	*counter++
	n := *counter
	if n&(n-1) == 0 {
		d.warn(msg, append([]any{"count", n}, args...)...)
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
// costs a re-classify, never correctness. This intentionally mirrors
// fileOpenDedupState; if a third use appears, move the shared algorithm to a
// dependency-neutral generic package.
type fifoSet struct {
	limit int
	seen  map[fileIdentity]struct{}
	order []fileIdentity
	next  int
}

func newFIFOSet(limit int) *fifoSet {
	return &fifoSet{
		limit: limit,
		seen:  make(map[fileIdentity]struct{}),
	}
}

func (s *fifoSet) has(id fileIdentity) bool {
	if s == nil {
		return false
	}
	_, ok := s.seen[id]
	return ok
}

func (s *fifoSet) add(id fileIdentity) {
	if s == nil || s.limit <= 0 {
		return
	}
	if _, ok := s.seen[id]; ok {
		return
	}
	if len(s.order) < s.limit {
		s.order = append(s.order, id)
	} else {
		delete(s.seen, s.order[s.next])
		s.order[s.next] = id
		s.next = (s.next + 1) % s.limit
	}
	s.seen[id] = struct{}{}
}
