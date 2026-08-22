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
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// http_uprobe_discovery.go — attach discovery and reclaim for HTTP uprobe taps.
//
// A single worker owns all mutable state (attached targets, negative cache), so
// no locking. KernelTracker sends connect hints (attach) and PID snapshots
// (reclaim); it never reads the registry. cgroup gates emission and scopes the
// scan; it does not own link lifetime — reclaim is a maps-liveness sweep.

// opensslSymbols are the write entry points attached with the same program.
// SSL_write covers curl/wget/node; SSL_write_ex is what Python (pip/requests)
// calls. Both are mandatory.
var opensslSymbols = []string{"SSL_write", "SSL_write_ex"}

// maxUprobeTargets bounds attached targets. On cap the worker refuses new
// targets and never evicts a live one; reclaim keeps the steady state bounded,
// so the cap is reached only under adversarial fan-out.
const maxUprobeTargets = 4096

// reclaimMissThreshold: close after this many complete snapshots miss a target.
// Incomplete scans neither advance nor reset it; a reappearance resets to 0.
const reclaimMissThreshold = 2

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

// registryEntry is one attached inode. lastSeenAt is refreshed on every
// observation (attach, already-attached hit, complete snapshot listing it) so a
// snapshot that started earlier does not reclaim a target seen since.
type registryEntry struct {
	links       []link.Link
	lastSeenAt  time.Time
	missedScans uint8
}

type httpUprobeDiscovery struct {
	openSSLProgram *ebpf.Program
	logger         *slog.Logger
	hints          chan int32                 // pid of a tracked process that just did a TCP connect
	snapshots      chan MappedProcessSnapshot // immutable reclaim input from KernelTracker
	queries        chan chan int              // test-only: worker answers the attached-target count
	now            func() time.Time           // injectable clock for tests

	// Worker-owned state (single goroutine, no locking).
	targets   map[fileIdentity]*registryEntry
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
		snapshots:      make(chan MappedProcessSnapshot, 1),
		queries:        make(chan chan int),
		now:            time.Now,
		targets:        make(map[fileIdentity]*registryEntry),
		negatives:      newFIFOSet(negativeCacheSize),
	}
}

// enqueueSnapshot hands the worker a reclaim snapshot without blocking the
// caller. The buffer is 1: a newer snapshot replaces a stale queued one,
// because only the latest liveness picture matters.
func (d *httpUprobeDiscovery) enqueueSnapshot(snapshot MappedProcessSnapshot) {
	select {
	case <-d.snapshots: // drop a stale queued snapshot; only the latest matters
	default:
	}
	select {
	case d.snapshots <- snapshot:
	default: // worker drained it concurrently and the buffer refilled: nothing to do
	}
}

// ReconcileHTTPUprobeTargets hands the reclaim worker an immutable PID
// snapshot. No-op when HTTP uprobe capture is disabled.
func (kernelIO *LinuxKernelIO) ReconcileHTTPUprobeTargets(ctx context.Context, snapshot MappedProcessSnapshot) {
	_ = ctx
	if kernelIO.httpUprobeDiscovery == nil {
		return
	}
	kernelIO.httpUprobeDiscovery.enqueueSnapshot(snapshot)
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

// run drains hints (attach) and snapshots (reclaim) on one goroutine until ctx
// is cancelled, then closes every attached link. It is the sole owner of
// targets/negatives; there is no separate closer goroutine.
func (d *httpUprobeDiscovery) run(ctx context.Context) {
	defer d.closeAll()
	for {
		select {
		case <-ctx.Done():
			return
		case snapshot := <-d.snapshots:
			d.reconcile(snapshot)
			if snapshot.Done != nil {
				close(snapshot.Done)
			}
		case reply := <-d.queries:
			reply <- len(d.targets)
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
				d.scanProcessInto(pid, nil)
			}
		}
	}
}

// scanProcessInto attaches to any executable mapping of pid that defines a
// target symbol and, when present is non-nil, records every mapping's identity
// into it (reclaim's liveness probe). Returns false if an error could have
// hidden a live mapping.
func (d *httpUprobeDiscovery) scanProcessInto(pid int32, present map[fileIdentity]struct{}) (complete bool) {
	complete = true
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		// Only a gone pid (ENOENT) is the benign race; anything else could hide
		// a live mapping. Permission errors are surfaced (discovery is blind).
		if errors.Is(err, os.ErrNotExist) {
			return true
		}
		if errors.Is(err, os.ErrPermission) {
			d.warnThrottled(&d.permDenied, "http_uprobe_discovery_permission_denied", "op", "open_maps")
		} else {
			d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "open_maps", "error", err)
		}
		return false
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
		// Keep probing every mapping even at the cap: the liveness of already
		// attached targets must still be observed, or stale links could never
		// be reclaimed and the cap would never clear. The cap only refuses NEW
		// attaches (inside classifyAndAttach).
		if !d.classifyAndAttach(pid, rng, present) {
			complete = false
		}
	}
	// A read error means a partial scan (e.g. the process exited mid-read). For
	// attach that is fine (the next connect retries); for reclaim it could hide a
	// live mapping, so report incomplete.
	if err := scanner.Err(); err != nil {
		return false
	}
	return complete
}

// classifyAndAttach opens the mapped file by FD (surviving unlink / mount-ns /
// path replacement), computes its identity, and attaches the uprobe program to
// each target symbol it defines. The FD is held until every attach completes.
// It returns false if an error could have hidden a live mapping (permission /
// unexpected I/O), which reclaim treats as an incomplete probe; a raced-away
// mapping (ENOENT) is the normal case and returns true.
func (d *httpUprobeDiscovery) classifyAndAttach(pid int32, rng string, present map[fileIdentity]struct{}) bool {
	f, err := os.Open(fmt.Sprintf("/proc/%d/map_files/%s", pid, rng))
	if err != nil {
		// ENOENT is a raced-away mapping (benign). Anything else could hide a
		// live mapping; EPERM additionally means discovery is blind. Never cached.
		if errors.Is(err, os.ErrNotExist) {
			return true
		}
		if errors.Is(err, os.ErrPermission) {
			d.warnThrottled(&d.permDenied, "http_uprobe_discovery_permission_denied", "op", "open_map_files")
		} else {
			d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "open_map_files", "error", err)
		}
		return false
	}
	defer f.Close()

	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "fstat", "error", err)
		return false
	}
	id := fileIdentity{dev: st.Dev, ino: st.Ino, size: st.Size, ctimeNano: st.Ctim.Nano()}
	if present != nil {
		present[id] = struct{}{}
	}
	if entry, have := d.targets[id]; have {
		// Record the observation so an older in-flight snapshot cannot reclaim
		// a target just seen live.
		entry.lastSeenAt = d.now()
		return true
	}
	if d.negatives.has(id) {
		return true
	}
	if len(d.targets) >= maxUprobeTargets {
		// Refuse-not-evict: decline the new inode, keep every live link.
		// Presence was already recorded above, so reclaim still sees it.
		d.warnThrottled(&d.capReached, "http_uprobe_target_cap_reached", "targets", len(d.targets))
		return true
	}

	ex, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	if err != nil {
		d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "open_executable", "error", err)
		return false
	}
	d.attachTarget(id, ex)
	return true
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
		d.targets[id] = &registryEntry{links: got, lastSeenAt: d.now()}
		return
	}
	// Every target symbol was definitively absent: safe to cache negative.
	d.negatives.add(id)
}

func (d *httpUprobeDiscovery) closeAll() {
	for _, entry := range d.targets {
		closeLinks(entry.links)
	}
}

// reconcile is the reclaim sweep. Scanning the snapshot's PIDs attaches
// (backstop) and is always safe; only detach is fail-keep: an incomplete
// snapshot neither advances nor resets missedScans and closes nothing. A
// target observed at or after ScanStartedAt is not closed by that snapshot;
// a hint still queued then can lose the race and be re-attached later.
func (d *httpUprobeDiscovery) reconcile(snapshot MappedProcessSnapshot) {
	present := make(map[fileIdentity]struct{})
	complete := snapshot.Complete
	for _, pid := range snapshot.PIDs {
		if !d.scanProcessInto(pid, present) {
			complete = false
		}
	}

	closed := 0
	if complete {
		now := d.now()
		for id, entry := range d.targets {
			_, mapped := present[id]
			switch {
			case mapped:
				entry.missedScans = 0
				entry.lastSeenAt = now
			case !entry.lastSeenAt.Before(snapshot.ScanStartedAt):
				// Observed during this scan (processed observation): leave the
				// miss count alone; this snapshot cannot vouch for its absence.
			default:
				entry.missedScans++
			}
			if entry.missedScans >= reclaimMissThreshold {
				closeLinks(entry.links)
				delete(d.targets, id)
				closed++
			}
		}
	}

	// Summary only when something happened; an unchanged complete sweep is
	// silent (a 60 s unchanged line would be steady-state noise).
	if closed > 0 || !complete || snapshot.ReadErrors > 0 {
		d.logInfo("http_uprobe_reclaim",
			"complete", complete,
			"closed", closed,
			"targets", len(d.targets),
			"mapped_identities", len(present),
			"scanned_cgroups", snapshot.ScannedCgroups,
			"scanned_pids", len(snapshot.PIDs),
			"pids_gone", snapshot.PIDsGone,
			"read_errors", snapshot.ReadErrors,
		)
	}
}

func (d *httpUprobeDiscovery) logInfo(msg string, args ...any) {
	if d.logger != nil {
		d.logger.Info(msg, args...)
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
