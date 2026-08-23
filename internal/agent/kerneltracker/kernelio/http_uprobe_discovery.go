//go:build linux

package kernelio

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// http_uprobe_discovery.go — attach discovery and reclaim for HTTP uprobe taps.
//
// A single worker owns all attached targets and the non-target file cache, so
// no locking. Connect hints and reclaim requests only enter this worker; no
// caller reads this state. cgroup gates emission and scopes the scan, but does
// not own link lifetime.

// opensslSymbols are the write entry points attached with the same program.
// SSL_write covers curl/wget/node; SSL_write_ex is what Python (pip/requests)
// calls. Both are mandatory.
var opensslSymbols = []string{"SSL_write", "SSL_write_ex"}

// maxAttachedUprobeTargets bounds attached targets. On cap the worker refuses new
// targets and never evicts a live one; reclaim keeps the steady state bounded,
// so the cap is reached only under adversarial fan-out.
const maxAttachedUprobeTargets = 4096

// missingScanLimit is the number of complete scans that must miss an attached
// target before its links are closed. Incomplete scans do not count; finding
// the target again resets its count.
const missingScanLimit = 2

// nonTargetFileCacheSize bounds the fixed FIFO of file identities definitively
// classified as having none of the target symbols. This avoids re-parsing libc
// or the loader on every connect.
const nonTargetFileCacheSize = 8192

// nonTargetFileCacheKey identifies one non-target cache entry, not a pathname.
// ctime invalidates the cached classification after an inode metadata change
// or ordinary inode reuse. This is a cache discriminator, not a generation ID.
// mnt_id is deliberately excluded:
// it is mount identity, and including it would over-split (the same file via two
// mounts) into a double attach, which the kernel runs as two consumers = two
// events.
type nonTargetFileCacheKey struct {
	mappedFile mappedFileIdentity
	ctimeNano  int64
}

// mappedFileIdentity is the device/inode identity available directly from /proc/pid/maps.
// Reclaim uses it so a map_files open race or metadata change cannot hide a live
// mapping. nonTargetFileCacheKey remains the stricter cache key.
type mappedFileIdentity string

// attachedUprobeTarget is one attached inode. It keeps only the links and the
// number of complete scans that have missed the inode since it was last seen.
type attachedUprobeTarget struct {
	links            []link.Link
	missingScanCount uint8
}

type httpUprobeReconcileRequest struct {
	cgroupPaths []string
	result      chan<- int // optional buffered completion result for integration tests
}

type httpUprobeDiscovery struct {
	openSSLProgram  *ebpf.Program
	logger          *slog.Logger
	hints           chan int32                      // pid of a tracked process that just did a TCP connect
	reconciliations chan httpUprobeReconcileRequest // immutable reclaim input from KernelTracker

	// Worker-owned state (single goroutine, no locking).
	attachedTargets    map[mappedFileIdentity]*attachedUprobeTarget
	nonTargetFileCache *fifoSet

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
		openSSLProgram:     openSSLProgram,
		logger:             logger,
		hints:              make(chan int32, 256),
		reconciliations:    make(chan httpUprobeReconcileRequest, 1),
		attachedTargets:    make(map[mappedFileIdentity]*attachedUprobeTarget),
		nonTargetFileCache: newFIFOSet(nonTargetFileCacheSize),
	}
}

func finishReconcile(request httpUprobeReconcileRequest, targetCount int) {
	if request.result == nil {
		return
	}
	select {
	case request.result <- targetCount:
	default:
	}
}

// enqueueReconciliation hands the worker tracked cgroup paths without blocking
// the caller. The buffer is 1: newer paths replace a stale queued request,
// because only the latest liveness picture matters.
func (d *httpUprobeDiscovery) enqueueReconciliation(cgroupPaths []string, result chan<- int) {
	request := httpUprobeReconcileRequest{cgroupPaths: cgroupPaths, result: result}
	select {
	case stale := <-d.reconciliations: // drop a stale queued request; only the latest matters
		finishReconcile(stale, -1)
	default:
	}
	select {
	case d.reconciliations <- request:
	default:
		finishReconcile(request, -1)
	}
}

// QueueHTTPUprobeReconciliation hands the reclaim worker cloned cgroup paths.
// No-op when HTTP uprobe capture is disabled.
func (kernelIO *LinuxKernelIO) QueueHTTPUprobeReconciliation(cgroupPaths []string) {
	if kernelIO.httpUprobeDiscovery == nil {
		return
	}
	kernelIO.httpUprobeDiscovery.enqueueReconciliation(slices.Clone(cgroupPaths), nil)
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

// run drains hints (attach) and reconciliations (reclaim) on one goroutine until ctx
// is cancelled, then closes every attached link. It is the sole owner of
// attachedTargets/nonTargetFileCache; there is no separate closer goroutine.
func (d *httpUprobeDiscovery) run(ctx context.Context) {
	defer func() {
		d.closeAll()
		select {
		case request := <-d.reconciliations:
			finishReconcile(request, -1)
		default:
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-d.reconciliations:
			d.reconcile(request.cgroupPaths)
			finishReconcile(request, len(d.attachedTargets))
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
func (d *httpUprobeDiscovery) scanProcessInto(pid int32, present map[mappedFileIdentity]struct{}) bool {
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

	seen := make(map[mappedFileIdentity]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		rng, mapped, ok := parseExecMapping(scanner.Text())
		if !ok {
			continue
		}
		if _, dup := seen[mapped]; dup {
			continue
		}
		seen[mapped] = struct{}{}
		if present != nil {
			present[mapped] = struct{}{}
		}
		if entry, have := d.attachedTargets[mapped]; have {
			entry.missingScanCount = 0
			continue
		}
		if len(d.attachedTargets) >= maxAttachedUprobeTargets {
			// Presence is already recorded. Refuse only this new mapping; existing
			// targets remain visible to reclaim so the cap can clear.
			d.warnThrottled(&d.capReached, "http_uprobe_target_cap_reached", "targets", len(d.attachedTargets))
			continue
		}
		d.classifyAndAttach(pid, rng, mapped)
	}
	// A read error means a partial scan (e.g. the process exited mid-read). For
	// attach that is fine (the next connect retries); for reclaim it could hide a
	// live mapping, so report incomplete.
	if err := scanner.Err(); err != nil {
		return false
	}
	return true
}

// classifyAndAttach opens the mapped file by FD (surviving unlink / mount-ns /
// path replacement), computes its identity, and attaches the uprobe program to
// each target symbol it defines. The FD is held until every attach completes.
// Presence was already recorded from maps, so classification failures affect
// attach only and do not make reclaim incomplete.
func (d *httpUprobeDiscovery) classifyAndAttach(pid int32, rng string, mapped mappedFileIdentity) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/map_files/%s", pid, rng))
	if err != nil {
		// ENOENT is a raced-away or non-openable range. Presence was already
		// recorded; other errors are attach failures and are surfaced for retry.
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if errors.Is(err, os.ErrPermission) {
			d.warnThrottled(&d.permDenied, "http_uprobe_discovery_permission_denied", "op", "open_map_files")
		} else {
			d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "open_map_files", "error", err)
		}
		return
	}
	defer f.Close()

	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "fstat", "error", err)
		return
	}
	id := nonTargetFileCacheKey{mappedFile: mapped, ctimeNano: st.Ctim.Nano()}
	if d.nonTargetFileCache.has(id) {
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
func (d *httpUprobeDiscovery) attachTarget(id nonTargetFileCacheKey, ex *link.Executable) {
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
		d.attachedTargets[id.mappedFile] = &attachedUprobeTarget{links: got}
		return
	}
	// Every target symbol was definitively absent: safe to cache negative.
	d.nonTargetFileCache.add(id)
}

func (d *httpUprobeDiscovery) closeAll() {
	for _, entry := range d.attachedTargets {
		closeLinks(entry.links)
	}
}

// reconcile is the reclaim sweep. Expanding the supplied cgroups through
// cgroup.procs and scanning their process maps also provides backstop attach.
// Only detach is fail-keep: an incomplete scan never advances a missing
// count or closes links, though a target positively observed before an error is
// reset to zero. We do not retain the prior scan result; each attached target
// only records how many complete scans have omitted it.
func (d *httpUprobeDiscovery) reconcile(cgroupPaths []string) {
	present := make(map[mappedFileIdentity]struct{})
	complete := true
	pids := make(map[int32]struct{})
	for _, cgroupPath := range cgroupPaths {
		if !d.collectCgroupPIDs(cgroupPath, pids) {
			complete = false
		}
	}
	for pid := range pids {
		if !d.scanProcessInto(pid, present) {
			complete = false
		}
	}

	closed := 0
	if complete {
		for mappedID, entry := range d.attachedTargets {
			if _, mapped := present[mappedID]; mapped {
				entry.missingScanCount = 0
			} else {
				entry.missingScanCount++
			}
			if entry.missingScanCount >= missingScanLimit {
				closeLinks(entry.links)
				delete(d.attachedTargets, mappedID)
				closed++
			}
		}
	}

	// Summary only when something happened; an unchanged complete sweep is
	// silent (a 60 s unchanged line would be steady-state noise).
	if closed > 0 || !complete {
		d.logInfo("http_uprobe_reclaim",
			"complete", complete,
			"closed", closed,
			"targets", len(d.attachedTargets),
			"mapped_identities", len(present),
			"scanned_cgroups", len(cgroupPaths),
			"scanned_pids", len(pids),
		)
	}
}

// collectCgroupPIDs adds the current members of one tracked cgroup. A vanished
// cgroup is the normal teardown race; every other read or parse error may hide
// a live mapper and therefore makes the reclaim scan incomplete.
func (d *httpUprobeDiscovery) collectCgroupPIDs(cgroupPath string, pids map[int32]struct{}) bool {
	f, err := os.Open(filepath.Join(cgroupPath, "cgroup.procs"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true
		}
		if errors.Is(err, os.ErrPermission) {
			d.warnThrottled(&d.permDenied, "http_uprobe_discovery_permission_denied", "op", "open_cgroup_procs")
		} else {
			d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "open_cgroup_procs", "error", err)
		}
		return false
	}
	defer f.Close()

	complete := true
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		pid, err := strconv.ParseInt(scanner.Text(), 10, 32)
		if err != nil || pid <= 0 {
			complete = false
			continue
		}
		pids[int32(pid)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "read_cgroup_procs", "error", err)
		return false
	}
	return complete
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

// parseExecMapping returns the address range and device/inode identity for an
// executable, file-backed mapping with a non-zero inode. Lines for anonymous or
// special ([vdso], [heap], ...) mappings return ok=false.
//
// /proc/<pid>/maps line: "start-end perms offset dev inode pathname".
func parseExecMapping(line string) (rng string, mapped mappedFileIdentity, ok bool) {
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
	return fields[0], mappedFileIdentity(fields[3] + ":" + fields[4]), true
}

// fifoSet is a fixed-size set with FIFO eviction. It is a cache: eviction only
// costs a re-classify, never correctness. This intentionally mirrors
// fileOpenDedupState; if a third use appears, move the shared algorithm to a
// dependency-neutral generic package.
type fifoSet struct {
	limit int
	seen  map[nonTargetFileCacheKey]struct{}
	order []nonTargetFileCacheKey
	next  int
}

func newFIFOSet(limit int) *fifoSet {
	return &fifoSet{
		limit: limit,
		seen:  make(map[nonTargetFileCacheKey]struct{}),
	}
}

func (s *fifoSet) has(id nonTargetFileCacheKey) bool {
	if s == nil {
		return false
	}
	_, ok := s.seen[id]
	return ok
}

func (s *fifoSet) add(id nonTargetFileCacheKey) {
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
