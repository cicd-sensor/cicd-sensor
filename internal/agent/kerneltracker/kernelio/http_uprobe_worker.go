//go:build linux

package kernelio

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// http_uprobe_worker.go — attach discovery and reclaim for HTTP uprobe taps.
//
// A single worker owns all attached targets and userspace updates to the
// discovery cache, so no locking. Attach candidates and reconcile requests only
// enter this worker; no caller reads this state. cgroup gates emission and
// scopes the scan, but does not own link lifetime.

type symbolUprobeTarget struct {
	symbol  string
	offset  uint64
	program *ebpf.Program
}

type goUprobeTarget struct {
	function string
	program  *ebpf.Program
}

// maxAttachedUprobeTargets bounds attached targets. On cap the worker refuses new
// targets and never evicts a live one; reclaim keeps the steady state bounded,
// so the cap is reached only under adversarial fan-out.
const maxAttachedUprobeTargets = 4096

// attachCandidateQueueSize absorbs first-seen executable mapping bursts while
// symbol classification and uprobe attach run on the single owner worker.
const attachCandidateQueueSize = 4096

// missingScanLimit is the number of complete scans that must miss an attached
// target before its links are closed. Incomplete scans do not count; finding
// the target again resets its count.
const missingScanLimit = 2

type mappedFileIdentity struct {
	deviceMajor uint32
	deviceMinor uint32
	inode       uint64
}

type fileClassificationKey struct {
	mappedFile mappedFileIdentity
	ctimeSec   int64
	ctimeNsec  uint32
	_          uint32 // explicit padding required by the BPF map-key ABI
}

type httpUprobeAttachCandidate struct {
	tgid    int32
	vmStart uint64
	vmEnd   uint64
	file    fileClassificationKey
}

type processMapping struct {
	addressRange string
	mappedFile   mappedFileIdentity
}

// attachedUprobeTarget is one attached inode. Its classification key identifies
// the discovery-cache entry removed before the links are reclaimed.
type attachedUprobeTarget struct {
	classificationKey fileClassificationKey
	links             []link.Link
	missingScanCount  uint8
	protectedUntil    time.Time
}

type httpUprobeWorker struct {
	symbolTargets  []symbolUprobeTarget // OpenSSL/nghttp2, attached by ELF symbol
	control        *uprobeControl
	goTarget       goUprobeTarget // Go net/http, attached by resolved file offset
	logger         *slog.Logger
	cgroupRootPath string

	// Submission is synchronized only against shutdown; classification stays loop-local.
	submissionMu        sync.Mutex
	stopped             bool
	preparationRequests chan *httpPreparationRequest
	preparationDrops    uint64 // submissionMu-owned

	// Worker inputs. run consumes serially.
	attachCandidates  chan httpUprobeAttachCandidate // candidates emitted by BPF and decoded by KernelIO
	reconcileRequests chan []uint64                  // immutable active cgroup IDs from KernelTracker

	// Worker-owned userspace state (single goroutine, no locking). BPF maps are
	// concurrency-safe kernel objects shared with the hook and sample reader.
	attachedTargets map[mappedFileIdentity]*attachedUprobeTarget
	discoveryCache  *ebpf.Map

	// Throttled-warning counters. attachCandidateQueueDropped is sample-reader-owned;
	// the others are worker-owned. Each counter is touched by one goroutine.
	attachCandidateQueueDropped uint64
	permDenied                  uint64
	opErrors                    uint64
	identityMismatch            uint64
	capReached                  uint64
}

func newHTTPUprobeWorker(
	symbolTargets []symbolUprobeTarget,
	logger *slog.Logger,
	cgroupRootPath string,
	discoveryCache *ebpf.Map,
	goTarget goUprobeTarget,
) *httpUprobeWorker {
	return &httpUprobeWorker{
		symbolTargets:       symbolTargets,
		goTarget:            goTarget,
		logger:              logger,
		cgroupRootPath:      cgroupRootPath,
		attachCandidates:    make(chan httpUprobeAttachCandidate, attachCandidateQueueSize),
		reconcileRequests:   make(chan []uint64, 1),
		attachedTargets:     make(map[mappedFileIdentity]*attachedUprobeTarget),
		preparationRequests: make(chan *httpPreparationRequest, httpPreparationQueueSize),
		discoveryCache:      discoveryCache,
	}
}

// queueTargetReconciliation hands the worker one immutable active-cgroup
// snapshot without blocking the KernelTracker loop. One pending sweep is enough;
// if it takes longer than the interval, the next ticker retries.
func (w *httpUprobeWorker) queueTargetReconciliation(activeCgroupIDs []uint64) {
	select {
	case w.reconcileRequests <- activeCgroupIDs:
	default:
	}
}

// QueueHTTPUprobeReconciliation hands the worker active cgroup IDs.
// No-op when HTTP uprobe capture is disabled.
func (kernelIO *LinuxKernelIO) QueueHTTPUprobeReconciliation(activeCgroupIDs []uint64) {
	if kernelIO.httpUprobeWorker == nil {
		return
	}
	kernelIO.httpUprobeWorker.queueTargetReconciliation(activeCgroupIDs)
}

// queueAttachCandidate schedules classification and attachment without blocking
// sample intake. The discovery-cache entry stays present while the candidate is
// queued; dropping it releases the entry so a later mapping can retry.
func (w *httpUprobeWorker) queueAttachCandidate(candidate httpUprobeAttachCandidate) {
	select {
	case w.attachCandidates <- candidate:
	default:
		if err := w.deleteDiscoveryCacheEntry(candidate.file); err != nil {
			w.warn("http_uprobe_discovery_unexpected_error", "op", "discovery_cache_delete", "error", err)
		}
		w.warnThrottled(&w.attachCandidateQueueDropped, "http_uprobe_attach_candidate_dropped")
	}
}

// run processes attach candidates and reconcile requests on one goroutine until ctx
// is cancelled, then closes every attached link. It is the sole owner of
// attachedTargets and link lifecycle; there is no separate closer goroutine.
func (w *httpUprobeWorker) run(ctx context.Context) {
	defer w.closeAll()
	defer w.shutdownPreparation()
	for {
		select {
		case <-ctx.Done():
			return
		case activeCgroupIDs := <-w.reconcileRequests:
			w.reconcileTargets(ctx, activeCgroupIDs)
		case candidate := <-w.attachCandidates:
			w.classifyAndAttach(candidate)
		case request := <-w.preparationRequests:
			w.prepareRequest(ctx, request)
		}
	}
}

// scanProcessMappings returns the executable file mappings of pid. It returns
// false if an error could have hidden a live mapping; mappings read before the
// error are still returned as positive observations.
func (w *httpUprobeWorker) scanProcessMappings(pid int32) ([]processMapping, bool) {
	if w.control != nil {
		return w.control.scan(pid)
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		// Only a gone pid (ENOENT) is the benign race; anything else could hide
		// a live mapping. Permission errors are surfaced (discovery is blind).
		if processIsGone(err) {
			return nil, true
		}
		if errors.Is(err, os.ErrPermission) {
			w.warnThrottled(&w.permDenied, "http_uprobe_discovery_permission_denied", "op", "open_maps")
		} else {
			w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "open_maps", "error", err)
		}
		return nil, false
	}
	defer f.Close()

	var mappings []processMapping
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
		mappings = append(mappings, processMapping{addressRange: rng, mappedFile: mapped})
	}
	// A read error means a partial scan (e.g. the process exited mid-read). It
	// makes reclaim fail-keep and prevents a stale-range fallback from guessing.
	if err := scanner.Err(); err != nil {
		return mappings, false
	}
	return mappings, true
}

func processIsGone(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH)
}

// openMappedFile first uses the completed VMA range from uprobe_mmap. A VMA
// can merge before userspace opens map_files, so ENOENT gets one current-maps
// lookup by device/inode. Other failures are returned unchanged.
func (w *httpUprobeWorker) openMappedFile(candidate httpUprobeAttachCandidate) (*os.File, error) {
	f, err := os.Open(mappedFilePath(candidate.tgid, candidate.vmStart, candidate.vmEnd))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return f, err
	}

	mappings, complete := w.scanProcessMappings(candidate.tgid)
	if !complete {
		return nil, err
	}
	for _, current := range mappings {
		if current.mappedFile == candidate.file.mappedFile {
			return os.Open(fmt.Sprintf("/proc/%d/map_files/%s", candidate.tgid, current.addressRange))
		}
	}
	return nil, err
}

func mappedFilePath(pid int32, start, end uint64) string {
	return fmt.Sprintf("/proc/%d/map_files/%x-%x", pid, start, end)
}

func classificationKeyFromFile(f *os.File) (fileClassificationKey, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return fileClassificationKey{}, err
	}
	return fileClassificationKey{
		mappedFile: mappedFileIdentity{
			deviceMajor: uint32(unix.Major(uint64(st.Dev))),
			deviceMinor: uint32(unix.Minor(uint64(st.Dev))),
			inode:       st.Ino,
		},
		ctimeSec:  st.Ctim.Sec,
		ctimeNsec: uint32(st.Ctim.Nsec),
	}, nil
}

func (w *httpUprobeWorker) deleteDiscoveryCacheEntry(key fileClassificationKey) error {
	if w.discoveryCache == nil {
		return nil
	}
	err := w.discoveryCache.Delete(key)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (w *httpUprobeWorker) cacheDiscoveryFile(key fileClassificationKey) {
	if w.discoveryCache == nil {
		return
	}
	if err := w.discoveryCache.Put(key, uint8(1)); err != nil {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "discovery_cache_update", "error", err)
	}
}

func (w *httpUprobeWorker) closeAll() {
	for _, entry := range w.attachedTargets {
		closeLinks(entry.links)
	}
	clear(w.attachedTargets)
}

// reconcileTargets is the reclaim sweep. It resolves the immutable active-ID
// snapshot to current filesystem paths, then expands cgroup.procs and scans
// process maps. It only observes liveness; mapping-triggered discovery owns
// target classification and attach.
// Only detach is fail-keep: an incomplete scan never advances a missing
// count or closes links, though a target positively observed before an error is
// reset to zero. We do not retain the prior scan result; each attached target
// only records how many complete scans have omitted it.
func (w *httpUprobeWorker) reconcileTargets(ctx context.Context, activeCgroupIDs []uint64) {
	if ctx.Err() != nil {
		return
	}
	scanStarted := time.Now()
	observedMappedFiles := make(map[mappedFileIdentity]struct{})
	activeCgroupPaths, complete := resolveActiveCgroupPaths(w.cgroupRootPath, activeCgroupIDs)
	pids := make(map[int32]struct{})
	for _, cgroupPath := range activeCgroupPaths {
		if !w.collectCgroupPIDs(cgroupPath, pids) {
			complete = false
		}
	}
	for pid := range pids {
		mappings, scanComplete := w.scanProcessMappings(pid)
		if !scanComplete {
			complete = false
		}
		for _, mapping := range mappings {
			observedMappedFiles[mapping.mappedFile] = struct{}{}
		}
	}

	closed := 0
	for mappedID, entry := range w.attachedTargets {
		if scanStarted.Before(entry.protectedUntil) {
			entry.missingScanCount = 0
			continue
		}
		if _, observed := observedMappedFiles[mappedID]; observed {
			entry.missingScanCount = 0
			continue
		}
		if !complete {
			continue
		}
		if entry.missingScanCount < missingScanLimit {
			entry.missingScanCount++
		}
		if entry.missingScanCount >= missingScanLimit {
			// Yield between targets when attachment work arrives. A fixed close
			// count per minute cannot drain short-lived container targets; an
			// idle worker can safely finish this sweep without another owner.
			if ctx.Err() != nil || len(w.preparationRequests) > 0 || len(w.attachCandidates) > 0 {
				continue
			}
			// Delete the discovery-cache entry first. If that fails, keep the link;
			// closing it would prevent a later mapping from requesting re-attach.
			if err := w.deleteDiscoveryCacheEntry(entry.classificationKey); err != nil {
				w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "discovery_cache_delete", "error", err)
				continue
			}
			closeStarted := time.Now()
			closeLinks(entry.links)
			if w.logger != nil {
				w.logger.Debug("http_uprobe_target_closed", "elapsed", time.Since(closeStarted))
			}
			delete(w.attachedTargets, mappedID)
			closed++
		}
	}

	// Summary only when something happened; an unchanged complete sweep is
	// silent (a 60 s unchanged line would be steady-state noise).
	if closed > 0 || !complete {
		w.logInfo("http_uprobe_reclaim",
			"complete", complete,
			"closed", closed,
			"targets", len(w.attachedTargets),
			"mapped_identities", len(observedMappedFiles),
			"scanned_cgroups", len(activeCgroupPaths),
			"scanned_pids", len(pids),
		)
	}
}

// resolveActiveCgroupPaths maps KernelTracker's active cgroup IDs to their
// current cgroupfs paths. A full walk is necessary because cgroup IDs do not
// encode paths. A disappearing child is a normal teardown race; any other walk
// or stat error makes reclaim incomplete and therefore fail-keep.
func resolveActiveCgroupPaths(cgroupRootPath string, activeCgroupIDs []uint64) ([]string, bool) {
	if len(activeCgroupIDs) == 0 {
		return nil, true
	}
	if cgroupRootPath == "" {
		return nil, false
	}

	wanted := make(map[uint64]struct{}, len(activeCgroupIDs))
	for _, cgroupID := range activeCgroupIDs {
		wanted[cgroupID] = struct{}{}
	}

	var paths []string
	err := filepath.WalkDir(cgroupRootPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if path != cgroupRootPath && errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}

		var stat unix.Stat_t
		if err := unix.Stat(path, &stat); err != nil {
			if path != cgroupRootPath && errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if _, ok := wanted[stat.Ino]; ok {
			paths = append(paths, path)
		}
		return nil
	})
	return paths, err == nil
}

// collectCgroupPIDs adds the current members of one tracked cgroup. A vanished
// cgroup is the normal teardown race; every other read or parse error may hide
// a live mapper and therefore makes the reclaim scan incomplete.
func (w *httpUprobeWorker) collectCgroupPIDs(cgroupPath string, pids map[int32]struct{}) bool {
	f, err := os.Open(filepath.Join(cgroupPath, "cgroup.procs"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true
		}
		if errors.Is(err, os.ErrPermission) {
			w.warnThrottled(&w.permDenied, "http_uprobe_discovery_permission_denied", "op", "open_cgroup_procs")
		} else {
			w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "open_cgroup_procs", "error", err)
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
		// Threaded children deliberately reject cgroup.procs reads. Their
		// process IDs live in the threaded domain, including sibling threads.
		// Scanning that superset is conservative for link liveness only.
		if errors.Is(err, unix.EOPNOTSUPP) {
			if domain := threadedDomainPath(cgroupPath, w.cgroupRootPath); domain != "" {
				return w.collectCgroupPIDs(domain, pids)
			}
		}
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "read_cgroup_procs", "error", err)
		return false
	}
	return complete
}

// threadedDomainPath follows the kernel's threaded topology, never escaping
// the configured cgroup mount. Unknown or changing topology remains fail-keep.
// https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#threads
func threadedDomainPath(path, root string) string {
	path, root = filepath.Clean(path), filepath.Clean(root)
	for first := true; ; first = false {
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return ""
		}
		kind, err := os.ReadFile(filepath.Join(path, "cgroup.type"))
		if err != nil {
			return ""
		}
		if !first && strings.TrimSpace(string(kind)) == "domain threaded" {
			return path
		}
		if strings.TrimSpace(string(kind)) != "threaded" || path == root {
			return ""
		}
		path = filepath.Dir(path)
	}
}

func (w *httpUprobeWorker) logInfo(msg string, args ...any) {
	if w.logger != nil {
		w.logger.Info(msg, args...)
	}
}

func (w *httpUprobeWorker) warn(msg string, args ...any) {
	if w.logger != nil {
		w.logger.Warn(msg, args...)
	}
}

// warnThrottled logs at a power-of-two cadence (1st, 2nd, 4th, 8th, ... event)
// so a systematic failure — a permission error that leaves discovery blind, a
// saturated mapping queue — is visible without emitting one line per mapping. The
// counter must be owned by the calling goroutine.
func (w *httpUprobeWorker) warnThrottled(counter *uint64, msg string, args ...any) {
	*counter++
	n := *counter
	if n&(n-1) == 0 {
		w.warn(msg, append([]any{"count", n}, args...)...)
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
		return "", mappedFileIdentity{}, false
	}
	perms := fields[1]
	if len(perms) < 3 || perms[2] != 'x' {
		return "", mappedFileIdentity{}, false
	}
	if fields[4] == "0" { // inode 0 = anonymous
		return "", mappedFileIdentity{}, false
	}
	if strings.HasPrefix(fields[5], "[") { // [vdso] etc.
		return "", mappedFileIdentity{}, false
	}
	deviceMajorText, deviceMinorText, found := strings.Cut(fields[3], ":")
	if !found {
		return "", mappedFileIdentity{}, false
	}
	deviceMajor, err := strconv.ParseUint(deviceMajorText, 16, 32)
	if err != nil {
		return "", mappedFileIdentity{}, false
	}
	deviceMinor, err := strconv.ParseUint(deviceMinorText, 16, 32)
	if err != nil {
		return "", mappedFileIdentity{}, false
	}
	inode, err := strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return "", mappedFileIdentity{}, false
	}
	startText, endText, found := strings.Cut(fields[0], "-")
	if !found {
		return "", mappedFileIdentity{}, false
	}
	start, err := strconv.ParseUint(startText, 16, 64)
	if err != nil {
		return "", mappedFileIdentity{}, false
	}
	end, err := strconv.ParseUint(endText, 16, 64)
	if err != nil || end <= start {
		return "", mappedFileIdentity{}, false
	}
	// /proc/<pid>/map_files exposes each mapped ELF under its unpadded VMA range.
	// Therefore maps "00400000-066a1000" becomes map_files "400000-66a1000".
	// Parse numerically so the lookup opens the mapped ELF entry.
	rng = fmt.Sprintf("%x-%x", start, end)
	return rng, mappedFileIdentity{
		deviceMajor: uint32(deviceMajor),
		deviceMinor: uint32(deviceMinor),
		inode:       inode,
	}, true
}
