//go:build linux

package kernelio

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// http_uprobe_worker.go — attach discovery and reclaim for HTTP uprobe taps.
//
// A single worker owns all attached targets and userspace updates to the
// discovery cache, so no locking. Attach candidates and reconcile requests only
// enter this worker. A tracking owner retains its links until its last cgroup
// leaves tracking; file mappings do not determine link lifetime.

type symbolUprobeTarget struct {
	symbol  string
	offset  uint64
	program *ebpf.Program
}

// maxAttachedUprobeTargets bounds attached targets. On cap the worker refuses new
// targets and never evicts a live one. Many simultaneous or long-lived owners
// can reach the cap even without malicious activity.
const maxAttachedUprobeTargets = 4096

// attachCandidateQueueSize absorbs first-seen executable mapping bursts while
// symbol classification and uprobe attach run on the single owner worker.
const attachCandidateQueueSize = 4096

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

type httpDiscoveryKey struct {
	owner uint64
	file  fileClassificationKey
}

type httpTargetKey struct {
	owner uint64
	file  mappedFileIdentity
}

type httpUprobeAttachCandidate struct {
	cgroupID uint64
	owner    uint64
	tgid     int32
	vmStart  uint64
	vmEnd    uint64
	file     fileClassificationKey
}

// attachedUprobeTarget holds one owner's links for a file. The classification
// key distinguishes file generations when a later mapping reaches the worker.
type attachedUprobeTarget struct {
	classificationKey httpDiscoveryKey
	links             []link.Link
}

type httpOwnerSource interface {
	httpOwner(uint64) uint64
	httpOwners() (map[uint64]struct{}, error)
}

type httpUprobeWorker struct {
	symbolTargets  []symbolUprobeTarget // OpenSSL/nghttp2, attached by ELF symbol
	control        *uprobeControl
	goProgram      *ebpf.Program // Go net/http, attached by resolved file offset
	logger         *slog.Logger
	cgroupRootPath string

	// Submission is synchronized only against shutdown; classification stays loop-local.
	submissionMu        sync.Mutex
	stopped             bool
	preparationRequests chan *httpPreparationRequest
	preparationDrops    uint64 // submissionMu-owned

	// Worker inputs. run consumes serially.
	attachCandidates  chan httpUprobeAttachCandidate // candidates emitted by BPF and decoded by KernelIO
	reconcileRequests chan struct{}                  // coalesced reclaim wakeups

	// Worker-owned userspace state (single goroutine, no locking). BPF maps are
	// concurrency-safe kernel objects shared with the hook and sample reader.
	attachedTargets map[httpTargetKey]*attachedUprobeTarget
	discoveryCache  *ebpf.Map
	tracking        httpOwnerSource

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
	goProgram *ebpf.Program,
) *httpUprobeWorker {
	return &httpUprobeWorker{
		symbolTargets:       symbolTargets,
		goProgram:           goProgram,
		logger:              logger,
		cgroupRootPath:      cgroupRootPath,
		attachCandidates:    make(chan httpUprobeAttachCandidate, attachCandidateQueueSize),
		reconcileRequests:   make(chan struct{}, 1),
		attachedTargets:     make(map[httpTargetKey]*attachedUprobeTarget),
		preparationRequests: make(chan *httpPreparationRequest, httpPreparationQueueSize),
		discoveryCache:      discoveryCache,
	}
}

// queueTargetReconciliation coalesces notifications without blocking event intake.
func (w *httpUprobeWorker) queueTargetReconciliation() {
	select {
	case w.reconcileRequests <- struct{}{}:
	default:
	}
}

// QueueHTTPUprobeReconciliation requests a tracking-owner reclaim sweep.
// No-op when HTTP uprobe capture is disabled.
func (kernelIO *LinuxKernelIO) QueueHTTPUprobeReconciliation() {
	if kernelIO.httpUprobeWorker == nil {
		return
	}
	kernelIO.httpUprobeWorker.queueTargetReconciliation()
}

// queueAttachCandidate schedules classification and attachment without blocking
// sample intake. The discovery-cache entry stays present while the candidate is
// queued; dropping it releases the entry so a later mapping can retry.
func (w *httpUprobeWorker) queueAttachCandidate(candidate httpUprobeAttachCandidate) {
	select {
	case w.attachCandidates <- candidate:
	default:
		if err := w.deleteDiscoveryCacheEntry(httpDiscoveryKey{candidate.owner, candidate.file}); err != nil {
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
		case <-w.reconcileRequests:
			w.reconcileTargets(ctx)
		case candidate := <-w.attachCandidates:
			w.classifyAndAttach(candidate)
		case request := <-w.preparationRequests:
			w.prepareRequest(ctx, request)
		}
	}
}

func processIsGone(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH)
}

// openMappedFile first uses the completed VMA range from uprobe_mmap. A VMA
// can merge before userspace opens map_files, so ENOENT gets one current-maps
// lookup by the original start address. Other failures are returned unchanged.
func (w *httpUprobeWorker) openMappedFile(candidate httpUprobeAttachCandidate) (*os.File, error) {
	f, err := os.Open(mappedFilePath(candidate.tgid, candidate.vmStart, candidate.vmEnd))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return f, err
	}

	// A merged VMA contains the old start address. Do not compare /proc's
	// overlay-visible inode with the backing inode from BPF. prepareFile verifies
	// the opened FD against the notification before using it.
	maps, readErr := os.Open(fmt.Sprintf("/proc/%d/maps", candidate.tgid))
	if readErr != nil {
		return nil, err
	}
	defer maps.Close()
	scanner := bufio.NewScanner(io.LimitReader(maps, 2<<20))
	for scanner.Scan() {
		start, end, ok := parseExecMapping(scanner.Text())
		if !ok {
			continue
		}
		if start <= candidate.vmStart && candidate.vmStart < end {
			return os.Open(mappedFilePath(candidate.tgid, start, end))
		}
	}

	return nil, err
}

func mappedFilePath(pid int32, start, end uint64) string {
	return fmt.Sprintf("/proc/%d/map_files/%x-%x", pid, start, end)
}

func (w *httpUprobeWorker) deleteDiscoveryCacheEntry(key httpDiscoveryKey) error {
	if w.discoveryCache == nil {
		return nil
	}
	err := w.discoveryCache.Delete(key)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (w *httpUprobeWorker) cacheDiscoveryFile(key httpDiscoveryKey) {
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

// Reclaim uses a coherent snapshot of tracking owners, never process maps.
// A missing owner cannot reappear: numbers are never reused, and inheritance
// needs an existing member. The tracking stamp also covers in-flight inheritance.
func (w *httpUprobeWorker) reconcileTargets(ctx context.Context) {
	if ctx.Err() != nil || w.tracking == nil {
		return
	}
	owners, err := w.tracking.httpOwners()
	if err != nil {
		return
	} // Changing or unreadable map: fail-keep.
	for key, target := range w.attachedTargets {
		if _, live := owners[key.owner]; live {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if len(w.preparationRequests) > 0 || len(w.attachCandidates) > 0 {
			w.queueTargetReconciliation()
			return
		}
		start := time.Now()
		closeLinks(target.links)
		delete(w.attachedTargets, key)
		if w.logger != nil {
			w.logger.Debug("http_uprobe_target_closed", "owner", key.owner, "elapsed", time.Since(start))
		}
	}
	// Includes negative classifications and notifications abandoned at teardown.
	if w.discoveryCache == nil {
		return
	}
	var key bpfprog.BPFProgramHttpDiscoveryKey
	var value uint8
	var expired []bpfprog.BPFProgramHttpDiscoveryKey
	it := w.discoveryCache.Iterate()
	for it.Next(&key, &value) {
		if _, live := owners[key.Owner]; !live {
			expired = append(expired, key)
		}
	}
	if it.Err() != nil {
		return
	}
	for _, key := range expired {
		_ = w.discoveryCache.Delete(key)
	}
}

func (w *httpUprobeWorker) ownerActive(cgroupID, owner uint64) bool {
	return owner != 0 && w.tracking != nil && w.tracking.httpOwner(cgroupID) == owner
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

// parseExecMapping extracts only the address range needed to open map_files.
// Its FD is verified against the BPF backing identity by prepareFile; the
// overlay-visible device/inode fields in /proc/maps are not identity inputs.
// /proc/<pid>/maps line: "start-end perms offset dev inode pathname".
func parseExecMapping(line string) (start, end uint64, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 || len(fields[1]) < 3 || fields[1][2] != 'x' ||
		fields[4] == "0" || strings.HasPrefix(fields[5], "[") {
		return 0, 0, false
	}
	startText, endText, found := strings.Cut(fields[0], "-")
	if !found {
		return 0, 0, false
	}
	start, err := strconv.ParseUint(startText, 16, 64)
	if err != nil {
		return 0, 0, false
	}
	end, err = strconv.ParseUint(endText, 16, 64)
	if err != nil || end <= start {
		return 0, 0, false
	}
	return start, end, true
}
