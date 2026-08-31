//go:build linux

package kernelio

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
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
	program *ebpf.Program
}

type goUprobeTarget struct {
	function string
	program  *ebpf.Program
}

type httpUprobeWorkerBPF struct {
	discoveryCache   *ebpf.Map
	inodeResolutions *ebpf.Map
	reclaimTGIDs     *ebpf.Map
	vmaIterator      *ebpf.Program
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

const (
	discoveryCacheClassified uint8 = 2
)

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

type httpUprobePermissionRequest struct {
	file *os.File
	done chan struct{}
}

type processMapping struct {
	addressRange string
	mappedFile   mappedFileIdentity
}

// attachedUprobeTarget is one backing inode selected by uprobe_register.
// Multiple visible file views can lead to it, so reclaim removes every cache
// key associated with the one link set.
type attachedUprobeTarget struct {
	classificationKeys map[fileClassificationKey]struct{}
	links              []link.Link
	missingScanCount   uint8
}

type httpUprobeWorker struct {
	symbolTargets  []symbolUprobeTarget // OpenSSL/nghttp2, attached by ELF symbol
	goTarget       goUprobeTarget       // Go net/http, attached by resolved file offset
	logger         *slog.Logger
	cgroupRootPath string

	// Worker inputs. run consumes both serially.
	permissionRequests chan httpUprobePermissionRequest
	attachCandidates   chan httpUprobeAttachCandidate // candidates emitted by BPF and decoded by KernelIO
	reconcileRequests  chan []uint64                  // immutable active cgroup IDs from KernelTracker

	// Worker-owned userspace state (single goroutine, no locking). BPF maps are
	// concurrency-safe kernel objects shared with the hook and sample reader.
	attachedTargets  map[mappedFileIdentity]*attachedUprobeTarget
	discoveryCache   *ebpf.Map
	inodeResolutions *ebpf.Map
	reclaimTGIDs     *ebpf.Map
	vmaIterator      *ebpf.Program
	attachGeneration uint64

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
	bpfObjects httpUprobeWorkerBPF,
	goTarget goUprobeTarget,
) *httpUprobeWorker {
	return &httpUprobeWorker{
		symbolTargets:      symbolTargets,
		goTarget:           goTarget,
		logger:             logger,
		cgroupRootPath:     cgroupRootPath,
		permissionRequests: make(chan httpUprobePermissionRequest, 1),
		attachCandidates:   make(chan httpUprobeAttachCandidate, attachCandidateQueueSize),
		reconcileRequests:  make(chan []uint64, 1),
		attachedTargets:    make(map[mappedFileIdentity]*attachedUprobeTarget),
		discoveryCache:     bpfObjects.discoveryCache,
		inodeResolutions:   bpfObjects.inodeResolutions,
		reclaimTGIDs:       bpfObjects.reclaimTGIDs,
		vmaIterator:        bpfObjects.vmaIterator,
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
	defer func() {
		w.releasePendingPermissionRequests()
		w.closeAll()
	}()
	for {
		// Permission requests hold an exec open, so check them before ordinary
		// mmap backstop and reclaim work at every worker loop boundary.
		select {
		case request := <-w.permissionRequests:
			w.handlePermissionRequest(request)
			continue
		default:
		}

		select {
		case <-ctx.Done():
			return
		case request := <-w.permissionRequests:
			w.handlePermissionRequest(request)
		case activeCgroupIDs := <-w.reconcileRequests:
			w.reconcileTargets(activeCgroupIDs)
		case candidate := <-w.attachCandidates:
			w.classifyAndAttach(candidate)
		}
	}
}

// releasePendingPermissionRequests closes event-FD duplicates that were queued
// when shutdown won the worker select. Closing each done channel also releases
// its fanotify response waiter; the group itself is closed independently.
func (w *httpUprobeWorker) releasePendingPermissionRequests() {
	for {
		select {
		case request := <-w.permissionRequests:
			_ = request.file.Close()
			close(request.done)
		default:
			return
		}
	}
}

func (w *httpUprobeWorker) handlePermissionRequest(request httpUprobePermissionRequest) {
	defer close(request.done)
	defer request.file.Close()

	w.classifyOpenFile(request.file)
}

// scanProcessMappings returns the executable file mappings of pid. It returns
// false if an error could have hidden a live mapping; mappings read before the
// error are still returned as positive observations.
func (w *httpUprobeWorker) scanProcessMappings(pid int32) ([]processMapping, bool) {
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

// classifyAndAttach verifies the kernel-provided file identity before
// using the mapped file. An identity mismatch is an ordinary mapping race and
// must not create either an attach or a discovery-cache entry.
func (w *httpUprobeWorker) classifyAndAttach(candidate httpUprobeAttachCandidate) {
	retainCacheEntry := false
	defer func() {
		if retainCacheEntry {
			return
		}
		if err := w.deleteDiscoveryCacheEntry(candidate.file); err != nil {
			w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "discovery_cache_delete", "error", err)
		}
	}()

	f, err := w.openMappedFile(candidate)
	if err != nil {
		if processIsGone(err) {
			return
		}
		if errors.Is(err, os.ErrPermission) {
			w.warnThrottled(&w.permDenied, "http_uprobe_discovery_permission_denied", "op", "open_map_files")
		} else {
			w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "open_map_files", "error", err)
		}
		return
	}
	defer f.Close()

	actual, err := classificationKeyFromFile(f)
	if err != nil {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "fstat", "error", err)
		return
	}
	if actual != candidate.file {
		w.warnThrottled(&w.identityMismatch, "http_uprobe_discovery_identity_mismatch")
		return
	}
	// fanotify can classify the executable before this previously emitted mmap
	// candidate reaches the worker. The classified cache state covers positive
	// and negative results, so do not parse or attach the same file again.
	if state, ok := w.discoveryCacheState(candidate.file); ok && state == discoveryCacheClassified {
		retainCacheEntry = true
		return
	}
	retainCacheEntry = w.classifyOpenFileWithKey(f, candidate.file)
}

func (w *httpUprobeWorker) classifyOpenFile(f *os.File) bool {
	key, err := classificationKeyFromFile(f)
	if err != nil {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "fstat", "error", err)
		return false
	}

	if state, ok := w.discoveryCacheState(key); ok && state == discoveryCacheClassified {
		return true
	}
	// Do not create a pending entry on the fanotify path. If its bounded wait
	// expires, the subsequent mmap must remain able to emit the retry candidate.
	return w.classifyOpenFileWithKey(f, key)
}

func (w *httpUprobeWorker) classifyOpenFileWithKey(
	f *os.File,
	key fileClassificationKey,
) bool {
	// Both fanotify and mmap discovery converge here, so enforce the one global
	// link-registry cap before either path can create another target.
	if len(w.attachedTargets) >= maxAttachedUprobeTargets {
		w.warnThrottled(&w.capReached, "http_uprobe_target_cap_reached", "targets", len(w.attachedTargets))
		return false
	}

	selected, definitive, err := definedSymbolTargets(f, w.symbolTargets)
	if err != nil {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "classify_elf_symbols", "error", err)
		return false
	}
	if len(selected) > 0 {
		ex, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
		if err != nil {
			w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "open_executable", "error", err)
			return false
		}
		return w.attachSymbolTargets(key, ex, selected)
	}
	if !definitive {
		return false
	}

	goFunctionOffset, found, err := resolveGoFunctionOffset(f, w.goTarget.function)
	if err != nil {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "resolve_go_http_function", "error", err)
		if errors.Is(err, errUnsupportedGoPclntab) {
			w.cacheDiscoveryFile(key)
			return true
		}
		return false
	}
	if !found {
		w.cacheDiscoveryFile(key)
		return true
	}

	ex, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	if err != nil {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "open_executable", "error", err)
		return false
	}
	return w.attachGoNetHTTPTarget(key, ex, goFunctionOffset)
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
	w.cacheDiscoveryFileState(key, discoveryCacheClassified)
}

func (w *httpUprobeWorker) cacheDiscoveryFileState(key fileClassificationKey, state uint8) {
	if w.discoveryCache == nil {
		return
	}
	if err := w.discoveryCache.Put(key, state); err != nil {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "discovery_cache_update", "error", err)
	}
}

func (w *httpUprobeWorker) discoveryCacheState(key fileClassificationKey) (uint8, bool) {
	if w.discoveryCache == nil {
		return 0, false
	}
	var state uint8
	if err := w.discoveryCache.Lookup(key, &state); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "discovery_cache_lookup", "error", err)
		}
		return 0, false
	}
	return state, true
}

func (w *httpUprobeWorker) beginInodeResolution() (uint64, error) {
	if w.inodeResolutions == nil {
		return 0, nil
	}
	w.attachGeneration++
	if w.attachGeneration == 0 {
		w.attachGeneration++
	}
	generation := w.attachGeneration
	pending := bpfprog.BPFProgramUprobeInodeResolution{Generation: generation}
	if err := w.inodeResolutions.Put(uint32(os.Getpid()), pending); err != nil {
		return 0, err
	}
	return generation, nil
}

func (w *httpUprobeWorker) finishInodeResolution(
	generation uint64,
	fallback fileClassificationKey,
) (fileClassificationKey, error) {
	if w.inodeResolutions == nil {
		return fallback, nil
	}
	defer w.inodeResolutions.Delete(uint32(os.Getpid()))

	var observed bpfprog.BPFProgramUprobeInodeResolution
	if err := w.inodeResolutions.Lookup(uint32(os.Getpid()), &observed); err != nil {
		return fileClassificationKey{}, err
	}
	if observed.Resolved == 0 || observed.Generation != generation {
		return fileClassificationKey{}, errors.New("uprobe backing inode was not resolved")
	}
	return fileClassificationKey{
		mappedFile: mappedIdentityFromKernelDevice(observed.Device, observed.Inode),
		ctimeSec:   observed.CtimeSec,
		ctimeNsec:  observed.CtimeNsec,
	}, nil
}

func (w *httpUprobeWorker) cancelInodeResolution() {
	if w.inodeResolutions != nil {
		_ = w.inodeResolutions.Delete(uint32(os.Getpid()))
	}
}

func mappedIdentityFromKernelDevice(device, inode uint64) mappedFileIdentity {
	return mappedFileIdentity{
		deviceMajor: uint32(device >> 20),
		deviceMinor: uint32(device & ((1 << 20) - 1)),
		inode:       inode,
	}
}

func (w *httpUprobeWorker) recordAttachedTarget(
	candidateKey fileClassificationKey,
	canonicalKey fileClassificationKey,
	links []link.Link,
) {
	if existing, ok := w.attachedTargets[canonicalKey.mappedFile]; ok {
		closeLinks(links)
		if existing.classificationKeys == nil {
			existing.classificationKeys = make(map[fileClassificationKey]struct{})
		}
		existing.classificationKeys[candidateKey] = struct{}{}
		existing.classificationKeys[canonicalKey] = struct{}{}
		w.cacheDiscoveryFile(candidateKey)
		w.cacheDiscoveryFile(canonicalKey)
		return
	}

	keys := map[fileClassificationKey]struct{}{
		candidateKey: {},
		canonicalKey: {},
	}
	w.attachedTargets[canonicalKey.mappedFile] = &attachedUprobeTarget{
		classificationKeys: keys,
		links:              links,
	}
	w.cacheDiscoveryFile(candidateKey)
	w.cacheDiscoveryFile(canonicalKey)
}

// attachSymbolTargets attaches programs by ELF symbol name and records the
// outcome. Only a definitive absence is cached; attach failures remain retryable.
func (w *httpUprobeWorker) attachSymbolTargets(
	id fileClassificationKey,
	ex *link.Executable,
	targets []symbolUprobeTarget,
) (retainCacheEntry bool) {
	generation, err := w.beginInodeResolution()
	if err != nil {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "uprobe_inode_resolution_begin", "error", err)
		return false
	}
	resolutionPending := true
	defer func() {
		if resolutionPending {
			w.cancelInodeResolution()
		}
	}()

	var got []link.Link
	for _, target := range targets {
		l, err := ex.Uprobe(target.symbol, target.program, nil)
		switch {
		case err == nil:
			got = append(got, l)
		case errors.Is(err, link.ErrNoSymbol):
			// Only a missing symbol is a definitive non-target. ErrNotSupported
			// can also report an attach-backend failure and must remain retryable.
		default:
			// Inconclusive: do not cache. Undo partial attaches and retry later.
			// Unlike a plain "symbol absent", an unexpected attach failure is a
			// real signal, so surface it (throttled).
			w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "uprobe_attach", "symbol", target.symbol, "error", err)
			closeLinks(got)
			return false
		}
	}
	if len(got) > 0 {
		canonical, err := w.finishInodeResolution(generation, id)
		resolutionPending = false
		if err != nil {
			w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "uprobe_inode_resolution_finish", "error", err)
			closeLinks(got)
			return false
		}
		w.recordAttachedTarget(id, canonical, got)
		return true
	}
	w.cancelInodeResolution()
	resolutionPending = false
	// Every target symbol was definitively absent: keep it in the cache.
	w.cacheDiscoveryFile(id)
	return true
}

// attachGoNetHTTPTarget attaches by absolute ELF file offset because stripped
// Go binaries do not expose the selected function through ELF symbols. The
// caller resolves fileOffset from Go metadata before reaching this function.
func (w *httpUprobeWorker) attachGoNetHTTPTarget(
	id fileClassificationKey,
	ex *link.Executable,
	fileOffset uint64,
) bool {
	generation, err := w.beginInodeResolution()
	if err != nil {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "uprobe_inode_resolution_begin", "error", err)
		return false
	}
	attached, err := ex.Uprobe("", w.goTarget.program, &link.UprobeOptions{Address: fileOffset})
	if err != nil {
		w.cancelInodeResolution()
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "uprobe_attach", "symbol", w.goTarget.function, "error", err)
		return false
	}
	canonical, err := w.finishInodeResolution(generation, id)
	if err != nil {
		_ = attached.Close()
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "uprobe_inode_resolution_finish", "error", err)
		return false
	}
	w.recordAttachedTarget(id, canonical, []link.Link{attached})
	return true
}

func (w *httpUprobeWorker) closeAll() {
	for _, entry := range w.attachedTargets {
		closeLinks(entry.links)
	}
}

func (w *httpUprobeWorker) observedBackingFiles(
	pids map[int32]struct{},
) (map[mappedFileIdentity]struct{}, bool) {
	// Unit tests and non-Linux substitutes can omit the iterator objects. The
	// production constructor always supplies all three together.
	if w.reclaimTGIDs == nil || w.vmaIterator == nil {
		observed := make(map[mappedFileIdentity]struct{})
		complete := true
		for pid := range pids {
			mappings, scanComplete := w.scanProcessMappings(pid)
			if !scanComplete {
				complete = false
			}
			for _, mapping := range mappings {
				observed[mapping.mappedFile] = struct{}{}
			}
		}
		return observed, complete
	}

	if err := clearMap(w.reclaimTGIDs); err != nil {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "reclaim_tgid_clear", "error", err)
		return nil, false
	}
	defer clearMap(w.reclaimTGIDs)

	one := uint8(1)
	for pid := range pids {
		if pid <= 0 {
			continue
		}
		if err := w.reclaimTGIDs.Put(uint32(pid), one); err != nil {
			w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "reclaim_tgid_update", "error", err)
			return nil, false
		}
	}

	iterator, err := link.AttachIter(link.IterOptions{Program: w.vmaIterator})
	if err != nil {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "attach_vma_iterator", "error", err)
		return nil, false
	}
	defer iterator.Close()

	reader, err := iterator.Open()
	if err != nil {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "open_vma_iterator", "error", err)
		return nil, false
	}
	raw, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "read_vma_iterator", "error", readErr)
		return nil, false
	}
	if closeErr != nil {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "close_vma_iterator", "error", closeErr)
		return nil, false
	}

	recordSize := binary.Size(bpfprog.BPFProgramIteratedVmaInode{})
	if recordSize <= 0 || len(raw)%recordSize != 0 {
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "decode_vma_iterator", "bytes", len(raw))
		return nil, false
	}

	observed := make(map[mappedFileIdentity]struct{})
	decoder := bytes.NewReader(raw)
	for decoder.Len() > 0 {
		var record bpfprog.BPFProgramIteratedVmaInode
		if err := binary.Read(decoder, binary.LittleEndian, &record); err != nil {
			w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "decode_vma_iterator", "error", err)
			return observed, false
		}
		observed[mappedIdentityFromKernelDevice(record.Device, record.Inode)] = struct{}{}
	}
	return observed, true
}

func clearMap(m *ebpf.Map) error {
	var key uint32
	var value uint8
	iterator := m.Iterate()
	for iterator.Next(&key, &value) {
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return iterator.Err()
}

// reconcileTargets is the reclaim sweep. It resolves the immutable active-ID
// snapshot to current filesystem paths, then expands cgroup.procs and scans
// process maps. It only observes liveness; mapping-triggered discovery owns
// target classification and attach.
// Only detach is fail-keep: an incomplete scan never advances a missing
// count or closes links, though a target positively observed before an error is
// reset to zero. We do not retain the prior scan result; each attached target
// only records how many complete scans have omitted it.
func (w *httpUprobeWorker) reconcileTargets(activeCgroupIDs []uint64) {
	activeCgroupPaths, complete := resolveActiveCgroupPaths(w.cgroupRootPath, activeCgroupIDs)
	pids := make(map[int32]struct{})
	for _, cgroupPath := range activeCgroupPaths {
		if !w.collectCgroupPIDs(cgroupPath, pids) {
			complete = false
		}
	}
	observedMappedFiles, mappingScanComplete := w.observedBackingFiles(pids)
	if !mappingScanComplete {
		complete = false
	}

	closed := 0
	for mappedID, entry := range w.attachedTargets {
		if _, observed := observedMappedFiles[mappedID]; observed {
			entry.missingScanCount = 0
			continue
		}
		if !complete {
			continue
		}
		entry.missingScanCount++
		if entry.missingScanCount >= missingScanLimit {
			// Delete the discovery-cache entry first. If that fails, keep the link;
			// closing it would prevent a later mapping from requesting re-attach.
			cacheDeleted := true
			for key := range entry.classificationKeys {
				if err := w.deleteDiscoveryCacheEntry(key); err != nil {
					w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "discovery_cache_delete", "error", err)
					cacheDeleted = false
				}
			}
			if !cacheDeleted {
				continue
			}
			closeLinks(entry.links)
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
		w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "read_cgroup_procs", "error", err)
		return false
	}
	return complete
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
