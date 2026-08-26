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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// http_uprobe_discovery.go — attach discovery and reclaim for HTTP uprobe taps.
//
// A single worker owns all attached targets and userspace updates to the
// non-target file map, so no locking. Mapping and reconcile requests only enter
// this worker; no caller reads this state. cgroup gates emission and scopes the
// scan, but does not own link lifetime.

type httpUprobeSymbol struct {
	name    string
	program *ebpf.Program
}

// maxAttachedUprobeTargets bounds attached targets. On cap the worker refuses new
// targets and never evicts a live one; reclaim keeps the steady state bounded,
// so the cap is reached only under adversarial fan-out.
const maxAttachedUprobeTargets = 4096

// mappingRequestQueueSize absorbs first-seen executable mapping bursts while
// symbol classification and uprobe attach run on the single owner worker.
const mappingRequestQueueSize = 4096

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

type httpUprobeMapping struct {
	tgid    int32
	vmStart uint64
	vmEnd   uint64
	file    fileClassificationKey
}

type processMapping struct {
	addressRange string
	mappedFile   mappedFileIdentity
}

// attachedUprobeTarget is one attached inode. It keeps only the links and the
// number of complete scans that have missed the inode since it was last seen.
type attachedUprobeTarget struct {
	links            []link.Link
	missingScanCount uint8
}

type httpUprobeDiscovery struct {
	symbols        []httpUprobeSymbol
	logger         *slog.Logger
	cgroupRootPath string

	// Worker inputs. run consumes both serially.
	mappingRequests   chan httpUprobeMapping // executable mappings decoded by the KernelIO reader
	reconcileRequests chan []uint64          // immutable active cgroup IDs from KernelTracker

	// Worker-owned state (single goroutine, no locking).
	attachedTargets map[mappedFileIdentity]*attachedUprobeTarget
	nonTargetFiles  *ebpf.Map

	// Throttled-warning counters. mappingQueueDropped is sample-reader-owned;
	// the others are worker-owned. Each counter is touched by one goroutine.
	mappingQueueDropped uint64
	permDenied          uint64
	opErrors            uint64
	identityMismatch    uint64
	capReached          uint64
}

func newHTTPUprobeDiscovery(
	symbols []httpUprobeSymbol,
	logger *slog.Logger,
	cgroupRootPath string,
	nonTargetFiles *ebpf.Map,
) *httpUprobeDiscovery {
	return &httpUprobeDiscovery{
		symbols:           symbols,
		logger:            logger,
		cgroupRootPath:    cgroupRootPath,
		mappingRequests:   make(chan httpUprobeMapping, mappingRequestQueueSize),
		reconcileRequests: make(chan []uint64, 1),
		attachedTargets:   make(map[mappedFileIdentity]*attachedUprobeTarget),
		nonTargetFiles:    nonTargetFiles,
	}
}

// queueTargetReconciliation hands the worker one immutable active-cgroup
// snapshot without blocking the KernelTracker loop. One pending sweep is enough;
// if it takes longer than the interval, the next ticker retries.
func (d *httpUprobeDiscovery) queueTargetReconciliation(activeCgroupIDs []uint64) {
	select {
	case d.reconcileRequests <- activeCgroupIDs:
	default:
	}
}

// QueueHTTPUprobeReconciliation hands the worker active cgroup IDs.
// No-op when HTTP uprobe capture is disabled.
func (kernelIO *LinuxKernelIO) QueueHTTPUprobeReconciliation(activeCgroupIDs []uint64) {
	if kernelIO.httpUprobeDiscovery == nil {
		return
	}
	kernelIO.httpUprobeDiscovery.queueTargetReconciliation(activeCgroupIDs)
}

// queueMapping schedules one mapping classification without blocking sample
// intake. A later process mapping the same file is a natural retry on overflow.
func (d *httpUprobeDiscovery) queueMapping(mapping httpUprobeMapping) {
	select {
	case d.mappingRequests <- mapping:
	default:
		d.warnThrottled(&d.mappingQueueDropped, "http_uprobe_mapping_request_dropped")
	}
}

// run processes scan and reconcile requests on one goroutine until ctx
// is cancelled, then closes every attached link. It is the sole owner of
// attachedTargets/nonTargetFiles; there is no separate closer goroutine.
func (d *httpUprobeDiscovery) run(ctx context.Context) {
	defer d.closeAll()
	for {
		select {
		case <-ctx.Done():
			return
		case activeCgroupIDs := <-d.reconcileRequests:
			d.reconcileTargets(activeCgroupIDs)
		case mapping := <-d.mappingRequests:
			d.classifyAndAttachMapping(mapping)
		}
	}
}

// scanProcessMappings returns the executable file mappings of pid. It returns
// false if an error could have hidden a live mapping; mappings read before the
// error are still returned as positive observations.
func (d *httpUprobeDiscovery) scanProcessMappings(pid int32) ([]processMapping, bool) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		// Only a gone pid (ENOENT) is the benign race; anything else could hide
		// a live mapping. Permission errors are surfaced (discovery is blind).
		if processIsGone(err) {
			return nil, true
		}
		if errors.Is(err, os.ErrPermission) {
			d.warnThrottled(&d.permDenied, "http_uprobe_discovery_permission_denied", "op", "open_maps")
		} else {
			d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "open_maps", "error", err)
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

// classifyAndAttachMapping verifies the kernel-provided file identity before
// using the mapped file. An identity mismatch is an ordinary mapping race and
// must not create either an attach or a negative-cache entry.
func (d *httpUprobeDiscovery) classifyAndAttachMapping(mapping httpUprobeMapping) {
	if _, attached := d.attachedTargets[mapping.file.mappedFile]; attached {
		return
	}
	if d.isKnownNonTarget(mapping.file) {
		return
	}
	if len(d.attachedTargets) >= maxAttachedUprobeTargets {
		d.warnThrottled(&d.capReached, "http_uprobe_target_cap_reached", "targets", len(d.attachedTargets))
		return
	}

	f, err := d.openMappedFile(mapping)
	if err != nil {
		if processIsGone(err) {
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

	actual, err := classificationKeyFromFile(f)
	if err != nil {
		d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "fstat", "error", err)
		return
	}
	if actual != mapping.file {
		d.warnThrottled(&d.identityMismatch, "http_uprobe_discovery_identity_mismatch")
		return
	}
	selected, definitive, err := definedHTTPUprobeSymbols(f, d.symbols)
	if err != nil {
		d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "classify_elf_symbols", "error", err)
		return
	}
	if len(selected) == 0 {
		if definitive {
			d.cacheNonTarget(mapping.file)
		}
		return
	}

	ex, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	if err != nil {
		d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "open_executable", "error", err)
		return
	}
	d.attachTarget(mapping.file, ex, selected)
}

func processIsGone(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH)
}

// openMappedFile first uses the completed VMA range from uprobe_mmap. A VMA
// can merge before userspace opens map_files, so ENOENT gets one current-maps
// lookup by device/inode. Other failures are returned unchanged.
func (d *httpUprobeDiscovery) openMappedFile(mapping httpUprobeMapping) (*os.File, error) {
	f, err := os.Open(mappedFilePath(mapping.tgid, mapping.vmStart, mapping.vmEnd))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return f, err
	}

	mappings, complete := d.scanProcessMappings(mapping.tgid)
	if !complete {
		return nil, err
	}
	for _, current := range mappings {
		if current.mappedFile == mapping.file.mappedFile {
			return os.Open(fmt.Sprintf("/proc/%d/map_files/%s", mapping.tgid, current.addressRange))
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

func (d *httpUprobeDiscovery) isKnownNonTarget(key fileClassificationKey) bool {
	if d.nonTargetFiles == nil {
		return false
	}
	var value uint8
	err := d.nonTargetFiles.Lookup(key, &value)
	switch {
	case err == nil:
		return true
	case errors.Is(err, ebpf.ErrKeyNotExist):
		return false
	default:
		d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "negative_cache_lookup", "error", err)
		return false
	}
}

func (d *httpUprobeDiscovery) cacheNonTarget(key fileClassificationKey) {
	if d.nonTargetFiles == nil {
		return
	}
	if err := d.nonTargetFiles.Put(key, uint8(1)); err != nil {
		d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "negative_cache_update", "error", err)
	}
}

// attachTarget attaches the program to the file's target symbols and records the
// outcome. Classification is conservative: only a definitive absence of all
// selected symbols is cached; attach failures remain retryable.
func (d *httpUprobeDiscovery) attachTarget(
	id fileClassificationKey,
	ex *link.Executable,
	targets []httpUprobeSymbol,
) {
	var got []link.Link
	for _, target := range targets {
		l, err := ex.Uprobe(target.name, target.program, nil)
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
			d.warnThrottled(&d.opErrors, "http_uprobe_discovery_unexpected_error", "op", "uprobe_attach", "symbol", target.name, "error", err)
			closeLinks(got)
			return
		}
	}
	if len(got) > 0 {
		d.attachedTargets[id.mappedFile] = &attachedUprobeTarget{links: got}
		return
	}
	// Every target symbol was definitively absent: safe to cache negative.
	d.cacheNonTarget(id)
}

func (d *httpUprobeDiscovery) closeAll() {
	for _, entry := range d.attachedTargets {
		closeLinks(entry.links)
	}
}

// reconcileTargets is the reclaim sweep. It resolves the immutable active-ID
// snapshot to current filesystem paths, then expands cgroup.procs and scans
// process maps. It only observes liveness; mapping-triggered discovery owns
// target classification and attach.
// Only detach is fail-keep: an incomplete scan never advances a missing
// count or closes links, though a target positively observed before an error is
// reset to zero. We do not retain the prior scan result; each attached target
// only records how many complete scans have omitted it.
func (d *httpUprobeDiscovery) reconcileTargets(activeCgroupIDs []uint64) {
	observedMappedFiles := make(map[mappedFileIdentity]struct{})
	activeCgroupPaths, complete := resolveActiveCgroupPaths(d.cgroupRootPath, activeCgroupIDs)
	pids := make(map[int32]struct{})
	for _, cgroupPath := range activeCgroupPaths {
		if !d.collectCgroupPIDs(cgroupPath, pids) {
			complete = false
		}
	}
	for pid := range pids {
		mappings, scanComplete := d.scanProcessMappings(pid)
		if !scanComplete {
			complete = false
		}
		for _, mapping := range mappings {
			observedMappedFiles[mapping.mappedFile] = struct{}{}
		}
	}

	closed := 0
	for mappedID, entry := range d.attachedTargets {
		if _, observed := observedMappedFiles[mappedID]; observed {
			entry.missingScanCount = 0
			continue
		}
		if !complete {
			continue
		}
		entry.missingScanCount++
		if entry.missingScanCount >= missingScanLimit {
			closeLinks(entry.links)
			delete(d.attachedTargets, mappedID)
			closed++
		}
	}

	// Summary only when something happened; an unchanged complete sweep is
	// silent (a 60 s unchanged line would be steady-state noise).
	if closed > 0 || !complete {
		d.logInfo("http_uprobe_reclaim",
			"complete", complete,
			"closed", closed,
			"targets", len(d.attachedTargets),
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
// saturated mapping queue — is visible without emitting one line per mapping. The
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
