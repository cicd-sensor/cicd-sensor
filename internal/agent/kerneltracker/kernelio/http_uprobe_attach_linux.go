//go:build linux

package kernelio

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Value 1 can also mean that a mapping notification is still queued.
const httpDiscoveryNegative = uint8(2)

var errHTTPTrackingEnded = errors.New("HTTP cgroup tracking ended")
var errHTTPMappedBackingChanged = errors.New("HTTP mapped backing changed")

func (w *httpUprobeWorker) classifyAndAttach(candidate httpUprobeAttachCandidate) {
	key := httpDiscoveryKey{candidate.rootCgroupID, candidate.file}
	if !w.rootActive(candidate.cgroupID, candidate.rootCgroupID) {
		_ = w.deleteDiscoveryCacheEntry(key)
		return
	}
	if a := w.attachedTargets[httpTargetKey{candidate.rootCgroupID, candidate.file.mappedFile}]; a != nil && a.classificationKey == key {
		w.cacheDiscoveryFile(key)
		return
	}
	f, err := w.openMappedFile(candidate)
	if err == nil {
		_, err = w.prepareFile(context.Background(), f, &candidate.file, candidate.cgroupID, candidate.rootCgroupID)
		_ = f.Close()
	}
	if err != nil {
		if cacheErr := w.deleteDiscoveryCacheEntry(key); cacheErr != nil {
			w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "discovery_cache_delete", "error", cacheErr)
		}
		switch {
		case errors.Is(err, errHTTPMappedBackingChanged):
			w.warnThrottled(&w.identityMismatch, "http_uprobe_discovery_identity_mismatch")
		case errors.Is(err, os.ErrPermission):
			w.warnThrottled(&w.permDenied, "http_uprobe_discovery_permission_denied", "op", "prepare_mapped_file")
		case !processIsGone(err) && !errors.Is(err, errHTTPTrackingEnded):
			w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "prepare_mapped_file", "error", err)
		}
	}
}

// prepareFile is the shared attachment path for normalized proactive and
// mapped FDs. It owns the temporary mapping/links; its caller owns the input FD.
func (w *httpUprobeWorker) prepareFile(ctx context.Context, f *os.File, expected *fileClassificationKey, cgroupID, rootCgroupID uint64) (bool, error) {
	if !w.rootActive(cgroupID, rootCgroupID) {
		return false, errHTTPTrackingEnded
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if f == nil {
		return false, errors.New("nil HTTP preparation file")
	}
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return false, errors.New("HTTP preparation file type or size unsupported")
	}
	if w.mmapRequests == nil {
		return false, ErrNotSupported
	}
	data, id, err := w.mapFile(f)
	if err != nil {
		return false, fmt.Errorf("normalize HTTP target: %w", err)
	}
	defer unix.Munmap(data)

	if expected != nil && *expected != id {
		return false, errHTTPMappedBackingChanged
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	key := httpDiscoveryKey{rootCgroupID, id}
	targetKey := httpTargetKey{rootCgroupID, id.mappedFile}
	if a := w.attachedTargets[targetKey]; a != nil {
		if a.classificationKey != key {
			return false, errors.New("HTTP live target generation changed")
		}
		w.cacheDiscoveryFile(key)
		return true, nil
	}
	var cached uint8
	if w.discoveryCache != nil && w.discoveryCache.Lookup(key, &cached) == nil && cached == httpDiscoveryNegative {
		return false, nil
	}
	if len(w.attachedTargets) >= maxAttachedUprobeTargets {
		w.warnThrottled(&w.capReached, "http_uprobe_target_cap_reached", "targets", len(w.attachedTargets))
		return false, errors.New("HTTP attached target cap")
	}

	selected, err := definedSymbolTargets(f, w.symbolTargets)
	if err != nil {
		return false, err
	}
	if len(selected) == 0 {
		offset, found, err := resolveGoFunctionOffset(f, goNetHTTPRoundTripFunction)
		if err != nil && !errors.Is(err, errUnsupportedGoPclntab) {
			return false, err
		}
		if found {
			selected = append(selected, symbolUprobeTarget{offset: offset, program: w.goProgram})
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	var links []link.Link
	committed := false
	defer func() {
		if !committed {
			closeLinks(links)
		}
	}()
	if len(selected) > 0 {
		ex, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
		if err != nil {
			return false, err
		}
		for _, target := range selected {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			l, err := ex.Uprobe("", target.program, &link.UprobeOptions{Address: target.offset, Cookie: rootCgroupID})
			if err != nil {
				return false, err
			}
			links = append(links, l)
		}
	}
	// Reopen after parsing and registration: overlay pread and uprobe lookup
	// can switch backing after copy-up, while mmap on the original FD cannot.
	// Reject before publishing either cache outcome; deferred close rolls back links.
	currentFile, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	if err != nil {
		return false, err
	}
	data, current, err := w.mapFile(currentFile)
	_ = currentFile.Close()
	if err != nil {
		return false, err
	}
	_ = unix.Munmap(data)
	if current != id {
		return false, errHTTPMappedBackingChanged
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !w.rootActive(cgroupID, rootCgroupID) {
		return false, errHTTPTrackingEnded
	}

	if len(selected) == 0 {
		if w.discoveryCache != nil {
			if err := w.discoveryCache.Put(key, httpDiscoveryNegative); err != nil {
				return false, err
			}
		}
		return false, nil
	}
	a := &attachedUprobeTarget{classificationKey: key, links: links}
	w.attachedTargets[targetKey] = a
	w.cacheDiscoveryFile(key)
	committed = true
	return true, nil
}
