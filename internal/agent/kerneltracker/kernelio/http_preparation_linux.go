//go:build linux

package kernelio

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/cgroupfs"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	httpPreparationQueueSize = 8
	// The existing discovery map also distinguishes completed negative results
	// from value 1, which can mean a mapping notification is still queued.
	httpDiscoveryNegative = uint8(2)
)

var errHTTPPreparationQueueFull = errors.New("HTTP preparation queue full")
var errHTTPPreparationStopped = errors.New("HTTP preparation worker stopped")
var errHTTPTrackingEnded = errors.New("HTTP cgroup tracking ended")
var errHTTPMappedBackingChanged = errors.New("HTTP mapped backing changed")

type httpPreparationRequest struct {
	cgroupID, owner uint64
	ctx             context.Context
	files           []*os.File
	source          string
	submitted       time.Time
	done            chan error
}

func closePreparationFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}

// PrepareHTTPFiles adopts the descriptors even when HTTP preparation is disabled.
// The caller's deadline bounds waiting, not an in-flight filesystem syscall.
func (k *LinuxKernelIO) PrepareHTTPFiles(ctx context.Context, files []*os.File, source string, membership *os.File) error {
	if membership == nil {
		closePreparationFiles(files)
		return errors.New("HTTP cgroup membership FD missing")
	}
	defer membership.Close()
	if k.httpUprobeWorker == nil || k.httpUprobeWorker.control == nil {
		closePreparationFiles(files)
		return ErrNotSupported
	}
	cgroupID, err := cgroupfs.ID(membership, k.httpUprobeWorker.cgroupRootPath)
	if err != nil {
		closePreparationFiles(files)
		return err
	}
	return k.httpUprobeWorker.submitPreparation(ctx, files, source, cgroupID)
}

func (w *httpUprobeWorker) submitPreparation(ctx context.Context, files []*os.File, source string, cgroupID uint64) error {
	if len(files) > MaxHTTPPreparationFiles {
		closePreparationFiles(files)
		return errors.New("HTTP preparation file cap")
	}
	if err := ctx.Err(); err != nil {
		closePreparationFiles(files)
		return err
	}
	// The descriptors are adopted, but the caller may reuse its slice after a
	// timeout. Keep our own bounded slice until the worker finishes cleanup.
	owner := uint64(0)
	if w.tracking != nil {
		owner = w.tracking.httpOwner(cgroupID)
	}
	if owner == 0 {
		closePreparationFiles(files)
		return errHTTPTrackingEnded
	}
	r := &httpPreparationRequest{
		cgroupID: cgroupID, owner: owner,
		ctx:       ctx,
		files:     slices.Clone(files),
		source:    source,
		submitted: time.Now(),
		done:      make(chan error, 1),
	}
	w.submissionMu.Lock()
	var err error
	var dropped uint64
	if w.stopped {
		err = errHTTPPreparationStopped
	} else {
		select {
		case w.preparationRequests <- r:
		default:
			err = errHTTPPreparationQueueFull
			w.preparationDrops++
			dropped = w.preparationDrops
		}
	}
	w.submissionMu.Unlock()
	if dropped != 0 && dropped&(dropped-1) == 0 {
		w.logInfo("http_uprobe_preparation_queue_full", "dropped_total", dropped)
	}
	if err != nil {
		closePreparationFiles(files)
		return err
	}
	select {
	case reply := <-r.done:
		return reply
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *httpUprobeWorker) shutdownPreparation() {
	w.submissionMu.Lock()
	if w.stopped {
		w.submissionMu.Unlock()
		return
	}
	w.stopped = true
	w.submissionMu.Unlock()
	for {
		select {
		case r := <-w.preparationRequests:
			closePreparationFiles(r.files)
			r.done <- errHTTPPreparationStopped
		default:
			return
		}
	}
}

func (w *httpUprobeWorker) prepareRequest(workerCtx context.Context, r *httpPreparationRequest) {
	start := time.Now()
	var preparedCount, skippedCount, failedCount int
	var firstErr error
	defer func() {
		closePreparationFiles(r.files)
		r.done <- firstErr
	}()
	for _, f := range r.files {
		if err := errors.Join(r.ctx.Err(), workerCtx.Err()); err != nil {
			firstErr = errors.Join(firstErr, err)
			break
		}
		prepared, err := w.prepareFile(r.ctx, f, nil, r.cgroupID, r.owner)
		if err != nil {
			failedCount++
			if firstErr == nil {
				firstErr = err
			}
		} else if prepared {
			preparedCount++
		} else {
			skippedCount++
		}
	}
	if w.logger != nil {
		w.logger.Debug("http_uprobe_preparation", "source", r.source, "files", len(r.files), "prepared", preparedCount, "skipped", skippedCount, "failed", failedCount, "queue_wait", start.Sub(r.submitted), "elapsed", time.Since(r.submitted), "error", firstErr,
			"targets", len(w.attachedTargets), "queue_depth", len(w.preparationRequests))
	}
}

func (w *httpUprobeWorker) classifyAndAttach(candidate httpUprobeAttachCandidate) {
	key := httpDiscoveryKey{candidate.owner, candidate.file}
	if !w.ownerActive(candidate.cgroupID, candidate.owner) {
		_ = w.deleteDiscoveryCacheEntry(key)
		return
	}
	if a := w.attachedTargets[httpTargetKey{candidate.owner, candidate.file.mappedFile}]; a != nil && a.classificationKey == key {
		w.cacheDiscoveryFile(key)
		return
	}
	f, err := w.openMappedFile(candidate)
	if err == nil {
		_, err = w.prepareFile(context.Background(), f, &candidate.file, candidate.cgroupID, candidate.owner)
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
func (w *httpUprobeWorker) prepareFile(ctx context.Context, f *os.File, expected *fileClassificationKey, cgroupID, owner uint64) (bool, error) {
	if !w.ownerActive(cgroupID, owner) {
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
	if w.control == nil {
		return false, ErrNotSupported
	}
	data, id, err := w.control.mapFile(f)
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
	key := httpDiscoveryKey{owner, id}
	targetKey := httpTargetKey{owner, id.mappedFile}
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
			l, err := ex.Uprobe("", target.program, &link.UprobeOptions{Address: target.offset, Cookie: owner})
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
	data, current, err := w.control.mapFile(currentFile)
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
	if !w.ownerActive(cgroupID, owner) {
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
