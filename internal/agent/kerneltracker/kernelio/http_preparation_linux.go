//go:build linux

package kernelio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	// Classification I/O cap; independent of the number of adopted descriptors.
	maxPreparedFileBytes = 256 << 20
	// Lifetime limits: fixed machine inventory versus runtime preparation grace.
	maxPinnedHTTPTargets = 128
	httpPreparationGrace = 30 * time.Second
	// The existing discovery map also distinguishes completed negative results
	// from value 1, which can mean a mapping notification is still queued.
	httpDiscoveryNegative = uint8(2)
)

var errHTTPPreparationQueueFull = errors.New("HTTP preparation queue full")
var errHTTPPreparationStopped = errors.New("HTTP preparation worker stopped")
var errHTTPMappedBackingChanged = errors.New("HTTP mapped backing changed")

type httpPreparationRequest struct {
	ctx       context.Context
	files     []*os.File
	options   HTTPPreparationOptions
	submitted time.Time
	done      chan error
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
func (k *LinuxKernelIO) PrepareHTTPFiles(ctx context.Context, files []*os.File, options HTTPPreparationOptions) error {
	if k.httpUprobeWorker == nil || k.httpUprobeWorker.control == nil {
		closePreparationFiles(files)
		return ErrNotSupported
	}
	return k.httpUprobeWorker.submitPreparation(ctx, files, options)
}

func (w *httpUprobeWorker) submitPreparation(ctx context.Context, files []*os.File, options HTTPPreparationOptions) error {
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
	r := &httpPreparationRequest{
		ctx:       ctx,
		files:     slices.Clone(files),
		options:   options,
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
	for i, f := range r.files {
		if err := r.ctx.Err(); err != nil {
			firstErr = errors.Join(firstErr, err)
			closePreparationFiles(r.files[i:])
			break
		}
		if err := workerCtx.Err(); err != nil {
			firstErr = errors.Join(firstErr, err)
			closePreparationFiles(r.files[i:])
			break
		}
		prepared, err := w.prepareFile(r.ctx, f, nil, r.options.Pin)
		if f != nil {
			_ = f.Close()
		}
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
		// A preparation batch cannot starve already-queued mapping discovery.
		select {
		case candidate := <-w.attachCandidates:
			w.classifyAndAttach(candidate)
		default:
		}
	}
	if w.logger != nil {
		w.logger.Debug("http_uprobe_preparation", "source", r.options.Source, "files", len(r.files), "prepared", preparedCount, "skipped", skippedCount, "failed", failedCount, "queue_wait", start.Sub(r.submitted), "elapsed", time.Since(r.submitted), "error", firstErr,
			"targets", len(w.attachedTargets), "pinned", w.pinnedTargets, "queue_depth", len(w.preparationRequests), "normalized_total", w.normalizedFiles, "parsed_total", w.parsedFiles, "attached_total", w.newlyAttachedFiles, "deduplicated_total", w.deduplicatedFiles)
	}
	r.done <- firstErr
}

func (w *httpUprobeWorker) classifyAndAttach(candidate httpUprobeAttachCandidate) {
	if a := w.attachedTargets[candidate.file.mappedFile]; a != nil {
		if w.control == nil && a.classificationKey != candidate.file {
			// Preserve the compatibility path's existing inode links while old
			// mappings remain live; only refresh their discovery generation hint.
			if err := w.deleteDiscoveryCacheEntry(a.classificationKey); err != nil {
				w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "discovery_cache_delete", "error", err)
			}
			a.classificationKey = candidate.file
		}
		if a.classificationKey == candidate.file {
			w.deduplicatedFiles++
			w.cacheDiscoveryFile(candidate.file)
			return
		}
	}
	f, err := w.openMappedFile(candidate)
	if err == nil {
		_, err = w.prepareFile(context.Background(), f, &candidate.file, false)
		_ = f.Close()
	}
	if err != nil {
		if cacheErr := w.deleteDiscoveryCacheEntry(candidate.file); cacheErr != nil {
			w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "discovery_cache_delete", "error", cacheErr)
		}
		switch {
		case errors.Is(err, errHTTPMappedBackingChanged):
			w.warnThrottled(&w.identityMismatch, "http_uprobe_discovery_identity_mismatch")
		case errors.Is(err, os.ErrPermission):
			w.warnThrottled(&w.permDenied, "http_uprobe_discovery_permission_denied", "op", "prepare_mapped_file")
		case !processIsGone(err):
			w.warnThrottled(&w.opErrors, "http_uprobe_discovery_unexpected_error", "op", "prepare_mapped_file", "error", err)
		}
	}
}

// prepareFile is the shared attachment path for normalized proactive and
// mapped FDs. It owns the temporary mapping/links; its caller owns the input FD.
func (w *httpUprobeWorker) prepareFile(ctx context.Context, f *os.File, expected *fileClassificationKey, pin bool) (bool, error) {
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
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPreparedFileBytes {
		return false, errors.New("HTTP preparation file type or size unsupported")
	}
	var reader io.ReaderAt = f
	var id fileClassificationKey
	if w.control != nil {
		var data []byte
		data, id, err = w.control.mapFile(f, int(info.Size()))
		if err != nil {
			return false, fmt.Errorf("normalize HTTP target: %w", err)
		}
		defer unix.Munmap(data)
		// Overlay pread can switch to a copied-up file. Classify the normalized
		// mapping, including negative results that never reach register verification.
		reader = mappedFileReader{data: data}
		w.normalizedFiles++
	} else {
		id, err = classificationKeyFromFile(f)
		if err != nil {
			return false, err
		}
	}
	if expected != nil && *expected != id {
		return false, errHTTPMappedBackingChanged
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if a := w.attachedTargets[id.mappedFile]; a != nil {
		if a.classificationKey != id {
			return false, errors.New("HTTP live target generation changed")
		}
		if err = w.retainPreparedTarget(a, pin, expected == nil); err != nil {
			return false, err
		}
		w.cacheDiscoveryFile(id)
		w.deduplicatedFiles++
		return true, nil
	}
	var cached uint8
	if w.discoveryCache != nil && w.discoveryCache.Lookup(id, &cached) == nil && cached == httpDiscoveryNegative {
		return false, nil
	}
	if len(w.attachedTargets) >= maxAttachedUprobeTargets {
		w.warnThrottled(&w.capReached, "http_uprobe_target_cap_reached", "targets", len(w.attachedTargets))
		return false, errors.New("HTTP attached target cap")
	}
	if pin && w.pinnedTargets >= maxPinnedHTTPTargets {
		return false, errors.New("HTTP pinned target cap")
	}
	w.parsedFiles++
	selected, definitive, err := definedSymbolTargets(reader, w.symbolTargets)
	if err != nil {
		return false, err
	}
	if !definitive {
		return false, errors.New("inconclusive HTTP target ELF")
	}
	if len(selected) == 0 {
		offset, found, err := resolveGoFunctionOffset(reader, w.goTarget.function)
		if err != nil && !errors.Is(err, errUnsupportedGoPclntab) {
			return false, err
		}
		if found {
			selected = append(selected, symbolUprobeTarget{offset: offset, program: w.goTarget.program})
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if len(selected) == 0 {
		if w.discoveryCache != nil {
			if err := w.discoveryCache.Put(id, httpDiscoveryNegative); err != nil {
				return false, err
			}
		}
		return false, nil
	}
	ex, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	if err != nil {
		return false, err
	}
	var links []link.Link
	committed := false
	defer func() {
		if !committed {
			closeLinks(links)
		}
	}()
	for _, target := range selected {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		var l link.Link
		if w.control != nil {
			l, err = w.control.attach(ex, target.program, target.offset, id)
		} else {
			l, err = ex.Uprobe("", target.program, &link.UprobeOptions{Address: target.offset})
		}
		if err != nil {
			return false, err
		}
		links = append(links, l)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	a := &attachedUprobeTarget{classificationKey: id, links: links}
	if err = w.retainPreparedTarget(a, pin, expected == nil); err != nil {
		return false, err
	}
	w.attachedTargets[id.mappedFile] = a
	w.newlyAttachedFiles++
	w.cacheDiscoveryFile(id)
	committed = true
	return true, nil
}

func (w *httpUprobeWorker) retainPreparedTarget(a *attachedUprobeTarget, pin, proactive bool) error {
	if pin && !a.pinned {
		if w.pinnedTargets >= maxPinnedHTTPTargets {
			return errors.New("HTTP pinned target cap")
		}
		a.pinned = true
		w.pinnedTargets++
	}
	if proactive {
		a.protectedUntil = time.Now().Add(httpPreparationGrace)
		a.missingScanCount = 0
	}
	return nil
}
