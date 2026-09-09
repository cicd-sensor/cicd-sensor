//go:build linux

package kernelio

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	maxPreparedFileBytes = 256 << 20
	maxPinnedHTTPTargets = 128
	httpPreparationGrace = 30 * time.Second
	// The existing discovery map also distinguishes completed negative results
	// from value 1, which can mean a mapping notification is still queued.
	httpDiscoveryNegative = uint8(2)
)

var errHTTPPreparationQueueFull = errors.New("HTTP preparation queue full")
var errHTTPPreparationStopped = errors.New("HTTP preparation worker stopped")
var errHTTPMappedBackingChanged = errors.New("HTTP mapped backing changed")

type httpPreparationReply struct {
	result HTTPPreparationResult
	err    error
}
type httpPreparationRequest struct {
	ctx       context.Context
	files     []*os.File
	options   HTTPPreparationOptions
	submitted time.Time
	done      chan httpPreparationReply
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
func (k *LinuxKernelIO) PrepareHTTPFiles(ctx context.Context, files []*os.File, options HTTPPreparationOptions) (HTTPPreparationResult, error) {
	if k.httpUprobeWorker == nil || k.httpUprobeWorker.control == nil {
		closePreparationFiles(files)
		return HTTPPreparationResult{}, ErrNotSupported
	}
	return k.httpUprobeWorker.submitPreparation(ctx, files, options)
}
func (w *httpUprobeWorker) submitPreparation(ctx context.Context, files []*os.File, options HTTPPreparationOptions) (HTTPPreparationResult, error) {
	if len(files) > MaxHTTPPreparationFiles {
		closePreparationFiles(files)
		return HTTPPreparationResult{}, errors.New("HTTP preparation file cap")
	}
	if err := ctx.Err(); err != nil {
		closePreparationFiles(files)
		return HTTPPreparationResult{}, err
	}
	// The descriptors are adopted, but the caller may reuse its slice after a
	// timeout. Keep our own bounded slice until the worker finishes cleanup.
	r := &httpPreparationRequest{
		ctx:       ctx,
		files:     slices.Clone(files),
		options:   options,
		submitted: time.Now(),
		done:      make(chan httpPreparationReply, 1),
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
		return HTTPPreparationResult{}, err
	}
	select {
	case reply := <-r.done:
		return reply.result, reply.err
	case <-ctx.Done():
		return HTTPPreparationResult{}, ctx.Err()
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
			r.done <- httpPreparationReply{err: errHTTPPreparationStopped}
		default:
			return
		}
	}
}
func (w *httpUprobeWorker) prepareRequest(workerCtx context.Context, r *httpPreparationRequest) {
	start := time.Now()
	var result HTTPPreparationResult
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
			result.Failed++
			if firstErr == nil {
				firstErr = err
			}
		} else if prepared {
			result.Prepared++
		} else {
			result.Skipped++
		}
		// A preparation batch cannot starve already-queued mapping discovery.
		select {
		case candidate := <-w.attachCandidates:
			w.classifyAndAttach(candidate)
		default:
		}
	}
	w.logInfo("http_uprobe_preparation", "source", r.options.Source, "files", len(r.files), "prepared", result.Prepared, "skipped", result.Skipped, "failed", result.Failed, "queue_wait", start.Sub(r.submitted), "elapsed", time.Since(r.submitted), "error", firstErr)
	w.logInfo("http_uprobe_preparation_state", "targets", len(w.attachedTargets), "pinned", w.pinnedTargets, "queue_depth", len(w.preparationRequests), "normalized_total", w.normalizedFiles, "parsed_total", w.parsedFiles, "attached_total", w.newlyAttachedFiles, "deduplicated_total", w.deduplicatedFiles)
	r.done <- httpPreparationReply{result: result, err: firstErr}
}
func (w *httpUprobeWorker) prepareMappedCandidate(candidate httpUprobeAttachCandidate) {
	// Registry/cache fast path is safe only for the same generation hint.
	if a := w.attachedTargets[candidate.file.mappedFile]; a != nil && a.classificationKey == candidate.file {
		w.deduplicatedFiles++
		w.cacheDiscoveryFile(candidate.file)
		return
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
	data, id, err := w.control.mapFile(f, int(info.Size()))
	if err != nil {
		return false, fmt.Errorf("normalize HTTP target: %w", err)
	}
	defer unix.Munmap(data)
	w.normalizedFiles++
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
		return false, errors.New("HTTP attached target cap")
	}
	if pin && w.pinnedTargets >= maxPinnedHTTPTargets {
		return false, errors.New("HTTP pinned target cap")
	}
	reader := mappedFileReader{data: data}
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
		if err != nil {
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
		l, err := w.control.attach(ex, target.program, target.offset, id)
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
