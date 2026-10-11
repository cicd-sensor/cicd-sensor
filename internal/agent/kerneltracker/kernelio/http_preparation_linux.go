//go:build linux

package kernelio

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"
	"github.com/cicd-sensor/cicd-sensor/internal/cgroupfs"
)

const httpPreparationQueueSize = 8

var errHTTPPreparationQueueFull = errors.New("HTTP preparation queue full")

type httpPreparationRequest struct {
	ctx       context.Context
	process   httpprepare.Process
	submitted time.Time
	done      chan error
}

// PrepareHTTP queues a PID, never an open file. A timed-out or stopped worker
// therefore has no queued descriptors to reclaim. Waiting is always bounded.
func (k *LinuxKernelIO) PrepareHTTP(ctx context.Context, process httpprepare.Process) error {
	if k.httpUprobeWorker == nil || k.httpUprobeWorker.mmapRequests == nil {
		return ErrNotSupported
	}
	return k.httpUprobeWorker.submitPreparation(ctx, process)
}

func (w *httpUprobeWorker) submitPreparation(ctx context.Context, process httpprepare.Process) error {
	if err := process.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, httpprepare.Budget)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	r := &httpPreparationRequest{ctx: ctx, process: process, submitted: time.Now(), done: make(chan error, 1)}
	select {
	case w.preparationRequests <- r:
	default:
		return errHTTPPreparationQueueFull
	}
	select {
	case err := <-r.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *httpUprobeWorker) prepareRequest(workerCtx context.Context, r *httpPreparationRequest) {
	err := w.prepareProcess(workerCtx, r)
	r.done <- err
	if w.logger != nil {
		w.logger.Debug("http_uprobe_preparation", "pid", r.process.PID, "elapsed", time.Since(r.submitted), "error", err,
			"targets", len(w.attachedTargets), "queue_depth", len(w.preparationRequests))
	}
}

func (w *httpUprobeWorker) prepareProcess(workerCtx context.Context, r *httpPreparationRequest) error {
	if err := errors.Join(r.ctx.Err(), workerCtx.Err()); err != nil {
		return err
	}
	proc, err := r.process.OpenProc()
	if err != nil {
		return err
	}
	defer proc.Close()
	// Keep this proc directory open: later lookups must not resolve a reused PID.
	base := fmt.Sprintf("/proc/self/fd/%d", proc.Fd())
	membership, err := os.Open(base + "/cgroup")
	if err != nil {
		return err
	}
	cgroupID, err := cgroupfs.ID(membership, w.cgroupRootPath)
	_ = membership.Close()
	if err != nil {
		return err
	}
	rootCgroupID := uint64(0)
	if w.tracking != nil {
		rootCgroupID = w.tracking.httpRootCgroup(cgroupID)
	}
	if rootCgroupID == 0 {
		return errHTTPTrackingEnded
	}
	files, firstErr := httpprepare.OpenFiles(r.ctx, base+"/root")
	defer httpprepare.CloseFiles(files)
	for _, f := range files {
		if err := errors.Join(r.ctx.Err(), workerCtx.Err()); err != nil {
			return errors.Join(firstErr, err)
		}
		if _, err := w.prepareFile(r.ctx, f, nil, cgroupID, rootCgroupID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
