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
	"github.com/cilium/ebpf/ringbuf"
)

const ringbufDropPollInterval = 5 * time.Second

// StartKernelSampleLoop reads kernel ringbuf samples and delivers raw samples.
func (kernelIO *LinuxKernelIO) StartKernelSampleLoop(ctx context.Context, handle KernelSampleHandler) error {
	if kernelIO.reader == nil {
		return errors.New("ringbuf reader is not initialized")
	}
	if kernelIO.httpUprobeWorker != nil && kernelIO.httpUprobeAttachCandidateReader == nil {
		return errors.New("HTTP uprobe attach-candidate ringbuf reader is not initialized")
	}
	if handle == nil {
		return errors.New("raw sample handler is nil")
	}

	loopCtx, cancelLoop := context.WithCancel(ctx)
	kernelIO.cancelLoop = cancelLoop

	if kernelIO.httpUprobeWorker != nil {
		kernelIO.loopWG.Go(func() {
			kernelIO.httpUprobeWorker.run(loopCtx)
		})
		kernelIO.loopWG.Go(func() {
			kernelIO.readHTTPUprobeAttachCandidates(loopCtx)
		})
	}
	kernelIO.loopWG.Go(func() {
		<-loopCtx.Done()

		if err := kernelIO.closeReader(); err != nil {
			kernelIO.logger.WarnContext(loopCtx, "bpf_reader_close_failed", "error", err)
		}
		if err := kernelIO.closeHTTPUprobeAttachCandidateReader(); err != nil {
			kernelIO.logger.WarnContext(loopCtx, "http_uprobe_attach_candidate_reader_close_failed", "error", err)
		}
	})

	kernelIO.loopWG.Go(func() {
		var record ringbuf.Record
		for {
			if err := kernelIO.reader.ReadInto(&record); err != nil {
				switch {
				case errors.Is(err, io.EOF), errors.Is(err, ringbuf.ErrClosed), errors.Is(err, os.ErrClosed):
					return
				case errors.Is(err, context.Canceled):
					return
				default:
					kernelIO.logger.WarnContext(ctx, "bpf_reader_failed", "error", err)
					return
				}
			}
			if err := handle(loopCtx, KernelSample(record.RawSample)); err != nil {
				if loopCtx.Err() != nil {
					return
				}
				kernelIO.logger.WarnContext(loopCtx, "bpf_event_handle_failed", "error", err)
				continue
			}
		}
	})

	kernelIO.loopWG.Go(func() {
		kernelIO.watchRingbufDrops(loopCtx)
	})

	return nil
}

func (kernelIO *LinuxKernelIO) readHTTPUprobeAttachCandidates(ctx context.Context) {
	var record ringbuf.Record
	for {
		if err := kernelIO.httpUprobeAttachCandidateReader.ReadInto(&record); err != nil {
			switch {
			case errors.Is(err, io.EOF), errors.Is(err, ringbuf.ErrClosed), errors.Is(err, os.ErrClosed):
				return
			case errors.Is(err, context.Canceled):
				return
			default:
				kernelIO.failHTTPUprobeDiscovery(fmt.Errorf("read attach candidate: %w", err))
				return
			}
		}
		if err := kernelIO.handleHTTPUprobeAttachCandidate(ctx, record.RawSample); err != nil {
			return
		}
	}
}

// failHTTPUprobeDiscovery stops new SIGSTOP requests. The worker's periodic
// lease sweep resumes any process whose candidate could not be consumed.
func (kernelIO *LinuxKernelIO) failHTTPUprobeDiscovery(cause error) {
	kernelIO.httpUprobeDiscoveryMu.Lock()
	if kernelIO.httpUprobeDiscoveryFailed {
		kernelIO.httpUprobeDiscoveryMu.Unlock()
		return
	}
	kernelIO.httpUprobeDiscoveryFailed = true
	discoveryLink := kernelIO.httpUprobeDiscoveryLink
	kernelIO.httpUprobeDiscoveryLink = nil
	kernelIO.httpUprobeDiscoveryMu.Unlock()

	if kernelIO.logger != nil {
		kernelIO.logger.Error("http_uprobe_discovery_disabled", "error", cause)
	}
	if discoveryLink != nil {
		if err := discoveryLink.Close(); err != nil {
			if kernelIO.logger != nil {
				kernelIO.logger.Error("http_uprobe_discovery_link_close_failed", "error", err)
			}
		}
	}
}

func (kernelIO *LinuxKernelIO) takeHTTPUprobeDiscoveryLink() link.Link {
	kernelIO.httpUprobeDiscoveryMu.Lock()
	defer kernelIO.httpUprobeDiscoveryMu.Unlock()
	discoveryLink := kernelIO.httpUprobeDiscoveryLink
	kernelIO.httpUprobeDiscoveryLink = nil
	return discoveryLink
}

func (kernelIO *LinuxKernelIO) watchRingbufDrops(ctx context.Context) {
	ticker := time.NewTicker(ringbufDropPollInterval)
	defer ticker.Stop()

	// Ringbuf drops happen before samples can be attributed to a Job. Keep
	// them as agent-wide audit signals; do not fold them into Job events_dropped.
	var dropWarnings ringbufDropWarnState
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		total, err := kernelIO.readRingbufDropCount()
		if err != nil {
			kernelIO.logger.WarnContext(ctx, "bpf_ringbuf_drop_count_read_failed", "error", err)
			continue
		}
		dropped, ok := dropWarnings.shouldWarn(total)
		if !ok {
			continue
		}

		kernelIO.logger.WarnContext(ctx, "bpf_ringbuf_drop",
			"dropped", dropped,
			"total", total,
		)
	}
}

type ringbufDropWarnState struct {
	lastWarnTotal uint64
	nextWarnTotal uint64
}

func (state *ringbufDropWarnState) shouldWarn(total uint64) (uint64, bool) {
	if total == 0 || total <= state.lastWarnTotal {
		return 0, false
	}
	if state.nextWarnTotal != 0 && total < state.nextWarnTotal {
		return 0, false
	}

	dropped := total - state.lastWarnTotal
	state.lastWarnTotal = total
	state.nextWarnTotal = nextRingbufDropWarnTotal(total)
	return dropped, true
}

func nextRingbufDropWarnTotal(total uint64) uint64 {
	if total == ^uint64(0) {
		return total
	}
	return roundUpToPowerOfTwo(total + 1)
}

func (kernelIO *LinuxKernelIO) readRingbufDropCount() (uint64, error) {
	if kernelIO.objs.RingbufDropCount == nil {
		return 0, errors.New("ringbuf drop count map is not initialized")
	}

	var perCPU []uint64
	if err := kernelIO.objs.RingbufDropCount.Lookup(uint32(0), &perCPU); err != nil {
		return 0, fmt.Errorf("lookup ringbuf drop count: %w", err)
	}

	var total uint64
	for _, count := range perCPU {
		total += count
	}
	return total, nil
}

// Close releases the ring buffer reader, tracing links, and loaded objects.
func (kernelIO *LinuxKernelIO) Close() error {
	if kernelIO == nil {
		return nil
	}

	var firstErr error
	if discoveryLink := kernelIO.takeHTTPUprobeDiscoveryLink(); discoveryLink != nil {
		if err := discoveryLink.Close(); err != nil {
			firstErr = err
		}
	}

	if kernelIO.cancelLoop != nil {
		kernelIO.cancelLoop()
	}

	if err := kernelIO.closeReader(); err != nil {
		firstErr = err
	}
	if err := kernelIO.closeHTTPUprobeAttachCandidateReader(); err != nil {
		if firstErr == nil {
			firstErr = err
		} else {
			kernelIO.logger.Warn("http_uprobe_attach_candidate_reader_close_failed", "error", err)
		}
	}
	// Drain goroutines before closing map FDs; workers may still be using maps.
	kernelIO.loopWG.Wait()
	// Recover any lease whose hook invocation was already in flight when the
	// discovery link was detached.
	if kernelIO.httpUprobeWorker != nil {
		if err := recoverHTTPUprobeStopLeases(kernelIO.objs.HttpUprobeStopLeases); err != nil {
			if firstErr == nil {
				firstErr = err
			} else {
				kernelIO.logger.Warn("http_uprobe_stop_recovery_failed", "error", err)
			}
		} else if err := kernelIO.objs.HttpUprobeStopLeases.Unpin(); err != nil && !errors.Is(err, os.ErrNotExist) {
			if firstErr == nil {
				firstErr = err
			} else {
				kernelIO.logger.Warn("http_uprobe_stop_lease_unpin_failed", "error", err)
			}
		}
	}
	for _, attachedLink := range slices.Backward(kernelIO.links) {
		if err := attachedLink.Close(); err != nil {
			if firstErr == nil {
				firstErr = err
			} else {
				kernelIO.logger.Warn("bpf_link_close_failed", "error", err)
			}
		}
	}
	if err := kernelIO.objs.Close(); err != nil {
		if firstErr == nil {
			firstErr = err
		} else {
			kernelIO.logger.Warn("bpf_objects_close_failed", "error", err)
		}
	}

	return firstErr
}

func (kernelIO *LinuxKernelIO) closeReader() error {
	var closeErr error

	kernelIO.closeReaderOnce.Do(func() {
		if kernelIO.reader == nil {
			return
		}

		closeErr = kernelIO.reader.Close()
		if errors.Is(closeErr, os.ErrClosed) {
			closeErr = nil
		}
	})

	return closeErr
}

func (kernelIO *LinuxKernelIO) closeHTTPUprobeAttachCandidateReader() error {
	var closeErr error

	kernelIO.closeHTTPUprobeAttachCandidateReaderOnce.Do(func() {
		if kernelIO.httpUprobeAttachCandidateReader == nil {
			return
		}

		closeErr = kernelIO.httpUprobeAttachCandidateReader.Close()
		if errors.Is(closeErr, os.ErrClosed) {
			closeErr = nil
		}
	})

	return closeErr
}
