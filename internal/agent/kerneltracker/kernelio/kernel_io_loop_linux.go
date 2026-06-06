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

	"github.com/cilium/ebpf/ringbuf"
)

const ringbufDropPollInterval = 5 * time.Second

// StartKernelSampleLoop reads kernel ringbuf samples and delivers raw samples.
func (kernelIO *LinuxKernelIO) StartKernelSampleLoop(ctx context.Context, handle KernelSampleHandler) error {
	if kernelIO.reader == nil {
		return errors.New("ringbuf reader is not initialized")
	}
	if handle == nil {
		return errors.New("raw sample handler is nil")
	}

	loopCtx, cancelLoop := context.WithCancel(ctx)
	kernelIO.cancelLoop = cancelLoop

	kernelIO.loopWG.Add(3)
	go func() {
		defer kernelIO.loopWG.Done()
		<-loopCtx.Done()

		if err := kernelIO.closeReader(); err != nil {
			kernelIO.logger.WarnContext(loopCtx, "bpf_reader_close_failed", "error", err)
		}
	}()

	go func() {
		defer kernelIO.loopWG.Done()
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
	}()

	go func() {
		defer kernelIO.loopWG.Done()
		kernelIO.watchRingbufDrops(loopCtx)
	}()

	return nil
}

func (kernelIO *LinuxKernelIO) watchRingbufDrops(ctx context.Context) {
	ticker := time.NewTicker(ringbufDropPollInterval)
	defer ticker.Stop()

	// Ringbuf drops happen before samples can be attributed to a Job. Keep
	// them as agent-wide audit signals; do not fold them into Job events_dropped.
	var lastTotal uint64
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
		if total <= lastTotal {
			continue
		}

		kernelIO.logger.WarnContext(ctx, "bpf_ringbuf_drop",
			"dropped", total-lastTotal,
			"total", total,
		)
		lastTotal = total
	}
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
	var firstErr error

	if kernelIO.cancelLoop != nil {
		kernelIO.cancelLoop()
	}

	if err := kernelIO.closeReader(); err != nil {
		firstErr = err
	}
	// Drain goroutines before closing map FDs; the drop watcher may be in Map.Lookup.
	kernelIO.loopWG.Wait()
	for _, attachedLink := range slices.Backward(kernelIO.links) {
		if err := attachedLink.Close(); err != nil {
			if firstErr == nil {
				firstErr = err
			} else {
				kernelIO.logger.Warn("bpf_link_close_failed", "error", err)
			}
		}
	}
	// coll owns all program/map FDs (objs only holds aliases into coll.Maps, so
	// closing coll is enough and avoids a double close). Collection.Close has no
	// return value.
	if kernelIO.coll != nil {
		kernelIO.coll.Close()
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
