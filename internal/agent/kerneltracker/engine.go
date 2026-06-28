// Package kerneltracker owns kernel sample intake and the Job observation loop.
package kerneltracker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

const (
	defaultEngineInputBufferSize = 16384
	defaultEventRecordBufferSize = 65536
)

type KernelTracker struct {
	logger           *slog.Logger
	jobEndNotifier   JobEndNotifier
	kernelIO         kernelio.KernelIO
	cgroupV2RootPath string
	inputCh          chan engineInput
	// jobTracking is owned by the KernelTracker.Run loop.
	jobTracking *jobTrackingState
}

// New builds the production KernelTracker and its KernelIO adapter.
func New(logger *slog.Logger, jobEndNotifier JobEndNotifier) (*KernelTracker, error) {
	cgroupRoot, err := getCgroupV2Root()
	if errors.Is(err, kernelio.ErrNotSupported) {
		cgroupRoot = ""
	} else if err != nil {
		return nil, fmt.Errorf("get cgroup v2 root: %w", err)
	}

	config := kernelio.Config{}
	if cgroupRoot != "" {
		config = kernelio.Config{CgroupV2RootPath: cgroupRoot}
	}
	kernelIO, err := kernelio.New(logger, config)
	if err != nil {
		return nil, fmt.Errorf("new kernel io: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	engine := &KernelTracker{
		logger:           logger.With("component", "kernel_tracker"),
		jobEndNotifier:   jobEndNotifier,
		kernelIO:         kernelIO,
		cgroupV2RootPath: cgroupRoot,
		inputCh:          make(chan engineInput, defaultEngineInputBufferSize),
	}
	engine.jobTracking = newJobTrackingState()
	engine.jobTracking.logger = engine.logger
	return engine, nil
}

// Close stops the KernelIO producer owned by this tracker.
func (engine *KernelTracker) Close() error {
	if engine == nil || engine.kernelIO == nil {
		return nil
	}
	return engine.kernelIO.Close()
}

// Run starts kernel sample intake and the single owner loop for job tracking.
func (engine *KernelTracker) Run(ctx context.Context) error {
	if engine.kernelIO == nil {
		return errors.New("kernel io is required")
	}
	if err := engine.kernelIO.StartKernelSampleLoop(ctx, engine.enqueueKernelSample); err != nil && !errors.Is(err, kernelio.ErrNotSupported) {
		return fmt.Errorf("start kernel sample loop: %w", err)
	}

	// Start periodic maintenance such as process context GC and lazy cgroup purge.
	stopTrackingStatePurgeTicker := engine.startTrackingStatePurgeTicker(ctx)
	stopCgroupLivenessScanner := engine.startCgroupLivenessScanner(ctx)
	defer engine.closeRemainingChannels()
	defer stopCgroupLivenessScanner()
	defer stopTrackingStatePurgeTicker()

	for {
		select {
		case <-ctx.Done():
			return nil
		case in := <-engine.inputCh:
			effects := handleEngineInput(engine.jobTracking, in)
			engine.runEngineEffects(ctx, effects)
		}
	}
}

// enqueueKernelSample decodes one raw ringbuf sample and queues the decoded input.
func (engine *KernelTracker) enqueueKernelSample(ctx context.Context, sample kernelio.KernelSample) error {
	input, err := decodeKernelSample(sample)
	if err != nil {
		engine.logger.WarnContext(ctx, "kernel_sample_decode_failed", "error", err, "bytes", len(sample))
		return nil
	}
	select {
	case engine.inputCh <- input:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// closeRemainingChannels unblocks Jobs left active when the engine stops.
func (engine *KernelTracker) closeRemainingChannels() {
	for _, channel := range engine.jobTracking.jobEventChannels {
		if channel != nil {
			close(channel)
		}
	}
}
